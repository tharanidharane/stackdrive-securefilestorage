"""Upload test files via the StackDrive API to test the pipeline."""
import requests
import time
import json

BASE = 'http://localhost:5000/api'

# Login
print("=== LOGIN ===")
r = requests.post(f'{BASE}/auth/login', json={'email': 'admin@stackdrive.io', 'password': 'secure123'})
token = r.json()['token']
headers = {'Authorization': f'Bearer {token}'}
print(f"Logged in. Token: {token[:30]}...")

# Upload safe file
print("\n=== UPLOAD #1: quarterly-report-2026.zip (SAFE) ===")
with open(r'n:\unisys project\stackdrive\test-files\quarterly-report-2026.zip', 'rb') as f:
    r = requests.post(f'{BASE}/upload', headers=headers, files={'file': ('quarterly-report-2026.zip', f, 'application/zip')})
print(f"Status: {r.status_code}")
safe_data = r.json()
print(f"Response: {json.dumps(safe_data, indent=2)}")
safe_id = safe_data['file']['id']

# Upload malware file (has .exe inside = ZIP validation should catch it)
print("\n=== UPLOAD #2: malware-sample.zip (MALICIOUS - .exe inside) ===")
with open(r'n:\unisys project\stackdrive\test-files\malware-sample.zip', 'rb') as f:
    r = requests.post(f'{BASE}/upload', headers=headers, files={'file': ('malware-sample.zip', f, 'application/zip')})
print(f"Status: {r.status_code}")
malware_data = r.json()
print(f"Response: {json.dumps(malware_data, indent=2)}")
malware_id = malware_data['file']['id']

# Upload another safe file
print("\n=== UPLOAD #3: client-data-v3.zip (SAFE) ===")
with open(r'n:\unisys project\stackdrive\test-files\client-data-v3.zip', 'rb') as f:
    r = requests.post(f'{BASE}/upload', headers=headers, files={'file': ('client-data-v3.zip', f, 'application/zip')})
print(f"Status: {r.status_code}")
client_data = r.json()
print(f"Response: {json.dumps(client_data, indent=2)}")
client_id = client_data['file']['id']

# Wait for pipeline to complete
print("\n=== WAITING 8s FOR PIPELINE ===")
time.sleep(8)

# Check pipeline results
print("\n=== PIPELINE RESULTS ===")
for fid, name in [(safe_id, 'quarterly-report'), (malware_id, 'malware-sample'), (client_id, 'client-data')]:
    r = requests.get(f'{BASE}/pipeline/{fid}', headers=headers)
    data = r.json()
    print(f"\n{name}: Status={data['status']}")
    for stage in data['stages']:
        print(f"  {stage['name']}: {stage['status']} — {stage['detail']}")

# Check dashboard metrics
print("\n=== DASHBOARD METRICS ===")
r = requests.get(f'{BASE}/dashboard/metrics', headers=headers)
metrics = r.json()
print(json.dumps(metrics, indent=2))

# Check security stats
print("\n=== SECURITY STATS ===")
r = requests.get(f'{BASE}/security/stats', headers=headers)
stats = r.json()
print(f"Total scanned: {stats['totalScanned']}")
print(f"Pass rate: {stats['passRate']}%")
print(f"Active threats: {stats['activeThreats']}")
for layer in stats['layerStats']:
    print(f"  {layer['name']}: {layer['passed']} passed, {layer['failed']} failed")

# Check notifications
print("\n=== NOTIFICATIONS ===")
r = requests.get(f'{BASE}/notifications', headers=headers)
notifs = r.json()
print(f"Unread: {notifs['unread_count']}")
for n in notifs['notifications']:
    print(f"  {n['fileName']}: {n['threatType']} at {n['layer']}")

print("\n=== ALL TESTS COMPLETE ===")
