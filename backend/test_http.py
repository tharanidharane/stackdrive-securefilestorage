import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app import app
from models import db, File, User
from flask_jwt_extended import create_access_token

with app.app_context():
    file = File.query.order_by(File.uploaded_at.desc()).first()
    if not file:
        print("No file found.")
        sys.exit(0)
        
    access_token = create_access_token(identity=file.user_id)
    
    with app.test_client() as client:
        response = client.get(
            f'/api/files/{file.id}/download',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        print(f"STATUS: {response.status_code}")
        if response.status_code == 500:
            print("ERROR DATA:", response.get_data(as_text=True))
