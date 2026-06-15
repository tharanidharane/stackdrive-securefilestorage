
rule ObfuscatedExecution {
    meta: description="Exec/eval+encoding" severity="high"
    strings:
        $e1=/exec\s*\(\s*base64/ nocase $e2=/eval\s*\(\s*(atob|base64)/ nocase
        $e3="__import__" nocase    $e4="marshal.loads" nocase
        $e5=/zlib\.decompress.{0,40}exec/ nocase
        $e6=/String\.fromCharCode\s*\(/ nocase
    condition: any of ($e1,$e2,$e5) or (($e3 or $e4) and $e1) or $e6
}
rule ReverseShellPattern {
    meta: description="Reverse/bind shell" severity="critical"
    strings:
        $r1="nc -e" nocase $r2="/dev/tcp/" nocase $r3="bash -i" nocase
        $r4="sh -i" nocase $r5="mkfifo"    nocase $r6="ncat -e" nocase
    condition: any of them
}
rule PowerShellObfuscation {
    meta: description="PowerShell encoded/download-exec" severity="high"
    strings:
        $p1=/-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]/
        $p2="IEX" nocase $p3="DownloadString" nocase $p4="ExecutionPolicy Bypass" nocase
    condition: $p1 or ($p2 and $p3) or ($p4 and $p2)
}
rule DocumentMacroAutoExec {
    meta: description="Office auto-exec macro" severity="high"
    strings:
        $m1="AutoOpen" nocase $m2="Workbook_Open" nocase $m3="Document_Open" nocase
        $m4="Shell("   nocase $m5="WScript.Shell"  nocase $m6="CreateObject"  nocase
    condition: (any of ($m1,$m2,$m3)) and (any of ($m4,$m5,$m6))
}
rule SuspiciousLOLBAS {
    meta: description="LOLBaS abuse" severity="medium"
    strings:
        $l1="certutil" nocase $l2="bitsadmin" nocase
        $l3="mshta"    nocase $l4="regsvr32"  nocase
        $h1="http://"  nocase $h2="https://"  nocase $h3="base64" nocase
    condition: (any of ($l1,$l2,$l3,$l4)) and (any of ($h1,$h2,$h3))
}
