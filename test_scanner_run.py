import requests
import json

BASE = 'http://127.0.0.1:5000'

def run():
    print("=" * 60)
    print("STEP 1: Health Check")
    print("=" * 60)
    r = requests.get(f'{BASE}/')
    print(f"Status: {r.status_code}")
    print(r.json())

    print("\n" + "=" * 60)
    print("STEP 2: Create Project")
    print("=" * 60)
    proj_data = {
        'name': 'Test Vulnerable API',
        'base_url': 'http://127.0.0.1:5001',
        'description': 'Target API for API-SHIELD validation'
    }
    r = requests.post(f'{BASE}/api/projects', json=proj_data)
    print(f"Status: {r.status_code}")
    res = r.json()
    print(res)
    project_id = res['project']['id']

    print("\n" + "=" * 60)
    print("STEP 3: Upload OpenAPI Spec")
    print("=" * 60)
    spec = """openapi: 3.0.0
info:
  title: Test Vulnerable API
  version: 1.0.0
paths:
  /api/users:
    get:
      summary: List users
      security: []
    post:
      summary: Create user
      requestBody:
        required: true
  /api/users/{user_id}:
    get:
      summary: Get user by ID
      security:
        - BearerAuth: []
  /api/profile:
    get:
      summary: Get user profile
      security:
        - BearerAuth: []
  /api/products:
    get:
      summary: List products
      security: []
"""
    r = requests.post(
        f'{BASE}/api/projects/{project_id}/spec',
        data=spec,
        headers={'Content-Type': 'text/plain'}
    )
    print(f"Status: {r.status_code}")
    print(r.json())

    print("\n" + "=" * 60)
    print("STEP 4: Fetch Imported Endpoints")
    print("=" * 60)
    r = requests.get(f'{BASE}/api/projects/{project_id}/endpoints')
    endpoints = r.json()
    print(f"Imported {len(endpoints)} endpoints:")
    for ep in endpoints:
        print(f"  • {ep['method']} {ep['path']} (auth={ep['auth_required']}, body={ep['has_body']})")

    print("\n" + "=" * 60)
    print("STEP 5: Run Full Security Scan (Phase 15)")
    print("=" * 60)
    r = requests.post(f'{BASE}/api/projects/{project_id}/scan/full')
    print(f"Status: {r.status_code}")
    scan_results = r.json()
    
    print("\n[Severity Summary]")
    for sev, count in scan_results.get('severity_summary', {}).items():
        print(f"  {sev}: {count}")
    print(f"Total Findings: {scan_results.get('total_findings')}")

    print("\n[Findings Sample by Module]")
    for mod_name, mod_data in scan_results.get('results_by_module', {}).items():
        findings = mod_data.get('findings', [])
        print(f"\n--- {mod_name.upper()} (Count: {len(findings)}) ---")
        for f in findings[:2]:  # Show top 2 findings per module
            print(f"  [{f.get('severity')}] {f.get('title')}")
            print(f"    Endpoint: {f.get('endpoint')} | Method: {f.get('method')}")
            print(f"    Evidence: {f.get('evidence')[:120]}...")

    print("\n" + "=" * 60)
    print("STEP 6: Run BOLA Test (Phase 12)")
    print("=" * 60)
    # User A (admin, id=1, token='YWRtaW4=')
    # User B (john, id=2, token='am9obg==')
    bola_payload = {
        "user_a": {
            "username": "admin",
            "token": "YWRtaW4="
        },
        "user_b": {
            "username": "john",
            "token": "am9obg=="
        },
        "resource_id_a": "1"
    }
    r = requests.post(f'{BASE}/api/projects/{project_id}/scan/bola', json=bola_payload)
    print(f"Status: {r.status_code}")
    print(f"Findings: {len(r.json().get('findings', []))}")
    for f in r.json().get('findings', []):
        print(f"  [{f['severity']}] {f['title']} on {f['endpoint']}")

    print("\n" + "=" * 60)
    print("STEP 7: Fetch Project Risk Report (Phase 16)")
    print("=" * 60)
    r = requests.get(f'{BASE}/api/projects/{project_id}/risk')
    print(f"Status: {r.status_code}")
    risk_data = r.json()
    print(f"Security Grade  : {risk_data.get('grade')}")
    print(f"Security Score  : {risk_data.get('security_score')}/100")
    print(f"Risk Breakdown  : {risk_data.get('risk_breakdown')}")
    print("Endpoints in DB with assigned Risk Levels:")
    for ep in risk_data.get('endpoints', []):
        print(f"  • {ep['method']} {ep['path']:<26} -> Risk: {ep['risk']:<8} (Last Tested: {ep['last_tested']})")

    print("\n" + "=" * 60)
    print("STEP 8: Fetch Security Advisories & Code Patches (Phase 17)")
    print("=" * 60)
    r = requests.get(f'{BASE}/api/projects/{project_id}/advisories')
    print(f"Status: {r.status_code}")
    advisories_data = r.json()
    print(f"Total Remediation Advisories: {advisories_data.get('total_advisories')}\n")
    for adv in advisories_data.get('advisories', []):
        print(f"[{adv.get('owasp')}] {adv.get('title')}")
        print(f"  CWE Reference : {adv.get('cwe')}")
        print(f"  Impact        : {adv.get('impact')[:120]}...")
        print(f"  Affected Paths: {adv.get('affected_endpoints')}")
        print(f"  Remediation   : {adv.get('remediation_steps')[0]}")
        print("  Code Patch Preview (Remediated):")
        patch_lines = adv.get('code_patch', {}).get('remediated', '').strip().split('\n')[:3]
        for line in patch_lines:
            print(f"    {line}")
        print("-" * 50)

    print("\n" + "=" * 60)
    print("STEP 9: Generate Executive Security Reports (Phase 18)")
    print("=" * 60)
    
    # 9a. HTML Report
    r_html = requests.get(f'{BASE}/api/projects/{project_id}/report/html')
    print(f"HTML Report Status     : {r_html.status_code}")
    print(f"HTML Content Length    : {len(r_html.text)} characters")
    with open('data/audit_report.html', 'w', encoding='utf-8') as f:
        f.write(r_html.text)
    print("  -> Saved standalone report to: data/audit_report.html")

    # 9b. Markdown Report
    r_md = requests.get(f'{BASE}/api/projects/{project_id}/report/markdown')
    print(f"Markdown Report Status : {r_md.status_code}")
    print(f"Markdown Content Length: {len(r_md.text)} characters")
    with open('data/audit_report.md', 'w', encoding='utf-8') as f:
        f.write(r_md.text)
    print("  -> Saved markdown report to  : data/audit_report.md")

    # 9c. JSON Report
    r_json = requests.get(f'{BASE}/api/projects/{project_id}/report/json')
    print(f"JSON Report Status     : {r_json.status_code}")
    json_data = r_json.json()
    print(f"JSON Report Keys       : {list(json_data.keys())}")
    print(f"Executive Grade In JSON: {json_data.get('executive_summary', {}).get('security_grade')}")
    print(f"Findings In JSON Report: {json_data.get('executive_summary', {}).get('total_findings')}")

if __name__ == '__main__':
    run()
