import time
import requests

BASE_URL = "http://127.0.0.1:8000/api"

TEST_SUITE = [
    {"name": "Legitimate Domain (Google)", "url": "https://www.google.com", "expected_verdict": "SAFE"},
    {"name": "Google Safe Browsing Test", "url": "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/", "expected_verdict": "MALICIOUS"},
    {"name": "Homoglyph + Combosquatting", "url": "https://www.paypa1-security-update.com/login", "expected_verdict": "MALICIOUS"},
    {"name": "Direct File Download (ZIP)", "url": "https://github.com/elceef/dnstwist/archive/refs/heads/master.zip", "expected_verdict": "MALICIOUS"},
    {"name": "Missing Scheme Normalization", "url": "paypa1-login-verify.com", "expected_verdict": "MALICIOUS"},
]

def run_tests():
    print("==================================================")
    print("        QUISHING BACKEND VERIFICATION SUITE       ")
    print("==================================================\n")

    for idx, test in enumerate(TEST_SUITE, 1):
        print(f"[{idx}/{len(TEST_SUITE)}] Running: {test['name']} ({test['url']})")
        
        # 1. Post Scan Request
        try:
            res = requests.post(f"{BASE_URL}/scan/", json={"url": test['url']}, timeout=5)
            if res.status_code != 202:
                print(f"  ❌ FAILED TO ENQUEUE: HTTP {res.status_code}\n")
                continue
            
            task_id = res.json().get("task_id")
        except Exception as e:
            print(f"  ❌ CONNECTION ERROR: {str(e)}\n")
            continue

        # 2. Poll Status Endpoint until completed
        completed = False
        data = {}
        for _ in range(15): # Poll for up to 15 seconds
            time.sleep(1)
            status_res = requests.get(f"{BASE_URL}/status/{task_id}/").json()
            if status_res.get("status") == "COMPLETED":
                completed = True
                data = status_res
                break

        if not completed:
            print(f"  ❌ TIMEOUT: Task did not complete in 15 seconds\n")
            continue

        verdict = data.get("verdict")
        score = data.get("risk_score")
        passed = (verdict == test["expected_verdict"])

        status_icon = "✅ PASS" if passed else "⚠️ MISMATCH"
        print(f"  {status_icon} -> Result Verdict: {verdict} | Risk Score: {score} (Expected: {test['expected_verdict']})\n")

if __name__ == "__main__":
    run_tests()