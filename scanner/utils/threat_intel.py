import base64
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.conf import settings

logger = logging.getLogger(__name__)

def check_google_safe_browsing(target_url: str) -> dict:
    """
    Queries Google Safe Browsing API v4 for threat classification.
    """
    api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
    if not api_key or api_key == "YOUR_GOOGLE_SAFE_BROWSING_KEY_HERE":
        return {"status": "SKIPPED", "reason": "No API key configured", "is_malicious": False}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "qrshield-app",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list(set([m.get("threatType") for m in matches]))
                return {
                    "status": "FLAGGED",
                    "is_malicious": True,
                    "threat_types": threat_types
                }
            return {"status": "CLEAN", "is_malicious": False, "threat_types": []}
        else:
            return {"status": "ERROR", "is_malicious": False, "code": response.status_code}
    except Exception as e:
        logger.error(f"Google Safe Browsing Error: {str(e)}")
        return {"status": "ERROR", "is_malicious": False, "error": str(e)}


def check_virustotal(target_url: str) -> dict:
    """
    Queries VirusTotal API v3 for multi-engine antivirus verdicts.
    """
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key or api_key == "YOUR_VIRUSTOTAL_KEY_HERE":
        return {"status": "SKIPPED", "reason": "No API key configured", "positives": 0, "malicious_count": 0, "is_malicious": False}

    # VirusTotal v3 URL ID is base64 encoded without padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(endpoint, headers=headers, timeout=6)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            return {
                "status": "COMPLETED",
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "total_engines": sum(stats.values()),
                "is_malicious": malicious_count >= 2
            }
        elif response.status_code == 404:
            # URL hasn't been scanned by VirusTotal yet
            return {"status": "NOT_FOUND", "malicious_count": 0, "is_malicious": False}
        elif response.status_code == 429:
            logger.warning("VirusTotal API quota / rate limit exceeded (429)")
            return {"status": "RATE_LIMITED", "malicious_count": 0, "is_malicious": False}
        else:
            return {"status": "ERROR", "code": response.status_code, "malicious_count": 0, "is_malicious": False}
    except Exception as e:
        logger.error(f"VirusTotal Error: {str(e)}")
        return {"status": "ERROR", "error": str(e), "malicious_count": 0, "is_malicious": False}


def check_urlhaus(target_url: str) -> dict:
    """
    Queries abuse.ch URLhaus API for confirmed malware distribution links.
    """
    api_key = getattr(settings, 'URLHAUS_API_KEY', '')
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {
        "User-Agent": "QRShield-Scanner/1.0"
    }
    if api_key:
        headers["Auth-Key"] = api_key

    data = {"url": target_url}

    try:
        response = requests.post(endpoint, data=data, headers=headers, timeout=5)
        if response.status_code == 200:
            res = response.json()
            query_status = res.get("query_status")
            if query_status == "ok":
                return {
                    "status": "FLAGGED",
                    "is_malicious": True,
                    "threat": res.get("threat"),
                    "tags": res.get("tags", [])
                }
            return {"status": "CLEAN", "is_malicious": False}
        elif response.status_code == 401:
            return {"status": "UNAVAILABLE", "reason": "Requires Auth-Key", "is_malicious": False}
        return {"status": f"HTTP_{response.status_code}", "is_malicious": False}
    except Exception as e:
        logger.error(f"URLhaus Error: {str(e)}")
        return {"status": "ERROR", "error": str(e), "is_malicious": False}


def _scan_single_url_concurrent(url: str) -> dict:
    with ThreadPoolExecutor(max_workers=3) as executor:
        gsb_future = executor.submit(check_google_safe_browsing, url)
        vt_future = executor.submit(check_virustotal, url)
        urlhaus_future = executor.submit(check_urlhaus, url)

        gsb_result = gsb_future.result()
        vt_result = vt_future.result()
        urlhaus_result = urlhaus_future.result()

    any_malicious = (
        gsb_result.get("is_malicious", False) or
        vt_result.get("is_malicious", False) or
        urlhaus_result.get("is_malicious", False)
    )

    return {
        "url": url,
        "any_flagged": any_malicious,
        "google_safe_browsing": gsb_result,
        "virustotal": vt_result,
        "urlhaus": urlhaus_result
    }


def aggregate_threat_intelligence(urls) -> dict:
    """
    Executes queries across all external threat feeds concurrently for all unique URLs.
    Accepts either a single URL string or an iterable of URLs (initial + redirect targets).
    """
    if isinstance(urls, str):
        target_list = [urls]
    else:
        target_list = list(dict.fromkeys([u for u in urls if u]))

    if not target_list:
        return {
            "any_flagged": False,
            "google_safe_browsing": {"status": "SKIPPED", "is_malicious": False},
            "virustotal": {"status": "SKIPPED", "malicious_count": 0, "is_malicious": False},
            "urlhaus": {"status": "SKIPPED", "is_malicious": False},
            "urls_scanned": []
        }

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(target_list))) as executor:
        futures = {executor.submit(_scan_single_url_concurrent, u): u for u in target_list}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.error(f"Threat intel execution error for URL: {str(e)}")

    # Aggregate cross-URL signals
    any_flagged = any(r.get("any_flagged", False) for r in results)
    max_vt_count = max((r.get("virustotal", {}).get("malicious_count", 0) for r in results), default=0)
    gsb_flagged = any(r.get("google_safe_browsing", {}).get("is_malicious", False) for r in results)
    urlhaus_flagged = any(r.get("urlhaus", {}).get("is_malicious", False) for r in results)

    # Collect consolidated responses
    consolidated_gsb = next((r["google_safe_browsing"] for r in results if r["google_safe_browsing"].get("is_malicious")), results[0]["google_safe_browsing"] if results else {})
    consolidated_vt = next((r["virustotal"] for r in results if r["virustotal"].get("malicious_count", 0) == max_vt_count), results[0]["virustotal"] if results else {})
    consolidated_urlhaus = next((r["urlhaus"] for r in results if r["urlhaus"].get("is_malicious")), results[0]["urlhaus"] if results else {})

    return {
        "any_flagged": any_flagged,
        "google_safe_browsing": consolidated_gsb,
        "virustotal": consolidated_vt,
        "urlhaus": consolidated_urlhaus,
        "urls_scanned": target_list,
        "detailed_results": results
    }