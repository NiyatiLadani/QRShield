import logging

logger = logging.getLogger(__name__)

def calculate_composite_risk_score(
    sandbox_data: dict,
    threat_intel_data: dict,
    homoglyph_data: dict
) -> dict:
    """
    Computes normalized sub-scores (T, D, R, F) and aggregates them into 
    a composite risk score in range [0, 100].
    """
    # 1. Calculate Threat Intelligence Sub-Score (T)
    vt_info = threat_intel_data.get("virustotal", {})
    vt_malicious_count = vt_info.get("malicious_count", 0)
    gsb_flagged = threat_intel_data.get("google_safe_browsing", {}).get("is_malicious", False)
    urlhaus_flagged = threat_intel_data.get("urlhaus", {}).get("is_malicious", False)

    t_score = 0.0
    if gsb_flagged:
        t_score += 100.0
    if urlhaus_flagged:
        t_score += 100.0
    t_score += (vt_malicious_count * 50.0)
    T = min(100.0, t_score)

    # 2. Calculate Domain Impersonation Sub-Score (D)
    is_impersonation = homoglyph_data.get("is_impersonation_suspect", False)
    D = 100.0 if is_impersonation else 0.0

    # 3. Calculate Redirection Anomaly Sub-Score (R)
    redirect_count = sandbox_data.get("redirect_count", 0)
    if redirect_count > 1:
        R = min(100.0, 30.0 + (redirect_count - 1) * 35.0)
    elif redirect_count == 1:
        R = 15.0
    else:
        R = 0.0

    # 4. Calculate File Download Risk Sub-Score (F)
    download_detected = sandbox_data.get("download_detected", False)
    F = 100.0 if download_detected else 0.0

    # 5. Credential Harvesting Telemetry
    has_password_field = sandbox_data.get("has_password_field", False)

    # Weighted composite score formula: S = min(100, w_t*T + w_d*D + w_r*R + w_f*F)
    w_t, w_d, w_r, w_f = 0.30, 0.35, 0.15, 0.20
    composite_score = (w_t * T) + (w_d * D) + (w_r * R) + (w_f * F)

    # Critical threat override check
    if download_detected or gsb_flagged or urlhaus_flagged or vt_malicious_count >= 2:
        composite_score = max(composite_score, 85.0)
    elif is_impersonation:
        # Brand impersonation is an immediate high-severity threat
        if has_password_field:
            composite_score = max(composite_score, 90.0)
        else:
            composite_score = max(composite_score, 80.0)
    elif has_password_field and redirect_count >= 2:
        # Multi-hop redirection ending in an unverified login/password form
        composite_score = max(composite_score, 50.0)

    final_score = round(min(100.0, composite_score), 1)

    # Assign verdict badge
    if final_score >= 70.0:
        verdict = "MALICIOUS"
    elif final_score >= 30.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Build human-readable threat summary explanations for UI
    threat_reasons = []
    if gsb_flagged:
        threat_reasons.append("Flagged by Google Safe Browsing blocklist")
    if urlhaus_flagged:
        threat_reasons.append("Urlhaus identified active malware payload host")
    if vt_malicious_count > 0:
        threat_reasons.append(f"Flagged by {vt_malicious_count} VirusTotal security engines")
    if is_impersonation:
        matched_brand = homoglyph_data.get("matched_brand", "known entity").upper()
        technique = homoglyph_data.get("fuzzing_technique", "LOOKALIKE")
        threat_reasons.append(f"Domain impersonates protected brand '{matched_brand}' ({technique})")
    if has_password_field and (is_impersonation or redirect_count >= 2):
        threat_reasons.append("Credential harvesting indicator detected (login password field on unverified destination)")
    if download_detected:
        threat_reasons.append("Attempted automated background binary download")
    if redirect_count > 2:
        threat_reasons.append(f"Excessive multi-hop redirection chain ({redirect_count} hops)")

    if not threat_reasons:
        threat_reasons.append("No threat indicators detected. Domain appears legitimate.")

    return {
        "score": final_score,
        "verdict": verdict,
        "sub_scores": {
            "threat_intelligence": round(T, 1),
            "domain_impersonation": round(D, 1),
            "redirect_anomalies": round(R, 1),
            "file_download_risk": round(F, 1),
            "T": round(T, 1),
            "D": round(D, 1),
            "R": round(R, 1),
            "F": round(F, 1),
            "threatIntel": round(T, 1),
            "impersonation": round(D, 1),
            "redirection": round(R, 1),
            "downloadRisk": round(F, 1)
        },
        "threat_reasons": threat_reasons
    }
