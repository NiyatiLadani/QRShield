from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock

from scanner.models import ScanResult
from scanner.utils.homoglyph import check_brand_impersonation
from scanner.utils.risk_engine import calculate_composite_risk_score
from scanner.utils.threat_intel import aggregate_threat_intelligence


class HomoglyphDetectionTests(TestCase):
    def test_leetspeak_impersonation(self):
        result = check_brand_impersonation("https://paypa1-security.com")
        self.assertTrue(result["is_impersonation_suspect"])
        self.assertEqual(result["matched_brand"], "paypal")

    def test_unicode_punycode_homoglyph(self):
        # xn--pypal-4ve.com is pаypal.com with Cyrillic 'а'
        result = check_brand_impersonation("https://xn--pypal-4ve.com")
        self.assertTrue(result["is_impersonation_suspect"])
        self.assertEqual(result["matched_brand"], "paypal")
        self.assertEqual(result["fuzzing_technique"], "UNICODE_HOMOGLYPH")

    def test_typosquatting(self):
        result = check_brand_impersonation("https://paypals.com")
        self.assertTrue(result["is_impersonation_suspect"])
        self.assertEqual(result["matched_brand"], "paypal")

    def test_combosquatting(self):
        result = check_brand_impersonation("https://chase-update.com")
        self.assertTrue(result["is_impersonation_suspect"])
        self.assertEqual(result["matched_brand"], "chase")

    def test_legitimate_brand_domains_not_flagged(self):
        for domain in ["https://google.co.uk", "https://paypal.me", "https://google.com", "https://apple.com"]:
            result = check_brand_impersonation(domain)
            self.assertFalse(result["is_impersonation_suspect"], f"{domain} should not be flagged as suspect")

    def test_substring_word_collisions_not_flagged(self):
        # pineapple contains 'apple', purchase contains 'chase'
        for domain in ["https://pineapple.com", "https://purchase.com", "https://example.com"]:
            result = check_brand_impersonation(domain)
            self.assertFalse(result["is_impersonation_suspect"], f"{domain} should not be flagged as suspect")


class RiskEngineTests(TestCase):
    def test_active_phishing_brand_impersonation_is_malicious(self):
        homoglyph = {"is_impersonation_suspect": True, "matched_brand": "paypal", "fuzzing_technique": "LEETSPEAK"}
        sandbox = {"redirect_count": 0, "download_detected": False, "has_password_field": True}
        threat_intel = {}

        assessment = calculate_composite_risk_score(sandbox, threat_intel, homoglyph)
        self.assertEqual(assessment["verdict"], "MALICIOUS")
        self.assertGreaterEqual(assessment["score"], 80.0)
        self.assertTrue(any("impersonates" in r for r in assessment["threat_reasons"]))

    def test_clean_domain_is_safe(self):
        homoglyph = {"is_impersonation_suspect": False}
        sandbox = {"redirect_count": 0, "download_detected": False, "has_password_field": False}
        threat_intel = {}

        assessment = calculate_composite_risk_score(sandbox, threat_intel, homoglyph)
        self.assertEqual(assessment["verdict"], "SAFE")
        self.assertEqual(assessment["score"], 0.0)

    def test_download_detected_override(self):
        homoglyph = {"is_impersonation_suspect": False}
        sandbox = {"redirect_count": 0, "download_detected": True, "has_password_field": False}
        threat_intel = {}

        assessment = calculate_composite_risk_score(sandbox, threat_intel, homoglyph)
        self.assertEqual(assessment["verdict"], "MALICIOUS")
        self.assertGreaterEqual(assessment["score"], 85.0)

    def test_threat_intel_gsb_override(self):
        homoglyph = {"is_impersonation_suspect": False}
        sandbox = {"redirect_count": 0, "download_detected": False, "has_password_field": False}
        threat_intel = {"google_safe_browsing": {"is_malicious": True}}

        assessment = calculate_composite_risk_score(sandbox, threat_intel, homoglyph)
        self.assertEqual(assessment["verdict"], "MALICIOUS")
        self.assertGreaterEqual(assessment["score"], 85.0)

    def test_multi_hop_login_is_suspicious(self):
        homoglyph = {"is_impersonation_suspect": False}
        sandbox = {"redirect_count": 2, "download_detected": False, "has_password_field": True}
        threat_intel = {}

        assessment = calculate_composite_risk_score(sandbox, threat_intel, homoglyph)
        self.assertEqual(assessment["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(assessment["score"], 30.0)


class ViewsAndApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("scanner.views.run_quishing_analysis_task.apply_async")
    def test_initiate_scan_success(self, mock_apply_async):
        mock_apply_async.return_value = MagicMock(id="test-task-123")

        response = self.client.post("/api/scan/", {"url": "https://example.com/login"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn("task_id", response.data)

        # Ensure record was pre-created in database
        record = ScanResult.objects.get(task_id=response.data["task_id"])
        self.assertEqual(record.status, "PROCESSING")
        self.assertEqual(record.target_url, "https://example.com/login")
        self.assertTrue(mock_apply_async.called)

    def test_get_scan_status(self):
        record = ScanResult.objects.create(
            task_id="unique-task-999",
            target_url="https://paypa1-security.com",
            risk_score=90.0,
            verdict="MALICIOUS",
            status="COMPLETED",
            analysis_details={"threat_reasons": ["Impersonation"]}
        )

        response = self.client.get(f"/api/status/{record.task_id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "COMPLETED")
        self.assertEqual(response.data["verdict"], "MALICIOUS")
        self.assertEqual(response.data["risk_score"], 90.0)
