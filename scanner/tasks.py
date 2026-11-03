import copy
import logging
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from celery import shared_task
from .models import ScanResult
from .utils.sandbox import analyze_url_in_sandbox
from .utils.threat_intel import aggregate_threat_intelligence
from .utils.homoglyph import check_brand_impersonation
from .utils.risk_engine import calculate_composite_risk_score

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def run_quishing_analysis_task(self, target_url):
    task_id = self.request.id
    logger.info(f"[CELERY TASK STARTED] Task ID: {task_id} | URL: {target_url}")

    # Fetch or create initial record
    scan_record, created = ScanResult.objects.get_or_create(
        task_id=task_id,
        defaults={'target_url': target_url, 'status': 'PROCESSING'}
    )

    if not created:
        scan_record.status = 'PROCESSING'
        scan_record.save()

    try:
        # -------------------------------------------------------------
        # OPTIMIZATION: CHECK CACHE (EXACT URL SCANNED IN PAST 24 HOURS)
        # -------------------------------------------------------------
        enable_cache = getattr(settings, 'ENABLE_SCAN_CACHE', not getattr(settings, 'DEBUG', True))
        if enable_cache:
            cache_cutoff = timezone.now() - timedelta(hours=24)
            recent_cached_scan = ScanResult.objects.filter(
                target_url=target_url,
                status='COMPLETED',
                created_at__gte=cache_cutoff
            ).exclude(task_id=task_id).order_by('-created_at').first()

            # Only reuse cache if it contains modern schema with sub_scores and threat_reasons
            if recent_cached_scan and recent_cached_scan.analysis_details and "sub_scores" in recent_cached_scan.analysis_details:
                logger.info(f"[CACHE HIT] Reusing previous scan analysis for URL: {target_url}")
                scan_record.risk_score = recent_cached_scan.risk_score
                scan_record.verdict = recent_cached_scan.verdict
                scan_record.status = 'COMPLETED'
                # Deepcopy to prevent mutating original cached record in memory
                scan_record.analysis_details = copy.deepcopy(recent_cached_scan.analysis_details)
                scan_record.analysis_details["cached_result"] = True
                scan_record.save()

                return {
                    "task_id": task_id,
                    "status": "COMPLETED",
                    "verdict": scan_record.verdict,
                    "score": scan_record.risk_score,
                    "details": scan_record.analysis_details
                }

        # -------------------------------------------------------------
        # FRESH SCAN PIPELINE
        # -------------------------------------------------------------
        # Step A: Playwright Sandbox Navigation
        sandbox_results = analyze_url_in_sandbox(target_url)

        # Collect all endpoints involved in navigation (target, intermediate hops, final destination)
        final_url = sandbox_results.get("final_url") or target_url
        redirect_hops = [hop.get("url") for hop in sandbox_results.get("redirect_chain", []) if hop.get("url")]
        all_eval_urls = list(dict.fromkeys([target_url, final_url] + redirect_hops))

        # Step B: External Threat Intelligence APIs (checks initial, hops, and final landing URL)
        threat_intel_results = aggregate_threat_intelligence(all_eval_urls)

        # Step C: Homoglyph & Brand Impersonation Fuzzer (checks both initial & final domain)
        homoglyph_results = check_brand_impersonation(all_eval_urls)

        # Step D: Compute Composite Risk Score & Verdict
        assessment = calculate_composite_risk_score(
            sandbox_results,
            threat_intel_results,
            homoglyph_results
        )

        # Save findings to SQLite Database
        scan_record.risk_score = assessment["score"]
        scan_record.verdict = assessment["verdict"]
        scan_record.status = "COMPLETED"
        scan_record.analysis_details = {
            "cached_result": False,
            "sub_scores": assessment["sub_scores"],
            "threat_reasons": assessment["threat_reasons"],
            "sandbox_telemetry": sandbox_results,
            "threat_intelligence": threat_intel_results,
            "homoglyph_analysis": homoglyph_results
        }
        scan_record.save()

        logger.info(f"[CELERY TASK SUCCESS] ID: {task_id} | Verdict: {assessment['verdict']} | Score: {assessment['score']}")

        return {
            "task_id": task_id,
            "status": "COMPLETED",
            "verdict": assessment["verdict"],
            "score": assessment["score"],
            "details": scan_record.analysis_details
        }

    except Exception as e:
        logger.error(f"[CELERY TASK FAILED] ID: {task_id} | Error: {str(e)}")
        scan_record.status = "FAILED"
        scan_record.verdict = "ERROR"
        scan_record.analysis_details = {"error": str(e)}
        scan_record.save()

        return {
            "task_id": task_id,
            "status": "FAILED",
            "error": str(e)
        }
