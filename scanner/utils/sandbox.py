import logging
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

# Executable, archive, or installer MIME types that indicate potential payload downloads
SUSPICIOUS_MIME_TYPES = [
    'application/octet-stream',
    'application/x-msdownload',
    'application/exe',
    'application/x-exe',
    'application/dos-exe',
    'vbs/express',
    'application/x-zip-compressed',
    'application/zip',
    'application/x-stuffit',
    'application/x-rar-compressed',
    'application/x-tar',
    'application/x-sh',
    'application/vnd.android.package-archive', # APK files
]

# Standard safe web assets that should NEVER be flagged as file downloads
SAFE_WEB_MIMES = [
    'text/html',
    'text/css',
    'text/plain',
    'application/javascript',
    'application/x-javascript',
    'application/json',
    'font/woff',
    'font/woff2',
    'font/ttf',
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    'image/x-icon',
]

def analyze_url_in_sandbox(target_url: str, timeout_ms: int = 15000) -> dict:
    telemetry = {
        "initial_url": target_url,
        "final_url": target_url,
        "status_code": None,
        "page_title": "",
        "redirect_chain": [],
        "has_redirects": False,
        "redirect_count": 0,
        "download_detected": False,
        "download_info": [],
        "suspicious_headers_found": [],
        "has_password_field": False,
        "input_count": 0,
        "form_count": 0,
        "error": None
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        )
        
        # Use mobile User-Agent to bypass mobile-cloaking anti-crawlers commonly used in Quishing
        context = browser.new_context(
            accept_downloads=True,
            user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
        )
        
        page = context.new_page()

        # -------------------------------------------------------------
        # EVENT 1: Explicit Browser Download Events (e.g. user clicks download)
        # -------------------------------------------------------------
        def handle_download(download):
            telemetry["download_detected"] = True
            telemetry["download_info"].append({
                "suggested_filename": download.suggested_filename,
                "url": download.url,
                "trigger_type": "EXPLICIT_BROWSER_DOWNLOAD"
            })
            logger.warning(f"[SANDBOX DOWNLOAD DETECTED]: {download.suggested_filename} from {download.url}")

        page.on("download", handle_download)

        # -------------------------------------------------------------
        # EVENT 2: Filtered Network Response Inspector
        # -------------------------------------------------------------
        def handle_response(response):
            # A) Record ONLY Main Frame Navigation Requests (True Domain Redirects)
            if response.frame == page.main_frame and response.request.is_navigation_request():
                telemetry["redirect_chain"].append({
                    "url": response.url,
                    "status": response.status
                })

            # B) Inspect for Hidden Binary/Payload Downloads
            headers = response.headers
            content_type = headers.get("content-type", "").lower()
            content_disposition = headers.get("content-disposition", "").lower()

            # Skip standard web page assets (JS, CSS, Images, Fonts)
            is_safe_asset = any(safe_mime in content_type for safe_mime in SAFE_WEB_MIMES)

            if not is_safe_asset:
                is_attachment = "attachment" in content_disposition
                is_suspicious_mime = any(mime in content_type for mime in SUSPICIOUS_MIME_TYPES)

                # Flag if it's explicitly an attachment or a navigation payload
                if is_attachment or (is_suspicious_mime and (response.request.is_navigation_request() or is_attachment)):
                    telemetry["download_detected"] = True
                    telemetry["suspicious_headers_found"].append({
                        "url": response.url,
                        "content_type": content_type,
                        "content_disposition": content_disposition,
                        "trigger_type": "IMPLICIT_HEADER_DOWNLOAD"
                    })
                    logger.warning(f"[SANDBOX SUSPICIOUS BINARY HEADER]: {response.url} | Content-Type: {content_type}")

        page.on("response", handle_response)

        # -------------------------------------------------------------
        # EXECUTE NAVIGATIONAL SCAN
        # -------------------------------------------------------------
        try:
            response = page.goto(target_url, wait_until="load", timeout=timeout_ms)
            if response:
                telemetry["status_code"] = response.status
            
            # Allow short pause for client-side scripts / redirects to settle
            page.wait_for_timeout(1000)
            telemetry["final_url"] = page.url
            telemetry["page_title"] = page.title()

            # Inspect DOM for credential harvesting indicators (password fields, forms)
            try:
                pw_count = page.locator('input[type="password"]').count()
                telemetry["has_password_field"] = pw_count > 0
                telemetry["input_count"] = page.locator('input').count()
                telemetry["form_count"] = page.locator('form').count()
            except Exception as dom_err:
                logger.debug(f"DOM inspection note: {dom_err}")

        except PlaywrightTimeoutError:
            telemetry["error"] = "Navigation timeout (15s limit)"
            try:
                telemetry["final_url"] = page.url
                telemetry["page_title"] = page.title()
            except Exception:
                pass
        except Exception as e:
            telemetry["error"] = str(e)
            try:
                telemetry["final_url"] = page.url
            except Exception:
                pass
        finally:
            context.close()
            browser.close()

    # Calculate actual main-frame redirection hop count
    if len(telemetry["redirect_chain"]) > 1:
        telemetry["has_redirects"] = True
        telemetry["redirect_count"] = len(telemetry["redirect_chain"]) - 1
    else:
        telemetry["redirect_count"] = 0

    return telemetry