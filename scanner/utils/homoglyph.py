import re
import idna
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

PROTECTED_BRANDS = [
    "google", "paypal", "microsoft", "apple", "amazon", 
    "facebook", "instagram", "netflix", "bankofamerica", 
    "chase", "wellsfargo", "linkedin", "binance", "coinbase"
]

LEET_MAP = {
    '1': 'l', '0': 'o', '3': 'e', '@': 'a', '4': 'a', 
    '5': 's', '8': 'b', '$': 's', '!': 'i'
}

CYRILLIC_GREEK_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P',
    'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
}

COMMON_BRAND_DOMAINS = {
    'google': {'google.com', 'google.co.uk', 'google.co.in', 'google.de', 'google.fr', 'google.org', 'google.net'},
    'paypal': {'paypal.com', 'paypal.me', 'paypal.co.uk', 'paypal.de'},
    'apple': {'apple.com', 'apple.co', 'icloud.com'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.co.jp'},
    'netflix': {'netflix.com', 'netflix.ca', 'netflix.net'},
    'chase': {'chase.com'},
    'bankofamerica': {'bankofamerica.com', 'bofa.com'},
    'wellsfargo': {'wellsfargo.com'},
    'linkedin': {'linkedin.com'},
    'binance': {'binance.com', 'binance.me'},
    'coinbase': {'coinbase.com'},
    'facebook': {'facebook.com', 'fb.com'},
    'instagram': {'instagram.com'}
}

def normalize_leetspeak(text: str) -> str:
    """Replaces numerical and symbol character swaps with their letter equivalents."""
    for char, replacement in LEET_MAP.items():
        text = text.replace(char, replacement)
    return text

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_domain(domain_str: str) -> tuple[str, bool, bool]:
    """
    Decodes Punycode/IDN, normalizes Unicode homoglyphs (Cyrillic/Greek), 
    and applies leetspeak substitution. Returns (normalized_str, has_unicode_swap, has_leet_swap).
    """
    has_unicode_swap = False
    has_leet_swap = False

    # 1. Decode IDN / Punycode (e.g. xn--pypal-4ve.com -> pаypal.com)
    try:
        if 'xn--' in domain_str.lower():
            domain_str = idna.decode(domain_str)
    except Exception:
        pass

    # 2. Map Cyrillic / Greek visual confusables to Latin
    decoded_chars = []
    for ch in domain_str:
        if ch in CYRILLIC_GREEK_MAP:
            decoded_chars.append(CYRILLIC_GREEK_MAP[ch])
            has_unicode_swap = True
        else:
            decoded_chars.append(ch)
    domain_str = ''.join(decoded_chars)

    # 3. Leetspeak mapping
    leet_chars = []
    for ch in domain_str:
        if ch in LEET_MAP:
            leet_chars.append(LEET_MAP[ch])
            has_leet_swap = True
        else:
            leet_chars.append(ch)

    return ''.join(leet_chars), has_unicode_swap, has_leet_swap

def check_single_url_impersonation(target_url: str) -> dict:
    parsed = urlparse(target_url if '://' in target_url else f'https://{target_url}')
    raw_domain = parsed.netloc or parsed.path
    raw_domain = raw_domain.split(':')[0].lower()
    if raw_domain.startswith("www."):
        raw_domain = raw_domain[4:]

    report = {
        "domain_analyzed": raw_domain,
        "is_impersonation_suspect": False,
        "matched_brand": None,
        "fuzzing_technique": None
    }

    if not raw_domain:
        return report

    # Allow verified legitimate brand domains and their official subdomains
    for brand, legit_domains in COMMON_BRAND_DOMAINS.items():
        if raw_domain in legit_domains or any(raw_domain.endswith('.' + d) for d in legit_domains):
            return report

    normalized, has_unicode, has_leet = normalize_domain(raw_domain)
    tokens = [t for t in re.split(r'[\.\-]', normalized) if t]

    for brand in PROTECTED_BRANDS:
        # Check A: Unicode Homoglyph
        if has_unicode and brand in tokens:
            report["is_impersonation_suspect"] = True
            report["matched_brand"] = brand
            report["fuzzing_technique"] = "UNICODE_HOMOGLYPH"
            logger.warning(f"[HOMOGLYPH MATCH]: {raw_domain} matches protected brand '{brand}' via UNICODE_HOMOGLYPH")
            return report

        # Check B: Leetspeak Impersonation
        if has_leet and brand in tokens:
            report["is_impersonation_suspect"] = True
            report["matched_brand"] = brand
            report["fuzzing_technique"] = "LEETSPEAK_IMPERSONATION"
            logger.warning(f"[HOMOGLYPH MATCH]: {raw_domain} matches protected brand '{brand}' via LEETSPEAK")
            return report

        # Check C: Combosquatting (brand token combined with hyphenated/subdomain words)
        if brand in tokens:
            non_tld_tokens = [t for t in tokens if t not in {'com', 'net', 'org', 'co', 'uk', 'de', 'in', 'io', 'me', 'xyz', 'app'}]
            if len(non_tld_tokens) > 1 and brand in non_tld_tokens:
                report["is_impersonation_suspect"] = True
                report["matched_brand"] = brand
                report["fuzzing_technique"] = "COMBOSQUATTING"
                logger.warning(f"[HOMOGLYPH MATCH]: {raw_domain} combosquats brand '{brand}'")
                return report

        # Check D: Typosquatting / Edit Distance on meaningful tokens
        for token in tokens:
            if token in {'com', 'net', 'org', 'co', 'uk', 'de', 'in', 'io', 'me', 'xyz', 'app', 'update', 'verify', 'login', 'security'}:
                continue
            distance = levenshtein_distance(token, brand)
            if distance == 1 and token != brand:
                report["is_impersonation_suspect"] = True
                report["matched_brand"] = brand
                report["fuzzing_technique"] = f"TYPOSQUATTING_EDIT_{distance}"
                logger.warning(f"[HOMOGLYPH MATCH]: Token '{token}' is distance {distance} from '{brand}'")
                return report

    return report

def check_brand_impersonation(target: str | list[str]) -> dict:
    """
    Evaluates one or more URLs/domains for leetspeak, combosquatting, typosquatting,
    and Unicode homoglyph impersonation attacks.
    """
    if isinstance(target, str):
        target_list = [target]
    else:
        target_list = list(dict.fromkeys([u for u in target if u]))

    if not target_list:
        return {
            "domain_analyzed": "",
            "is_impersonation_suspect": False,
            "matched_brand": None,
            "fuzzing_technique": None
        }

    reports = [check_single_url_impersonation(u) for u in target_list]
    suspect_report = next((r for r in reports if r["is_impersonation_suspect"]), None)

    if suspect_report:
        return suspect_report

    return reports[0]