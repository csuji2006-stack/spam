"""
SpamShield AI - Detection Engine, Heuristic Intelligence & Explainability (XAI)
Combines Scikit-Learn Ensemble with deep rule-based cyber intelligence heuristics.
"""

import os
import re
import html
import joblib
import numpy as np
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

MODEL_FILE = os.path.join(os.path.dirname(__file__), "models", "spam_detector.joblib")

# Global singleton model pipeline
_PIPELINE = None


def clean_text(text: str) -> str:
    """Preprocess text for model training and inference."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    # Normalize URLs to a token
    text = re.sub(r'https?://\S+|www\.\S+', ' http_url ', text)
    # Normalize currency
    text = re.sub(r'[\$€£₹]\s*\d+', ' currency_val ', text)
    # Normalize numbers
    text = re.sub(r'\b\d{4,}\b', ' num_token ', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def get_model():
    """Load or train model artifact lazily."""
    global _PIPELINE
    if _PIPELINE is not None:
        return _PIPELINE

    if not os.path.exists(MODEL_FILE):
        from .train import train_and_export
        train_and_export()

    artifact = joblib.load(MODEL_FILE)
    _PIPELINE = artifact["pipeline"]
    return _PIPELINE


# -------------------------------------------------------------
# Heuristic Patterns & Cyber Threat Rules
# -------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "vip", "club", "work", "biz", "ru", "cc", "cn", 
    "rest", "online", "site", "cam", "fit", "live", "link", "gq", "ml", "cf"
}

BRAND_IMPERSONATIONS = [
    r"\bpaypal\b", r"\bwells\s*fargo\b", r"\bchase\b", r"\bbank\s*of\s*america\b",
    r"\bnetflix\b", r"\bamazon\b", r"\bapple\s*id\b", r"\bgeek\s*squad\b",
    r"\birs\b", r"\binternal\s*revenue\s*service\b", r"\bmicrosoft\s*365\b",
    r"\bcoinbase\b", r"\busps\b", r"\bfedex\b", r"\bdhl\b", r"\bwalmart\b",
    r"\bat&t\b", r"\bciti\s*bank\b"
]

URGENCY_PATTERNS = [
    (r"\b(urgent|urgently|immediate|immediately)\b", "Urgency indicator", "HIGH"),
    (r"\b(account.*(suspend|restrict|lock|block|terminate|flagged))\b", "Account restriction lure", "CRITICAL"),
    (r"\b(within\s*\d+\s*(hours?|minutes?|hrs?))\b", "Artificial time pressure constraint", "HIGH"),
    (r"\b(final\s*(notice|warning|reminder))\b", "Coercive final warning lure", "HIGH"),
    (r"\b(arrest\s*warrant|legal\s*action|police\s*report)\b", "Extortion / legal intimidation lure", "CRITICAL"),
    (r"\b(unauthorized\s*(access|login|sign-in|charge|transaction))\b", "Fear-inducing security lure", "HIGH"),
    (r"\b(password.*expir\w+)\b", "Fake credential expiration alert", "HIGH")
]

FINANCIAL_SCAM_PATTERNS = [
    (r"\b(inheritance|beneficiary|barrister|late\s*oil\s*magnate)\b", "419 Advanced fee inheritance scam", "CRITICAL"),
    (r"\b(\$\s*\d+([,\.]\d+)?\s*(million|usd|dollars))\b", "Astronomical cash prize lure", "CRITICAL"),
    (r"\b(guaranteed\s*(roi|returns?|profit|income))\b", "Fraudulent investment guarantee", "HIGH"),
    (r"\b(bitcoin\s*giveaway|double\s*your\s*(btc|crypto|eth))\b", "Cryptocurrency giveaway scam", "CRITICAL"),
    (r"\b(pre-approved\s*loan|bad\s*credit\s*accepted)\b", "Predatory loan / credit scam", "MEDIUM"),
    (r"\b(wire\s*transfer|western\s*union|moneygram)\b", "Untraceable money transfer request", "HIGH"),
    (r"\b(lottery\s*winner|lucky\s*winner|chosen\s*winner|won\s*\$\d+)\b", "Fake lottery prize lure", "CRITICAL")
]

CREDENTIAL_HARVESTING_PATTERNS = [
    (r"\b(confirm|verify|update|restore)\s*(your)?\s*(ssn|social\s*security|pin|password|credentials|debit\s*card)\b", "Direct credential / identity theft request", "CRITICAL"),
    (r"\b(click\s*here\s*to\s*(verify|restore|login|unlock|reactivate))\b", "Suspicious authentication call-to-action", "HIGH"),
    (r"\b(unpaid\s*(customs|tax|shipping|clearance)\s*(fee|duty))\b", "Smishing package delivery fee bait", "HIGH")
]

PROMOTIONAL_BOT_PATTERNS = [
    (r"\b(buy\s*(instagram|tiktok|youtube)\s*(followers|likes|views))\b", "Social media engagement bot spam", "HIGH"),
    (r"\b(whatsapp\s*her|whatsapp\s*him|contact\s*on\s*telegram|t\.me/)\b", "Off-platform redirect to encrypted chat", "HIGH"),
    (r"\b(viagra|cialis|xanax|diet\s*pill|belly\s*fat\s*miracle)\b", "Unregulated pharmaceutical / supplement spam", "HIGH")
]


def extract_urls(text: str) -> List[str]:
    """Find all URLs in message text."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)


def analyze_url_threat(url: str) -> Dict[str, Any]:
    """Inspect individual URL for phishing, malicious TLDs, and deception patterns."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
    except Exception:
        return {"risk_score": 50, "flags": ["Invalid or obfuscated URL structure"]}

    flags = []
    risk_score = 0

    # 1. Scheme check
    if parsed.scheme == "http":
        flags.append("Insecure HTTP protocol (missing TLS/SSL encryption)")
        risk_score += 15

    # 2. Hostname is raw IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        flags.append("Host is direct numeric IP address (common evasion tactic)")
        risk_score += 45

    # 3. Suspicious or high-abuse TLD
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"High-abuse top-level domain (.{tld}) commonly used in phishing")
        risk_score += 35

    # 4. Brand spoofing in domain or subdomain
    for b_pat in BRAND_IMPERSONATIONS:
        if re.search(b_pat, hostname) and not hostname.endswith(('paypal.com', 'chase.com', 'apple.com', 'netflix.com', 'amazon.com', 'microsoft.com', 'usps.com', 'fedex.com', 'dhl.com', 'walmart.com', 'att.com', 'citigroup.com')):
            flags.append(f"Suspected brand spoofing / typosquatting in domain name")
            risk_score += 50
            break

    # 5. Phishing keywords in URL path
    sensitive_path_keywords = ["login", "verify", "secure", "auth", "account", "update-billing", "signin", "wallet", "restore"]
    for kw in sensitive_path_keywords:
        if kw in path:
            flags.append(f"Sensitive credential keyword '{kw}' detected in URL path")
            risk_score += 20
            break

    # 6. Excessive dots or hyphens
    if hostname.count('-') >= 2 or hostname.count('.') >= 3:
        flags.append("Excessive hyphens/subdomains in hostname (deceptive domain structure)")
        risk_score += 20

    # 7. Punycode check (homograph attack)
    if "xn--" in hostname:
        flags.append("Punycode / IDN homograph attack detected")
        risk_score += 55

    risk_score = min(100, risk_score)
    return {
        "url": url,
        "hostname": hostname,
        "risk_score": risk_score,
        "is_suspicious": risk_score >= 40,
        "flags": flags
    }


def analyze_heuristics(text: str) -> Dict[str, Any]:
    """Extract heuristic red flags and compute multi-factor cyber risk score."""
    red_flags = []
    total_heuristic_penalty = 0

    urgency_score = 0
    financial_score = 0
    credential_score = 0
    link_score = 0

    # 1. Evaluate Urgency & Fear Patterns
    for pattern, reason, severity in URGENCY_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            red_flags.append({
                "phrase": match.group(0),
                "reason": reason,
                "category": "Urgency & Psychological Coercion",
                "severity": severity
            })
            pts = 35 if severity == "CRITICAL" else 20
            urgency_score += pts
            total_heuristic_penalty += pts

    # 2. Evaluate Financial & Crypto Scams
    for pattern, reason, severity in FINANCIAL_SCAM_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            red_flags.append({
                "phrase": match.group(0),
                "reason": reason,
                "category": "Financial / Crypto Fraud",
                "severity": severity
            })
            pts = 40 if severity == "CRITICAL" else 25
            financial_score += pts
            total_heuristic_penalty += pts

    # 3. Evaluate Credential Theft & Phishing Call to Actions
    for pattern, reason, severity in CREDENTIAL_HARVESTING_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            red_flags.append({
                "phrase": match.group(0),
                "reason": reason,
                "category": "Credential Harvesting",
                "severity": severity
            })
            pts = 45 if severity == "CRITICAL" else 25
            credential_score += pts
            total_heuristic_penalty += pts

    # 4. Evaluate Bot & Social Promo Spam
    for pattern, reason, severity in PROMOTIONAL_BOT_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            red_flags.append({
                "phrase": match.group(0),
                "reason": reason,
                "category": "Bot & Commercial Spam",
                "severity": severity
            })
            pts = 30
            total_heuristic_penalty += pts

    # 5. Evaluate URLs inside text
    urls = extract_urls(text)
    url_threats = []
    if urls:
        for u in urls:
            u_info = analyze_url_threat(u)
            url_threats.append(u_info)
            if u_info["is_suspicious"]:
                link_score += u_info["risk_score"]
                red_flags.append({
                    "phrase": u,
                    "reason": "; ".join(u_info["flags"]) or "Suspicious URL detected",
                    "category": "Phishing Link / Malicious Domain",
                    "severity": "CRITICAL" if u_info["risk_score"] > 60 else "HIGH"
                })
        total_heuristic_penalty += min(60, link_score)

    # 6. Formatting / Obfuscation indicators
    # High uppercase ratio
    letters = [c for c in text if c.isalpha()]
    if letters:
        upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if upper_ratio > 0.4 and len(text) > 20:
            red_flags.append({
                "phrase": "[EXCESSIVE CAPITALIZATION]",
                "reason": "Abnormal uppercase text ratio (>40%) indicating shouting or panic induction",
                "category": "Formatting Anomaly",
                "severity": "MEDIUM"
            })
            total_heuristic_penalty += 15

    # Obfuscated spacing like "p a y p a l" or "f r e e"
    if re.search(r'\b[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\b', text):
        red_flags.append({
            "phrase": "[SPACED CHARACTERS]",
            "reason": "Obfuscated text with spaced characters to evade keyword filters",
            "category": "Evasion Technique",
            "severity": "HIGH"
        })
        total_heuristic_penalty += 25

    heuristic_risk = min(1.0, total_heuristic_penalty / 100.0)

    return {
        "heuristic_risk": heuristic_risk,
        "urgency_score": min(1.0, urgency_score / 100.0),
        "financial_score": min(1.0, financial_score / 100.0),
        "credential_score": min(1.0, credential_score / 100.0),
        "link_score": min(1.0, link_score / 100.0),
        "red_flags": red_flags,
        "url_threats": url_threats
    }


def generate_highlighted_html(text: str, red_flags: List[Dict[str, Any]]) -> str:
    """Highlight identified red flag tokens directly in HTML safe format."""
    safe_text = html.escape(text)

    # Sort phrases by length descending to match longer strings first
    phrases = []
    for rf in red_flags:
        p = rf.get("phrase", "")
        if p and not p.startswith("[") and len(p) >= 3:
            phrases.append((p, rf.get("severity", "HIGH"), rf.get("category", "Flag")))

    phrases = sorted(phrases, key=lambda x: len(x[0]), reverse=True)

    for phrase, severity, cat in phrases:
        escaped_phrase = html.escape(phrase)
        if escaped_phrase in safe_text:
            css_class = "flag-critical" if severity == "CRITICAL" else "flag-warning"
            replacement = f'<mark class="threat-flag {css_class}" title="{html.escape(cat)}: {html.escape(severity)}">{escaped_phrase}</mark>'
            safe_text = safe_text.replace(escaped_phrase, replacement)

    return safe_text


def classify_spam_category(text: str, is_spam: bool, red_flags: List[Dict[str, Any]]) -> str:
    """Categorize the exact threat vector."""
    if not is_spam:
        return "LEGITIMATE_HAM"

    text_lower = text.lower()

    if any(rf.get("category") == "Phishing Link / Malicious Domain" for rf in red_flags) or "verify" in text_lower or "password" in text_lower or "suspended" in text_lower:
        return "PHISHING_CREDENTIAL_THEFT"
    if "usps" in text_lower or "delivery" in text_lower or "parcel" in text_lower or "fedex" in text_lower:
        return "DELIVERY_SMISHING"
    if "crypto" in text_lower or "bitcoin" in text_lower or "investment" in text_lower or "roi" in text_lower:
        return "CRYPTO_FINANCIAL_FRAUD"
    if "lottery" in text_lower or "winner" in text_lower or "inheritance" in text_lower or "gift card" in text_lower:
        return "LOTTERY_ADVANCE_FEE_SCAM"
    if "followers" in text_lower or "whatsapp" in text_lower or "viagra" in text_lower or "telegram" in text_lower:
        return "COMMERCIAL_BOT_SPAM"

    return "UNSOLICITED_BULK_SPAM"


def generate_recommendations(is_spam: bool, risk_level: str, category: str) -> List[str]:
    """Generate tailored security guidance based on scan findings."""
    if not is_spam or risk_level in ("SAFE", "LOW"):
        return [
            "This communication exhibits legitimate linguistic patterns and contains no known threat signatures.",
            "Normal caution is advised: Verify unexpected sender addresses if sensitive actions are requested."
        ]

    recs = [
        "DO NOT click any embedded links or open attachments in this message.",
        "DO NOT provide passwords, one-time OTP codes, credit card numbers, or social security details."
    ]

    if "PHISHING" in category or "DELIVERY" in category:
        recs.append("Check the sender's actual address/number directly through official bookmarks or mobile apps.")
        recs.append("Report message as Phishing / Smishing to your service provider or IT Security department.")
    elif "CRYPTO" in category or "LOTTERY" in category:
        recs.append("Legitimate institutions never ask for wire transfers, crypto deposits, or prepaid cards to claim funds.")
        recs.append("Block the sender immediately across all communication channels.")
    else:
        recs.append("Block and report the sender domain / phone number to prevent future unsolicited contact.")

    return recs


def analyze_message(text: str) -> Dict[str, Any]:
    """
    Main analysis pipeline:
    1. Preprocessing & ML inference via Ensemble Pipeline
    2. Deep heuristic & cyber threat extraction
    3. Multi-layer risk fusion
    4. XAI token highlighting & recommendations
    """
    if not text or not text.strip():
        return {
            "is_spam": False,
            "spam_probability": 0.0,
            "risk_score": 0,
            "risk_level": "SAFE",
            "category": "EMPTY",
            "breakdown": {
                "ml_probability": 0.0,
                "heuristic_score": 0.0,
                "urgency_score": 0.0,
                "financial_score": 0.0,
                "link_score": 0.0
            },
            "red_flags": [],
            "highlighted_html": "",
            "recommendations": ["No text provided for analysis."],
            "char_count": 0,
            "word_count": 0
        }

    # 1. ML Model Probability
    pipeline = get_model()
    try:
        cleaned = clean_text(text)
        ml_prob = float(pipeline.predict_proba([cleaned])[0][1])
    except Exception:
        ml_prob = 0.5

    # 2. Heuristics & Cyber Intelligence
    heuristics = analyze_heuristics(text)
    heuristic_risk = heuristics["heuristic_risk"]

    # 3. Fusion Score (Ensemble + Rule Engine)
    # If critical red flags exist (e.g. spoofed brand domain or fake credential lure), ensure risk is elevated
    has_critical_flag = any(rf.get("severity") == "CRITICAL" for rf in heuristics["red_flags"])

    if has_critical_flag:
        combined_prob = max(ml_prob, 0.85 * heuristic_risk + 0.15 * ml_prob)
        combined_prob = max(combined_prob, 0.88)
    else:
        combined_prob = 0.60 * ml_prob + 0.40 * heuristic_risk

    combined_prob = float(np.clip(combined_prob, 0.0, 1.0))
    risk_score = int(round(combined_prob * 100))

    # Determine Risk Level & Classification
    if risk_score >= 80:
        risk_level = "CRITICAL"
        is_spam = True
    elif risk_score >= 55:
        risk_level = "HIGH"
        is_spam = True
    elif risk_score >= 35:
        risk_level = "SUSPICIOUS"
        is_spam = True
    elif risk_score >= 20:
        risk_level = "LOW_RISK"
        is_spam = False
    else:
        risk_level = "SAFE"
        is_spam = False

    category = classify_spam_category(text, is_spam, heuristics["red_flags"])
    highlighted_html = generate_highlighted_html(text, heuristics["red_flags"])
    recommendations = generate_recommendations(is_spam, risk_level, category)

    return {
        "is_spam": is_spam,
        "spam_probability": round(combined_prob, 4),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category": category,
        "breakdown": {
            "ml_probability": round(ml_prob, 4),
            "heuristic_score": round(heuristic_risk, 4),
            "urgency_score": round(heuristics["urgency_score"], 4),
            "financial_score": round(heuristics["financial_score"], 4),
            "link_score": round(heuristics["link_score"], 4)
        },
        "red_flags": heuristics["red_flags"],
        "url_threats": heuristics["url_threats"],
        "highlighted_html": highlighted_html,
        "recommendations": recommendations,
        "char_count": len(text),
        "word_count": len(text.split())
    }
