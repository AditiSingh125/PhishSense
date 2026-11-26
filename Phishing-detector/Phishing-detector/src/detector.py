import joblib
from pathlib import Path
import pandas as pd, shap
from features import url_features, homepage
ROOT = Path(__file__).resolve().parent.parent
_bundle = joblib.load(ROOT / "models" / "url_model.joblib")
MODEL, COLS = _bundle["model"], _bundle["columns"]
EXPLAINER = shap.TreeExplainer(MODEL)

TEMPLATES = {
    "url_length": "The URL is unusually long ({v:.0f} characters).",
    "hostname_length": "The hostname is long ({v:.0f} characters).",
    "num_dots": "The address has {v:.0f} dots.",
    "num_hyphens": "The address contains {v:.0f} hyphens.",
    "num_digits": "The URL contains {v:.0f} digits.",
    "has_at_symbol": "The URL contains an '@' symbol.",
    "is_ip_host": "It uses a raw IP number instead of a domain name.",
    "num_subdomains": "It has {v:.0f} subdomains.",
    "path_depth": "The path is {v:.0f} levels deep.",
    "url_entropy": "The URL looks random and complex (entropy {v:.2f}).",
    "keyword_count": "It contains {v:.0f} sensitive words such as login, verify, secure or bank.",
    "uses_https": "The site does not use HTTPS.",
}

def check(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    f = url_features(homepage(url))
    x = pd.DataFrame([f])[COLS]
    risk = float(MODEL.predict_proba(x)[0, 1] * 100)
    level = "HIGH" if risk >= 70 else "MEDIUM" if risk >= 30 else "LOW"
    sv = pd.Series(EXPLAINER.shap_values(x)[0], index=COLS).sort_values(ascending=False)
    reasons = []
    if level != "LOW":
        for c in sv.index:
            if sv[c] <= 0 or len(reasons) == 3:
                break
            if c == "uses_https" and f[c] == 1:
                continue
            if c == "path_depth" and f[c] == 0:
                continue
            if c in TEMPLATES:
                reasons.append(TEMPLATES[c].format(v=f[c]))
    return {"risk": risk, "level": level, "reasons": reasons, "features": f}