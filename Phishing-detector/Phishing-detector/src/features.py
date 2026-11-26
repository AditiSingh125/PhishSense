import math, ssl, socket, datetime
from urllib.parse import urlparse
import tldextract, whois, requests
from bs4 import BeautifulSoup

KEYWORDS = ["login", "verify", "secure", "account", "bank", "update", "signin", "confirm"]
def homepage(u):
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    p = urlparse(u)
    return f"{p.scheme}://{p.hostname}"
def _norm(url):
    return url if url.startswith(("http://", "https://")) else "http://" + url

def _entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def url_features(url):
    url = _norm(url)
    p = urlparse(url)
    host = p.hostname or ""
    ext = tldextract.extract(url)
    sub = [s for s in ext.subdomain.split(".") if s]
    return {
        "url_length": len(url), "hostname_length": len(host),
        "num_dots": url.count("."), "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url), "has_at_symbol": int("@" in url),
        "is_ip_host": int(host.replace(".", "").isdigit()), "num_subdomains": len(sub),
        "path_depth": len([x for x in p.path.split("/") if x]),
        "url_entropy": round(_entropy(url), 3),
        "keyword_count": sum(k in url.lower() for k in KEYWORDS),
        "uses_https": int(p.scheme == "https"),
    }
def _registered(host):
    ext = tldextract.extract(host or "")
    return getattr(ext, "top_domain_under_public_suffix", "") or ext.registered_domain

def _first(d):
    return d[0] if isinstance(d, list) else d

def domain_features(url):
    ext = tldextract.extract(_norm(url))
    domain = getattr(ext, "top_domain_under_public_suffix", "") or ext.registered_domain
    out = {"domain_age_days": -1, "days_to_expiry": -1, "whois_available": 0}
    try:
        w = whois.whois(domain)
        created, expires = _first(w.creation_date), _first(w.expiration_date)
        now = datetime.datetime.now()
        if created:
            out["domain_age_days"] = (now - created.replace(tzinfo=None)).days
            out["whois_available"] = 1
        if expires:
            out["days_to_expiry"] = (expires.replace(tzinfo=None) - now).days
    except Exception:
        pass
    return out

def ssl_features(url):
    host = urlparse(_norm(url)).hostname or ""
    out = {"cert_valid": 0, "cert_age_days": -1}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        out["cert_valid"] = 1
        start = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        out["cert_age_days"] = (now - start).days
    except Exception:
        pass
    return out

def html_features(url):
    url = _norm(url)
    out = {"fetch_ok": 0, "num_redirects": 0, "has_password_field": 0, "num_forms": 0,
           "form_external": 0, "num_iframes": 0, "external_link_ratio": 0.0,
           "empty_link_ratio": 0.0, "num_external_scripts": 0}
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0 (college research project)"})
        out["fetch_ok"] = 1
        out["num_redirects"] = len(r.history)
        soup = BeautifulSoup(r.text, "html.parser")
        host = _registered(urlparse(r.url).hostname)

        def is_external(link):
            h = urlparse(link).hostname
            return int(bool(h) and _registered(h) != host)

        out["has_password_field"] = int(bool(soup.find("input", {"type": "password"})))
        forms = soup.find_all("form")
        out["num_forms"] = len(forms)
        out["form_external"] = int(any(is_external(f.get("action", "")) for f in forms))
        out["num_iframes"] = len(soup.find_all("iframe"))
        links = [a.get("href", "") for a in soup.find_all("a")]
        n = max(len(links), 1)
        out["external_link_ratio"] = round(sum(is_external(l) for l in links) / n, 3)
        out["empty_link_ratio"] = round(sum(l.strip() in ("", "#") or l.lower().startswith("javascript") for l in links) / n, 3)
        out["num_external_scripts"] = sum(is_external(s["src"]) for s in soup.find_all("script", src=True))
    except Exception:
        pass
    return out

def extract_features(url):
    f = {}
    for part in (url_features, domain_features, ssl_features, html_features):
        f.update(part(url))
    return f