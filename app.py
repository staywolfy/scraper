"""
NEXUS — Professional Business Intelligence Scraper
Multi-layer extraction engine with 8+ data sources
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from bs4 import BeautifulSoup
import requests, re, json, socket, subprocess, random, time, os, hashlib, ssl, secrets
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime, timedelta
from functools import wraps
import urllib3
urllib3.disable_warnings()

# ── Selenium ──────────────────────────────────────────────────────────────────
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        WDM_OK = True
    except ImportError:
        WDM_OK = False
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False
    WDM_OK = False

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Random key each restart
app.permanent_session_lifetime = timedelta(hours=8)

# ════════════════════════════════════════════════════════
# API KEYS  (add your free keys here)
# ════════════════════════════════════════════════════════
WHOIS_XML_KEY    = "YOUR_WHOISXML_KEY"      # whoisxmlapi.com   → 500 free/month
HUNTER_IO_KEY    = "YOUR_HUNTER_KEY"        # hunter.io         → 25 free/month
CLEARBIT_KEY     = "YOUR_CLEARBIT_KEY"      # clearbit.com      → free tier
IPINFO_KEY       = "YOUR_IPINFO_KEY"        # ipinfo.io         → 50k free/month
BUILTWITH_KEY    = "YOUR_BUILTWITH_KEY"     # builtwith.com     → limited free
SHODAN_KEY       = "YOUR_SHODAN_KEY"        # shodan.io         → free tier

# ════════════════════════════════════════════════════════
# USER DATABASE FILE
# ════════════════════════════════════════════════════════
USERS_FILE   = "nexus_users.json"
HISTORY_FILE = "nexus_history.json"
SESSIONS_FILE = "nexus_sessions.json"

def hash_password(password):
    """SHA-256 hash with salt for security"""
    salt = "nexus_salt_2024_secure"
    return hashlib.sha256((salt + password + salt).encode()).hexdigest()

def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        try:
            return json.load(open(USERS_FILE))
        except: pass
    # Default users if file doesn't exist
    defaults = {
        "admin":   {"password": hash_password("admin123"),    "role": "Admin",    "created": datetime.now().strftime("%d %b %Y"), "active": True},
        "user1":   {"password": hash_password("pass1234"),    "role": "User",     "created": datetime.now().strftime("%d %b %Y"), "active": True},
        "analyst": {"password": hash_password("analyst2024"), "role": "Analyst",  "created": datetime.now().strftime("%d %b %Y"), "active": True},
        "mahesh":  {"password": hash_password("mahesh12345"), "role": "Member",   "created": datetime.now().strftime("%d %b %Y"), "active": True},
    }
    save_users(defaults)
    return defaults

def save_users(users):
    try:
        json.dump(users, open(USERS_FILE, "w"), indent=2)
    except: pass

def register_user(username, password, role="User"):
    """Register a new user"""
    users = load_users()
    if username in users:
        return False, "Username already exists"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    users[username] = {
        "password": hash_password(password),
        "role": role,
        "created": datetime.now().strftime("%d %b %Y %H:%M"),
        "active": True,
        "last_login": "Never",
        "scan_count": 0,
    }
    save_users(users)
    return True, "User registered successfully"

def verify_user(username, password):
    """Verify login credentials"""
    users = load_users()
    if username not in users:
        return False, "User not found"
    user = users[username]
    if not user.get("active", True):
        return False, "Account is disabled"
    if user["password"] != hash_password(password):
        return False, "Incorrect password"
    # Update last login and scan count
    users[username]["last_login"] = datetime.now().strftime("%d %b %Y %H:%M")
    save_users(users)
    return True, user

def get_user_info(username):
    users = load_users()
    return users.get(username, {})

def update_scan_count(username):
    users = load_users()
    if username in users:
        users[username]["scan_count"] = users[username].get("scan_count", 0) + 1
        save_users(users)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
]

SOCIAL_PLATFORMS = {
    "facebook.com":"Facebook","instagram.com":"Instagram","twitter.com":"Twitter/X",
    "x.com":"Twitter/X","linkedin.com":"LinkedIn","youtube.com":"YouTube",
    "tiktok.com":"TikTok","pinterest.com":"Pinterest","threads.net":"Threads",
    "github.com":"GitHub","t.me":"Telegram","wa.me":"WhatsApp",
    "snapchat.com":"Snapchat","reddit.com":"Reddit","medium.com":"Medium",
    "koo.com":"Koo","sharechat.com":"ShareChat","discord.gg":"Discord",
    "twitch.tv":"Twitch","spotify.com":"Spotify",
}

JUNK_EMAILS = {
    "email@domain.tld","email@example.com","user@example.com","noreply@example.com",
    "no-reply@example.com","test@test.com","your@email.com","hello@example.com",
    "admin@example.com","webmaster@example.com","privacy@example.com",
    "legal@example.com","sample@example.com","info@example.com",
    "support@example.com","contact@example.com","sales@example.com",
}

CATEGORY_MAP = {
    "🛒 E-Commerce":     ["cart","checkout","buy now","add to cart","shop","product","order","shipping","flipkart","amazon","myntra","snapdeal"],
    "🍔 Food & Delivery":["menu","order food","restaurant","cuisine","delivery","swiggy","zomato","food","dining"],
    "📰 News & Media":   ["breaking news","headline","article","reporter","politics","ndtv","times","hindustan"],
    "💻 Technology":     ["software","saas","api","cloud","dashboard","subscription","developer","tech","startup"],
    "🏥 Healthcare":     ["doctor","hospital","clinic","medicine","health","patient","pharmacy","wellness"],
    "🎓 Education":      ["course","learn","student","exam","certificate","academy","college","university","byjus"],
    "💰 Finance":        ["bank","loan","invest","insurance","mutual fund","stock","finance","payment","upi"],
    "🏠 Real Estate":    ["property","flat","apartment","rent","builder","sqft","bedroom","housing","99acres"],
    "✈️ Travel":         ["hotel","flight","tour","trip","vacation","booking","destination","makemytrip"],
    "📝 Blog/Content":   ["blog","post","article","author","category","subscribe","newsletter","wordpress"],
    "🏛️ Government":     ["gov","government","ministry","department","scheme","portal","citizen","official"],
    "🎬 Entertainment":  ["movie","watch","stream","episode","series","music","song","video","netflix","spotify"],
    "💼 Job Portal":     ["job","career","vacancy","apply","resume","hiring","recruitment","employer","naukri"],
    "🌐 Social Media":   ["profile","follow","like","share","feed","community","forum","friend","connect"],
}

COMPETITORS_DB = {
    "amazon":      ["Flipkart","Meesho","Myntra","Snapdeal","Ajio","Nykaa"],
    "flipkart":    ["Amazon","Meesho","Myntra","Snapdeal","Ajio","Tata Cliq"],
    "swiggy":      ["Zomato","Dunzo","Blinkit","Zepto","EatSure"],
    "zomato":      ["Swiggy","Dunzo","Blinkit","EatSure","Magicpin"],
    "myntra":      ["Ajio","Nykaa Fashion","Amazon Fashion","H&M","Zara"],
    "youtube":     ["Netflix","Hotstar","Prime Video","MX Player","Voot"],
    "netflix":     ["Hotstar","Amazon Prime","Zee5","SonyLiv","Jio Cinema"],
    "facebook":    ["Instagram","Twitter/X","Snapchat","LinkedIn","Threads"],
    "instagram":   ["Facebook","Snapchat","Pinterest","TikTok","BeReal"],
    "twitter":     ["Facebook","Instagram","Threads","Mastodon","Bluesky"],
    "linkedin":    ["Naukri","Indeed","Glassdoor","Monster","Shine"],
    "naukri":      ["LinkedIn","Indeed","Monster","Shine","TimesJobs","Apna"],
    "google":      ["Bing","DuckDuckGo","Yahoo","Yandex","Ecosia"],
    "airbnb":      ["MakeMyTrip","OYO","Booking.com","Goibibo","Trivago"],
    "makemytrip":  ["Goibibo","Cleartrip","Yatra","EaseMyTrip","Booking.com"],
    "paytm":       ["PhonePe","Google Pay","Amazon Pay","BHIM","MobiKwik"],
    "byju":        ["Unacademy","Vedantu","WhiteHatJr","Toppr","Doubtnut"],
    "ola":         ["Uber","Rapido","InDrive","BluSmart","Yulu"],
    "uber":        ["Ola","Rapido","InDrive","Lyft","DiDi"],
    "nykaa":       ["Purplle","MyGlamm","Sugar Cosmetics","Mamaearth","mCaffeine"],
    "hdfc":        ["ICICI","SBI","Axis Bank","Kotak","Yes Bank"],
    "reliance":    ["Tata","Adani","Birla","Mahindra","Bajaj"],
    "infosys":     ["TCS","Wipro","HCL","Tech Mahindra","Cognizant"],
    "tcs":         ["Infosys","Wipro","HCL","Accenture","IBM"],
    "shopify":     ["WooCommerce","Magento","BigCommerce","Wix","Squarespace"],
    "wordpress":   ["Wix","Squarespace","Webflow","Ghost","Drupal"],
}

# ════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        # Session timeout check (8 hours)
        login_time = session.get("login_time")
        if login_time:
            lt = datetime.strptime(login_time, "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - lt).total_seconds() > 28800:
                session.clear()
                return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ════════════════════════════════════════════════════════
# HISTORY — Per-user private history
# ════════════════════════════════════════════════════════
def load_history(username=None):
    """Load history - filtered per user for privacy"""
    try:
        if os.path.exists(HISTORY_FILE):
            all_history = json.load(open(HISTORY_FILE))
            if username:
                # Each user sees ONLY their own history
                return [h for h in all_history if h.get("username") == username]
            return all_history
    except: pass
    return []

def save_history(entry):
    try:
        if os.path.exists(HISTORY_FILE):
            all_history = json.load(open(HISTORY_FILE))
        else:
            all_history = []
        all_history.insert(0, entry)
        json.dump(all_history[:500], open(HISTORY_FILE,"w"), indent=2)
    except: pass

# ════════════════════════════════════════════════════════
# FETCH ENGINE
# ════════════════════════════════════════════════════════
def selenium_fetch(url, debug):
    if not SELENIUM_OK:
        debug.append({"step":"Selenium","status":"skip","msg":"Not installed"})
        return None
    opts = ChromeOptions()
    for arg in ["--headless=new","--no-sandbox","--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--window-size=1920,1080","--ignore-certificate-errors",
                "--disable-gpu","--disable-extensions",
                f"--user-agent={random.choice(USER_AGENTS)}"]:
        opts.add_argument(arg)
    opts.add_experimental_option("excludeSwitches",["enable-automation"])
    opts.add_experimental_option("useAutomationExtension",False)
    driver = None
    try:
        if WDM_OK:
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=opts)
        else:
            driver = webdriver.Chrome(options=opts)
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument",{
            "source":"Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
        })
        driver.set_page_load_timeout(30)
        driver.get(url)
        WebDriverWait(driver,10).until(EC.presence_of_element_located((By.TAG_NAME,"body")))
        time.sleep(2.5)
        driver.execute_script("window.scrollTo(0,document.body.scrollHeight/2)")
        time.sleep(1)
        html = driver.page_source
        driver.quit()
        if len(html) > 500:
            debug.append({"step":"Selenium","status":"ok","msg":f"Loaded {len(html):,} bytes"})
            return html
        return None
    except Exception as e:
        if driver:
            try: driver.quit()
            except: pass
        debug.append({"step":"Selenium","status":"fail","msg":str(e)[:80]})
        return None

def http_fetch(url, debug):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    sess = requests.Session()
    sess.headers.update(headers)
    attempts = [url]
    parsed = urlparse(url)
    if url.startswith("https://"):
        attempts.append(url.replace("https://","http://"))
    if not parsed.netloc.startswith("www."):
        attempts.append(f"{parsed.scheme}://www.{parsed.netloc}{parsed.path}")

    for attempt in attempts:
        try:
            r = sess.get(attempt, timeout=15, allow_redirects=True, verify=False)
            if r.status_code == 200 and len(r.text) > 300:
                debug.append({"step":"HTTP Fetch","status":"ok","msg":f"HTTP {r.status_code} — {len(r.text):,} bytes"})
                return r.text
        except Exception as e:
            debug.append({"step":"HTTP Fetch","status":"fail","msg":str(e)[:60]})

    # Google Cache fallback
    try:
        r = sess.get(f"https://webcache.googleusercontent.com/search?q=cache:{url}", timeout=10, verify=False)
        if r.status_code == 200:
            debug.append({"step":"Google Cache","status":"ok","msg":"Loaded from cache"})
            return r.text
    except:
        debug.append({"step":"Google Cache","status":"fail","msg":"Cache unavailable"})
    return None

def fetch_subpage(base_url, path, debug):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(base_url+path, headers=headers, timeout=8, verify=False)
        if r.status_code == 200:
            return r.text
    except: pass
    return None

# ════════════════════════════════════════════════════════
# EXTRACTORS
# ════════════════════════════════════════════════════════
def extract_emails(html, soup, debug):
    found = set()
    # 1. mailto: links
    for a in soup.find_all("a", href=True):
        h = a["href"]
        if h.lower().startswith("mailto:"):
            e = h[7:].split("?")[0].strip().lower()
            if "@" in e: found.add(e)
    # 2. data-email attributes
    for tag in soup.find_all(attrs={"data-email":True}):
        e = tag["data-email"].strip().lower()
        if "@" in e: found.add(e)
    # 3. JSON-LD
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            d = json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            e = d.get("email","")
            if e and "@" in e: found.add(e.lower().replace("mailto:",""))
        except: pass
    # 4. Email-class elements
    for tag in soup.find_all(class_=re.compile(r"email|mail|contact",re.I)):
        for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", tag.get_text()):
            found.add(e.lower())
    # 5. Full HTML regex
    for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html):
        found.add(e.lower())

    clean, seen = [], set()
    for e in sorted(found):
        if (e in JUNK_EMAILS or len(e)>80 or len(e)<6 or "example" in e
            or "domain.tld" in e or "sentry" in e or e in seen
            or re.search(r"\.(png|jpg|gif|svg|css|js|woff|ttf|ico|php)$",e,re.I)):
            continue
        seen.add(e); clean.append(e)

    debug.append({"step":"Email Extraction","status":"ok" if clean else "warn",
                  "msg":f"Found {len(clean)} email(s): {', '.join(clean[:3]) or 'none'}"})
    return clean[:10]

def extract_phones(soup, text, debug):
    found, seen = [], set()
    def add(n):
        n = n.strip()
        d = re.sub(r"\D","",n)
        if not (6<=len(d)<=15): return
        if re.fullmatch(r"(19|20)\d{2}",d): return
        if re.fullmatch(r"(19|20)\d{6}",d): return
        if d in seen: return
        seen.add(d); found.append(n)

    for a in soup.find_all("a",href=True):
        if a["href"].startswith("tel:"): add(a["href"][4:])
    for tag in soup.find_all(attrs={"itemprop":re.compile(r"telephone|phone",re.I)}):
        add(tag.get_text(strip=True))
    for tag in soup.find_all(attrs={"data-phone":True}):
        add(tag["data-phone"])
    for script in soup.find_all("script",type="application/ld+json"):
        try:
            d=json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            ph=d.get("telephone") or d.get("phone","")
            if ph: add(str(ph))
        except: pass
    for tag in soup.find_all(class_=re.compile(r"phone|mobile|tel|contact",re.I)):
        for m in re.finditer(r"[\+\d][\d\s\-\.\(\)]{6,20}",tag.get_text()):
            add(m.group())
    for pat in [r"\+91[\s\-]?[6-9]\d{9}",r"\b[6-9]\d{9}\b",
                r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{2,5}[\s\-]?\d{4,6}",
                r"\(?\d{3}\)?[\s\.\-]\d{3}[\s\.\-]\d{4}",
                r"\b0\d{2,4}[\s\-]\d{6,8}\b",r"\+\d{10,13}"]:
        for m in re.finditer(pat,text):
            add(m.group())

    debug.append({"step":"Phone Extraction","status":"ok" if found else "warn",
                  "msg":f"Found {len(found)} phone(s): {', '.join(found[:2]) or 'none'}"})
    return found[:6]

def extract_address(soup, text, debug):
    def clean(s):
        s=re.sub(r"\s+"," ",s).strip()
        return s if 10<len(s)<600 else None

    # JSON-LD
    for script in soup.find_all("script",type="application/ld+json"):
        try:
            d=json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            for key in ["address","location"]:
                addr=d.get(key,{})
                if isinstance(addr,str):
                    r=clean(addr)
                    if r:
                        debug.append({"step":"Address","status":"ok","msg":"Found via JSON-LD"})
                        return r
                if isinstance(addr,dict):
                    parts=[addr.get(k,"") for k in ("streetAddress","addressLocality","addressRegion","postalCode","addressCountry")]
                    r=clean(", ".join(p for p in parts if p))
                    if r:
                        debug.append({"step":"Address","status":"ok","msg":"Found via JSON-LD structured"})
                        return r
        except: pass

    # <address> tag
    tag=soup.find("address")
    if tag:
        r=clean(tag.get_text(" "))
        if r:
            debug.append({"step":"Address","status":"ok","msg":"Found via <address> tag"})
            return r

    # itemprop
    for attr in ["address","streetAddress","location"]:
        tag=soup.find(attrs={"itemprop":attr})
        if tag:
            r=clean(tag.get_text(" "))
            if r:
                debug.append({"step":"Address","status":"ok","msg":f"Found via itemprop={attr}"})
                return r

    # CSS classes
    addr_re=re.compile(r"\b(address|addr|location|office|postal|hq|branch|contact[\-_]?address)\b",re.I)
    for tag in soup.find_all(["div","p","span","li","section","footer"],limit=800):
        cls=" ".join(tag.get("class",[]))
        iid=tag.get("id","")
        if addr_re.search(cls) or addr_re.search(iid):
            r=clean(tag.get_text(" "))
            if r:
                debug.append({"step":"Address","status":"ok","msg":"Found via CSS class/id"})
                return r

    # Footer
    footer=soup.find("footer") or soup.find(class_=re.compile(r"footer",re.I))
    if footer:
        ft=footer.get_text(" ")
        for pat in [r"[\w\s,\-\.#]+\d{6}(?!\d)",r"[\w\s,\.\-]+[A-Z]{2}\s+\d{5}"]:
            m=re.search(pat,ft)
            if m:
                r=clean(m.group())
                if r:
                    debug.append({"step":"Address","status":"ok","msg":"Found in footer"})
                    return r

    # Regex
    for pat in [r"(?:No\.?\s*)?\d{1,5}[\s,]+[\w\s]{5,60},[\s]*[\w\s]{3,40},[\s]*\d{6}",
                r"\d{1,5}\s+[\w\s]{2,40},\s*[\w\s]{2,30},\s*[A-Z]{2}\s*\d{5}",
                r"[\w\s,\.\-]{10,100}\d{5,6}"]:
        m=re.search(pat,text)
        if m:
            r=clean(m.group())
            if r:
                debug.append({"step":"Address","status":"ok","msg":"Found via regex pattern"})
                return r

    # Keyword
    kw=re.compile(r"(?:address|office|location|head\s?quarters|registered\s?office|find\s?us)[:\-\s]+",re.I)
    m=kw.search(text)
    if m:
        snippet=re.split(r"\n{2,}",text[m.end():m.end()+300])[0]
        r=clean(snippet)
        if r:
            debug.append({"step":"Address","status":"ok","msg":"Found via keyword context"})
            return r

    debug.append({"step":"Address","status":"warn","msg":"Not found on page"})
    return "Not Found"

def extract_owner(soup, debug):
    # JSON-LD
    for script in soup.find_all("script",type="application/ld+json"):
        try:
            d=json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            for field in ["founder","author","creator","director","employee"]:
                p=d.get(field)
                if isinstance(p,dict):
                    n=p.get("name","")
                    if n and 2<len(n)<60:
                        debug.append({"step":"Owner","status":"ok","msg":f"Found via JSON-LD {field}"})
                        return n
                elif isinstance(p,list) and p:
                    n=(p[0] if isinstance(p[0],dict) else {}).get("name","")
                    if n and 2<len(n)<60:
                        debug.append({"step":"Owner","status":"ok","msg":f"Found via JSON-LD {field} list"})
                        return n
        except: pass

    # Meta author
    tag=soup.find("meta",attrs={"name":re.compile(r"^author$",re.I)})
    if tag and tag.get("content"):
        n=tag["content"].strip()
        if 2<len(n)<60 and not re.search(r"http|www|\.",n):
            debug.append({"step":"Owner","status":"ok","msg":"Found via meta author"})
            return n

    # HTML elements
    for tag in soup.find_all(["span","div","p","h2","h3","h4"],limit=500):
        cls=" ".join(tag.get("class",[])).lower()
        if any(k in cls for k in ["founder","ceo","owner","director","author","team-name"]):
            n=tag.get_text(strip=True)
            if 3<len(n)<60 and not re.search(r"http|@|\d{5}",n):
                debug.append({"step":"Owner","status":"ok","msg":"Found via HTML class"})
                return n

    # Regex
    text=soup.get_text(" ")
    for pat in [r"(?:Founded by|Founder)[:\s—]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)",
                r"(?:CEO|Chief Executive)[:\s—]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)",
                r"(?:Owner|Director|MD|President)[:\s—]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)"]:
        m=re.search(pat,text)
        if m:
            debug.append({"step":"Owner","status":"ok","msg":"Found via page text regex"})
            return m.group(1)

    debug.append({"step":"Owner","status":"warn","msg":"Not found on page"})
    return "Not Found"

def extract_name(soup):
    for prop,attr in [("og:site_name","property"),("og:title","property"),("application-name","name")]:
        tag=soup.find("meta",{attr:prop})
        if tag and tag.get("content"):
            v=tag["content"].strip()
            for sep in [" | "," - "," – "," — "," :: "]:
                v=v.split(sep)[0]
            if v and len(v)<80: return v
    for script in soup.find_all("script",type="application/ld+json"):
        try:
            d=json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            n=d.get("name") or d.get("legalName","")
            if n and len(n)<80: return n
        except: pass
    if soup.title and soup.title.string:
        t=soup.title.string.strip()
        for sep in [" | "," - "," – "," — "," :: "]:
            t=t.split(sep)[0]
        return t.strip()
    return "Not Found"

def extract_description(soup):
    for attr,val in [("property","og:description"),("name","description"),("name","twitter:description")]:
        tag=soup.find("meta",{attr:val})
        if tag and tag.get("content"):
            return tag["content"].strip()[:600]
    for script in soup.find_all("script",type="application/ld+json"):
        try:
            d=json.loads(script.string or "")
            if isinstance(d,list): d=d[0]
            desc=d.get("description","")
            if desc and len(desc)>20: return desc[:600]
        except: pass
    for p in soup.find_all("p"):
        t=p.get_text(strip=True)
        if len(t)>80: return t[:400]
    return "Not Found"

def extract_social(soup, base_url):
    found={}
    for a in soup.find_all("a",href=True):
        href=a["href"].strip()
        if not href or href.startswith(("#","javascript","mailto","tel")): continue
        full=urljoin(base_url,href)
        for domain,label in SOCIAL_PLATFORMS.items():
            if domain in full and label not in found:
                if len(urlparse(full).path)>1:
                    found[label]=full
    return [{"label":k,"url":v} for k,v in found.items()]

def extract_tech_stack(soup, html):
    tech=[]
    checks={
        "WordPress":   ["wp-content","wp-includes","wordpress"],
        "React":       ["react","__REACT","_react"],
        "Angular":     ["ng-version","angular","ng-app"],
        "Vue.js":      ["vue.js","vuejs","__vue"],
        "jQuery":      ["jquery.min","jquery.js"],
        "Bootstrap":   ["bootstrap.min","bootstrap.css"],
        "Shopify":     ["shopify","cdn.shopify"],
        "Wix":         ["wix.com","static.wixstatic"],
        "Squarespace": ["squarespace.com","static.squarespace"],
        "Magento":     ["mage/","magento"],
        "Next.js":     ["__NEXT_DATA__","_next/static"],
        "Nuxt.js":     ["__NUXT__","nuxt.js"],
        "Google Analytics":["google-analytics","gtag(","UA-","G-"],
        "Facebook Pixel":  ["fbq(","connect.facebook.net"],
        "Cloudflare":      ["cloudflare","__cfduid","cf-ray"],
        "AWS":             ["amazonaws.com","cloudfront.net"],
        "Google Cloud":    ["googleapis.com","googlecloud"],
        "Nginx":           ["nginx"],
        "Apache":          ["apache"],
    }
    html_lower=html.lower()
    for name,patterns in checks.items():
        if any(p.lower() in html_lower for p in patterns):
            tech.append(name)
    return tech

def detect_category(soup, text, domain):
    text_lower=(text+" "+domain).lower()
    scores={}
    for cat,kws in CATEGORY_MAP.items():
        score=sum(1 for kw in kws if kw in text_lower)
        if score>0: scores[cat]=score
    return max(scores,key=scores.get) if scores else "🌐 General Website"

def find_competitors(domain, category):
    d=domain.lower()
    for key,comps in COMPETITORS_DB.items():
        if key in d: return comps
    cat_map={
        "🛒 E-Commerce":     ["Amazon","Flipkart","Meesho","Myntra","Snapdeal"],
        "🍔 Food & Delivery":["Swiggy","Zomato","Dunzo","Blinkit","Zepto"],
        "💻 Technology":     ["Salesforce","HubSpot","Zoho","Freshworks","SAP"],
        "🏥 Healthcare":     ["Practo","1mg","PharmEasy","Netmeds","Apollo"],
        "🎓 Education":      ["Byju's","Unacademy","Vedantu","Toppr","Doubtnut"],
        "💰 Finance":        ["Paytm","PhonePe","Google Pay","Groww","Zerodha"],
        "🏠 Real Estate":    ["99acres","MagicBricks","Housing.com","NoBroker"],
        "✈️ Travel":         ["MakeMyTrip","Goibibo","Cleartrip","Yatra"],
        "💼 Job Portal":     ["Naukri","LinkedIn","Indeed","Shine","Monster"],
        "🎬 Entertainment":  ["Netflix","Hotstar","Amazon Prime","Zee5"],
        "🌐 Social Media":   ["Facebook","Instagram","Twitter/X","Snapchat"],
        "📰 News & Media":   ["Times of India","NDTV","The Hindu","HT"],
    }
    return cat_map.get(category,["Google","Yahoo","Bing","Wikipedia","DuckDuckGo"])

def generate_summary(data):
    name    = data.get("website_name","this website")
    cat     = data.get("category","")
    desc    = data.get("description","")
    emails  = data.get("emails",[])
    phones  = data.get("phones",[])
    addr    = data.get("address","")
    social  = data.get("social",[])
    tech    = data.get("tech_stack",[])
    country = data.get("country","")
    domain  = data.get("domain","")

    parts=[]
    parts.append(f"{name} ({domain}) is a {cat} platform.")
    if desc and desc!="Not Found":
        parts.append(desc[:200]+("..." if len(desc)>200 else ""))
    if country and country!="Not Found":
        parts.append(f"The domain is registered in {country}.")
    if emails:
        parts.append(f"Public contact email: {emails[0]}.")
    if phones:
        parts.append(f"Contact phone: {phones[0]}.")
    if addr and addr!="Not Found":
        parts.append(f"Business address: {addr[:120]}.")
    if social:
        pl=", ".join(s["label"] for s in social[:4])
        parts.append(f"Active on social media: {pl}.")
    if tech:
        parts.append(f"Built with: {', '.join(tech[:5])}.")
    return " ".join(parts)

# ════════════════════════════════════════════════════════
# WHOIS ENGINE — 3 sources
# ════════════════════════════════════════════════════════
def format_date(raw):
    if not raw or raw=="Not Found": return raw
    for fmt in ["%Y-%m-%dT%H:%M:%SZ","%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d","%d-%b-%Y","%d/%m/%Y","%Y%m%d"]:
        try:
            return datetime.strptime(raw[:19],fmt[:len(raw[:19])]).strftime("%d %b %Y")
        except: pass
    return raw[:10] if len(raw)>10 else raw

def whois_rdap(domain, debug):
    debug.append({"step":"WHOIS → RDAP","status":"running","msg":"Querying IANA RDAP..."})
    try:
        r=requests.get(f"https://rdap.org/domain/{domain}",timeout=12,
                       headers={"Accept":"application/rdap+json"})
        if r.status_code!=200:
            debug.append({"step":"WHOIS → RDAP","status":"fail","msg":f"HTTP {r.status_code}"})
            return None
        data=r.json()
        events={e["eventAction"]:e["eventDate"] for e in data.get("events",[])}
        ns=[n.get("ldhName","") for n in data.get("nameservers",[])]
        registrar,reg_url,owner,org,country="Not Found","Not Found","Not Found","Not Found","Not Found"
        reg_email="Not Found"
        for ent in data.get("entities",[]):
            roles=ent.get("roles",[])
            vcard=ent.get("vcardArray",[None,[]])[1]
            if "registrar" in roles:
                for vc in vcard:
                    if vc[0]=="fn": registrar=vc[3]
                links=ent.get("links",[])
                if links: reg_url=links[0].get("href","Not Found")
            if "registrant" in roles:
                for vc in vcard:
                    if vc[0]=="fn" and owner=="Not Found": owner=vc[3]
                    if vc[0]=="org" and org=="Not Found":  org=str(vc[3])
                    if vc[0]=="email" and reg_email=="Not Found": reg_email=vc[3]
                    if vc[0]=="adr":
                        adr=vc[3] if isinstance(vc[3],list) else []
                        if len(adr)>6 and country=="Not Found": country=adr[6] if adr[6] else "Not Found"
        # Domain age
        created_raw=events.get("registration","")
        age_days="Not Found"
        if created_raw:
            try:
                ct=datetime.fromisoformat(created_raw.replace("Z","+00:00").replace("+00:00",""))
                age_days=str((datetime.utcnow()-ct).days)
            except: pass
        result={
            "source":"RDAP (Free — No Key)","domain":data.get("ldhName",domain),
            "registrar":registrar,"registrar_url":reg_url,
            "creation_date":format_date(events.get("registration","Not Found")),
            "expiration_date":format_date(events.get("expiration","Not Found")),
            "updated_date":format_date(events.get("last changed","Not Found")),
            "domain_status":", ".join(data.get("status",[])) or "Not Found",
            "owner_name":owner,"organization":org,"country":country,
            "state":"Not Found","city":"Not Found","registrant_email":reg_email,
            "name_servers":", ".join(filter(None,ns[:6])) or "Not Found",
            "dnssec":"Signed" if data.get("secureDNS",{}).get("delegationSigned") else "Unsigned",
            "domain_age_days":age_days,
        }
        debug.append({"step":"WHOIS → RDAP","status":"ok","msg":f"Registrar: {registrar}"})
        return result
    except Exception as e:
        debug.append({"step":"WHOIS → RDAP","status":"fail","msg":str(e)[:80]})
        return None

def whois_xmlapi(domain, debug):
    if WHOIS_XML_KEY=="YOUR_WHOISXML_KEY":
        debug.append({"step":"WHOIS → WhoisXML","status":"skip","msg":"API key not set"})
        return None
    debug.append({"step":"WHOIS → WhoisXML","status":"running","msg":"Querying WhoisXML API..."})
    try:
        r=requests.get("https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={"apiKey":WHOIS_XML_KEY,"domainName":domain,"outputFormat":"JSON"},timeout=12)
        data=r.json()
        if "ErrorMessage" in data:
            debug.append({"step":"WHOIS → WhoisXML","status":"fail","msg":data["ErrorMessage"].get("msg","error")})
            return None
        w=data.get("WhoisRecord",{})
        reg=w.get("registrant",{})
        ns=w.get("nameServers",{}).get("hostNames",[])
        created_raw=w.get("createdDate","")
        age_days="Not Found"
        if created_raw:
            try:
                ct=datetime.fromisoformat(created_raw[:19])
                age_days=str((datetime.utcnow()-ct).days)
            except: pass
        result={
            "source":"WhoisXML API","domain":domain,
            "registrar":w.get("registrarName","Not Found"),
            "registrar_url":str(w.get("registrarIANAID","Not Found")),
            "creation_date":format_date(w.get("createdDate","Not Found")),
            "expiration_date":format_date(w.get("expiresDate","Not Found")),
            "updated_date":format_date(w.get("updatedDate","Not Found")),
            "domain_status":w.get("status","Not Found"),
            "owner_name":reg.get("name","Not Found"),
            "organization":reg.get("organization","Not Found"),
            "country":reg.get("country","Not Found"),
            "state":reg.get("state","Not Found"),
            "city":reg.get("city","Not Found"),
            "registrant_email":reg.get("email","Not Found"),
            "name_servers":", ".join(ns[:6]) if ns else "Not Found",
            "dnssec":w.get("dnsSec","Not Found"),
            "domain_age_days":age_days,
        }
        debug.append({"step":"WHOIS → WhoisXML","status":"ok","msg":f"Registrar: {result['registrar']}"})
        return result
    except Exception as e:
        debug.append({"step":"WHOIS → WhoisXML","status":"fail","msg":str(e)[:80]})
        return None

def whois_system(domain, debug):
    debug.append({"step":"WHOIS → System","status":"running","msg":"Running system whois..."})
    try:
        proc=subprocess.run(["whois",domain],capture_output=True,text=True,timeout=15)
        raw=proc.stdout
        if not raw or len(raw)<100:
            debug.append({"step":"WHOIS → System","status":"fail","msg":"No output"})
            return None
        def find(pats,t):
            for pat in pats:
                m=re.search(pat,t,re.I|re.M)
                if m: return m.group(1).strip()
            return "Not Found"
        created_raw=find([r"Creation Date:\s*(.+)",r"created:\s*(.+)"],raw)
        age_days="Not Found"
        if created_raw and created_raw!="Not Found":
            try:
                ct=datetime.fromisoformat(created_raw[:19])
                age_days=str((datetime.utcnow()-ct).days)
            except: pass
        result={
            "source":"System WHOIS","domain":domain,
            "registrar":find([r"Registrar:\s*(.+)"],raw),
            "registrar_url":find([r"Registrar URL:\s*(.+)"],raw),
            "creation_date":format_date(created_raw),
            "expiration_date":format_date(find([r"Registry Expiry Date:\s*(.+)",r"Expiry Date:\s*(.+)"],raw)),
            "updated_date":format_date(find([r"Updated Date:\s*(.+)"],raw)),
            "domain_status":find([r"Domain Status:\s*(.+)"],raw),
            "owner_name":find([r"Registrant Name:\s*(.+)"],raw),
            "organization":find([r"Registrant Organization:\s*(.+)"],raw),
            "country":find([r"Registrant Country:\s*(.+)"],raw),
            "state":find([r"Registrant State/Province:\s*(.+)"],raw),
            "city":find([r"Registrant City:\s*(.+)"],raw),
            "registrant_email":find([r"Registrant Email:\s*(.+)"],raw),
            "name_servers":find([r"Name Server:\s*(.+)"],raw),
            "dnssec":find([r"DNSSEC:\s*(.+)"],raw),
            "domain_age_days":age_days,
        }
        debug.append({"step":"WHOIS → System","status":"ok","msg":f"Registrar: {result['registrar']}"})
        return result
    except FileNotFoundError:
        debug.append({"step":"WHOIS → System","status":"skip","msg":"whois not installed"})
        return None
    except Exception as e:
        debug.append({"step":"WHOIS → System","status":"fail","msg":str(e)[:80]})
        return None

# ════════════════════════════════════════════════════════
# DNS + IP + SERVER INFO
# ════════════════════════════════════════════════════════
def get_ip_info(domain, debug):
    info={"ip_address":"Not Found","server_location":"Not Found",
          "isp":"Not Found","timezone":"Not Found","asn":"Not Found",
          "org":"Not Found","lat":"Not Found","lon":"Not Found"}
    debug.append({"step":"DNS / IP","status":"running","msg":"Resolving domain IP..."})
    try:
        ip=socket.gethostbyname(domain)
        info["ip_address"]=ip
        # Try ipinfo.io
        token_param=f"?token={IPINFO_KEY}" if IPINFO_KEY!="YOUR_IPINFO_KEY" else ""
        r=requests.get(f"https://ipinfo.io/{ip}/json{token_param}",timeout=6)
        if r.status_code==200:
            d=r.json()
            parts=[d.get("city",""),d.get("region",""),d.get("country","")]
            info["server_location"]=", ".join(p for p in parts if p) or "Not Found"
            info["isp"]=d.get("org","Not Found")
            info["timezone"]=d.get("timezone","Not Found")
            loc=d.get("loc","")
            if loc:
                coords=loc.split(",")
                if len(coords)==2:
                    info["lat"]=coords[0]
                    info["lon"]=coords[1]
        debug.append({"step":"DNS / IP","status":"ok","msg":f"IP: {ip}, Location: {info['server_location']}"})
    except Exception as e:
        debug.append({"step":"DNS / IP","status":"fail","msg":str(e)[:80]})
    return info

def get_ssl_info(domain, debug):
    info={"ssl_issuer":"Not Found","ssl_valid_from":"Not Found",
          "ssl_valid_to":"Not Found","ssl_version":"Not Found"}
    debug.append({"step":"SSL Certificate","status":"running","msg":"Checking SSL..."})
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain,443))
            cert=s.getpeercert()
            subject=dict(x[0] for x in cert.get("subject",()))
            issuer=dict(x[0] for x in cert.get("issuer",()))
            info["ssl_issuer"]=issuer.get("organizationName","Not Found")
            info["ssl_valid_from"]=cert.get("notBefore","Not Found")
            info["ssl_valid_to"]=cert.get("notAfter","Not Found")
            info["ssl_version"]=s.version()
        debug.append({"step":"SSL Certificate","status":"ok","msg":f"Issuer: {info['ssl_issuer']}"})
    except Exception as e:
        debug.append({"step":"SSL Certificate","status":"fail","msg":str(e)[:60]})
    return info

def hunter_email_finder(domain, debug):
    if HUNTER_IO_KEY=="YOUR_HUNTER_KEY":
        debug.append({"step":"Hunter.io","status":"skip","msg":"API key not set"})
        return []
    debug.append({"step":"Hunter.io","status":"running","msg":"Searching emails via Hunter.io..."})
    try:
        r=requests.get("https://api.hunter.io/v2/domain-search",
            params={"domain":domain,"api_key":HUNTER_IO_KEY,"limit":10},timeout=10)
        data=r.json()
        emails=[e["value"] for e in data.get("data",{}).get("emails",[]) if e.get("value")]
        debug.append({"step":"Hunter.io","status":"ok","msg":f"Found {len(emails)} email(s)"})
        return emails
    except Exception as e:
        debug.append({"step":"Hunter.io","status":"fail","msg":str(e)[:60]})
        return []

def clearbit_enrich(domain, debug):
    if CLEARBIT_KEY=="YOUR_CLEARBIT_KEY":
        debug.append({"step":"Clearbit","status":"skip","msg":"API key not set"})
        return {}
    debug.append({"step":"Clearbit","status":"running","msg":"Enriching domain data..."})
    try:
        r=requests.get(f"https://company.clearbit.com/v2/companies/find",
            params={"domain":domain},
            headers={"Authorization":f"Bearer {CLEARBIT_KEY}"},timeout=10)
        if r.status_code==200:
            d=r.json()
            result={
                "cb_name":d.get("name",""),
                "cb_description":d.get("description",""),
                "cb_industry":d.get("category",{}).get("industry",""),
                "cb_employees":str(d.get("metrics",{}).get("employees","")),
                "cb_revenue":str(d.get("metrics",{}).get("annualRevenue","")),
                "cb_founded":str(d.get("foundedYear","")),
                "cb_linkedin":d.get("linkedin",{}).get("handle",""),
                "cb_twitter":d.get("twitter",{}).get("handle",""),
                "cb_phone":d.get("phone",""),
                "cb_location":d.get("location",""),
                "cb_country":d.get("geo",{}).get("country",""),
                "cb_city":d.get("geo",{}).get("city",""),
                "cb_type":d.get("type",""),
            }
            debug.append({"step":"Clearbit","status":"ok","msg":f"Company: {result['cb_name']}"})
            return result
        debug.append({"step":"Clearbit","status":"fail","msg":f"HTTP {r.status_code}"})
        return {}
    except Exception as e:
        debug.append({"step":"Clearbit","status":"fail","msg":str(e)[:60]})
        return {}

# ════════════════════════════════════════════════════════
# MAIN SCRAPER
# ════════════════════════════════════════════════════════
def run_full_scan(url):
    start_time=time.time()
    debug=[]
    parsed=urlparse(url)
    domain=parsed.netloc.replace("www.","") or url.replace("https://","").replace("http://","").split("/")[0]
    base_url=f"{parsed.scheme}://{parsed.netloc}"

    result={
        "url":url,"domain":domain,"scan_time":datetime.now().strftime("%d %b %Y %H:%M:%S"),
        # identity
        "website_name":"Not Found","owner_name":"Not Found",
        "description":"Not Found","category":"Not Found",
        # contact
        "emails":[],"phones":[],"address":"Not Found",
        # enrichment
        "social":[],"tech_stack":[],"competitors":[],
        "summary":"Not Found",
        # WHOIS
        "whois_source":"Not Found","registrar":"Not Found",
        "registrar_url":"Not Found","creation_date":"Not Found",
        "expiration_date":"Not Found","updated_date":"Not Found",
        "domain_status":"Not Found","organization":"Not Found",
        "country":"Not Found","state":"Not Found","city":"Not Found",
        "registrant_email":"Not Found","name_servers":"Not Found",
        "dnssec":"Not Found","domain_age_days":"Not Found",
        # server
        "ip_address":"Not Found","server_location":"Not Found",
        "isp":"Not Found","timezone":"Not Found",
        # SSL
        "ssl_issuer":"Not Found","ssl_valid_from":"Not Found",
        "ssl_valid_to":"Not Found","ssl_version":"Not Found",
        # Clearbit enrichment
        "cb_name":"","cb_description":"","cb_industry":"",
        "cb_employees":"","cb_revenue":"","cb_founded":"",
        "cb_linkedin":"","cb_twitter":"","cb_phone":"","cb_location":"",
        "cb_country":"","cb_city":"","cb_type":"",
        # meta
        "fetch_method":"Not Found","debug":debug,"scan_duration":"",
    }

    # ── STEP 1: Fetch Page ────────────────────────────────────────
    debug.append({"step":"Scan Started","status":"ok","msg":f"Target: {url}"})
    html=selenium_fetch(url,debug)
    if html:
        result["fetch_method"]="Selenium Chrome (Real Browser)"
    else:
        html=http_fetch(url,debug)
        result["fetch_method"]="HTTP Request"

    if html:
        soup=BeautifulSoup(html,"html.parser")
        page_text=soup.get_text(" ")

        # ── STEP 2: Basic Info ────────────────────────────────────
        result["website_name"]=extract_name(soup)
        result["description"] =extract_description(soup)
        result["tech_stack"]  =extract_tech_stack(soup,html)
        result["category"]    =detect_category(soup,page_text,domain)
        debug.append({"step":"Page Analysis","status":"ok",
                      "msg":f"Name: {result['website_name']} | Category: {result['category']} | Tech: {len(result['tech_stack'])} detected"})

        # ── STEP 3: Contact Extraction ────────────────────────────
        emails=extract_emails(html,soup,debug)
        phones=extract_phones(soup,page_text,debug)
        address=extract_address(soup,page_text,debug)
        owner  =extract_owner(soup,debug)
        result.update({"emails":emails,"phones":phones,"address":address,"owner_name":owner})

        # ── STEP 4: Sub-page crawl ────────────────────────────────
        debug.append({"step":"Sub-page Crawl","status":"running","msg":"Scanning contact/about/support pages..."})
        crawled=0
        for path in ["/contact","/contact-us","/about","/about-us","/support","/reach-us","/help","/offices"]:
            if crawled>=6: break
            if len(emails)>=4 and phones and address!="Not Found": break
            sub_html=fetch_subpage(base_url,path,debug)
            if not sub_html: continue
            crawled+=1
            s2=BeautifulSoup(sub_html,"html.parser")
            t2=s2.get_text(" ")
            for e in extract_emails(sub_html,s2,[]):
                if e not in emails: emails.append(e)
            if address=="Not Found":
                address=extract_address(s2,t2,[])
                if address!="Not Found": debug.append({"step":"Sub-page","status":"ok","msg":f"Address found on {path}"})
            if owner=="Not Found":
                owner=extract_owner(s2,[])
                if owner!="Not Found": debug.append({"step":"Sub-page","status":"ok","msg":f"Owner found on {path}"})
            p2=extract_phones(s2,t2,[])
            seen_ph={re.sub(r"\D","",p) for p in phones}
            for p in p2:
                if re.sub(r"\D","",p) not in seen_ph:
                    phones.append(p); seen_ph.add(re.sub(r"\D","",p))
        result.update({"emails":emails[:10],"phones":phones[:6],"address":address,"owner_name":owner})
        debug.append({"step":"Sub-page Crawl","status":"ok","msg":f"Scanned {crawled} sub-pages"})

        # ── STEP 5: Social Links ──────────────────────────────────
        result["social"]=extract_social(soup,base_url)

    else:
        debug.append({"step":"Page Fetch","status":"fail","msg":"Could not load page — WHOIS scan will continue"})

    # ── STEP 6: WHOIS (all 3 sources) ─────────────────────────────
    debug.append({"step":"WHOIS Engine","status":"running","msg":"Trying all WHOIS sources..."})
    whois=whois_xmlapi(domain,debug) or whois_rdap(domain,debug) or whois_system(domain,debug)
    if whois:
        result.update({
            "whois_source":    whois.get("source","Not Found"),
            "registrar":       whois.get("registrar","Not Found"),
            "registrar_url":   whois.get("registrar_url","Not Found"),
            "creation_date":   whois.get("creation_date","Not Found"),
            "expiration_date": whois.get("expiration_date","Not Found"),
            "updated_date":    whois.get("updated_date","Not Found"),
            "domain_status":   whois.get("domain_status","Not Found"),
            "organization":    whois.get("organization","Not Found"),
            "country":         whois.get("country","Not Found"),
            "state":           whois.get("state","Not Found"),
            "city":            whois.get("city","Not Found"),
            "registrant_email":whois.get("registrant_email","Not Found"),
            "name_servers":    whois.get("name_servers","Not Found"),
            "dnssec":          whois.get("dnssec","Not Found"),
            "domain_age_days": whois.get("domain_age_days","Not Found"),
        })
        if result["owner_name"]=="Not Found":
            wn=whois.get("owner_name","Not Found")
            if wn not in ("Not Found","REDACTED FOR PRIVACY","Data Protected",""):
                result["owner_name"]=wn
        if result["organization"]!="Not Found" and result["organization"]:
            result["website_name"]=result["website_name"] if result["website_name"]!="Not Found" else result["organization"]

    # ── STEP 7: IP/DNS ────────────────────────────────────────────
    ip_info=get_ip_info(domain,debug)
    result.update(ip_info)

    # ── STEP 8: SSL ───────────────────────────────────────────────
    ssl_info=get_ssl_info(domain,debug)
    result.update(ssl_info)

    # ── STEP 9: Hunter.io ─────────────────────────────────────────
    hunter_emails=hunter_email_finder(domain,debug)
    for e in hunter_emails:
        if e not in result["emails"]:
            result["emails"].append(e)
    result["emails"]=result["emails"][:10]

    # ── STEP 10: Clearbit ─────────────────────────────────────────
    cb=clearbit_enrich(domain,debug)
    result.update(cb)
    if cb.get("cb_phone") and not result["phones"]:
        result["phones"]=[cb["cb_phone"]]

    # ── STEP 11: Competitors & Summary ───────────────────────────
    result["competitors"]=find_competitors(domain,result["category"])
    result["summary"]    =generate_summary(result)

    result["scan_duration"]=f"{time.time()-start_time:.1f}s"
    debug.append({"step":"Scan Complete","status":"ok",
                  "msg":f"Done in {result['scan_duration']} — {len(result['emails'])} emails, {len(result['phones'])} phones, {len(result['social'])} social"})
    return result

# ════════════════════════════════════════════════════════
# FLASK ROUTES
# ════════════════════════════════════════════════════════

@app.route("/login", methods=["GET","POST"])
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        action = request.form.get("action", "login")
        u = request.form.get("username","").strip().lower()
        p = request.form.get("password","").strip()

        if action == "register":
            # Sign Up
            cp = request.form.get("confirm_password","").strip()
            if p != cp:
                error = "Passwords do not match"
            else:
                ok, msg = register_user(u, p)
                if ok:
                    session["logged_in"]  = True
                    session["username"]   = u
                    session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    session["role"]       = "User"
                    session.permanent     = True
                    return redirect(url_for("index"))
                else:
                    error = msg
        else:
            # Sign In
            ok, result = verify_user(u, p)
            if ok:
                session["logged_in"]  = True
                session["username"]   = u
                session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                session["role"]       = result.get("role", "User")
                session.permanent     = True
                return redirect(url_for("index"))
            else:
                error = result

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/")
@login_required
def index():
    se = "✅ Active" if SELENIUM_OK else "❌ Not installed"
    user_info = get_user_info(session.get("username",""))
    return render_template("index.html",
                           username=session.get("username",""),
                           role=session.get("role","User"),
                           se_status=se,
                           user_info=user_info)

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.json or {}
    url  = data.get("url","").strip()
    if not url: return jsonify({"error":"No URL"}),400
    if not url.startswith(("http://","https://")): url="https://"+url
    result = run_full_scan(url)
    username = session.get("username","")
    save_history({
        "url":          url,
        "domain":       result.get("domain",""),
        "website_name": result.get("website_name",""),
        "category":     result.get("category",""),
        "scan_time":    result.get("scan_time",""),
        "username":     username,
        "emails_found": len(result.get("emails",[])),
        "phones_found": len(result.get("phones",[])),
        "country":      result.get("country",""),
        "registrar":    result.get("registrar",""),
        "scan_duration":result.get("scan_duration",""),
        "ip_address":   result.get("ip_address",""),
    })
    update_scan_count(username)
    return jsonify(result)

@app.route("/history")
@login_required
def history():
    # Each user sees ONLY their own history
    username = session.get("username","")
    return jsonify(load_history(username))

@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    """Clear only current user's history"""
    username = session.get("username","")
    try:
        if os.path.exists(HISTORY_FILE):
            all_h = json.load(open(HISTORY_FILE))
            # Keep other users' history, remove only this user's
            filtered = [h for h in all_h if h.get("username") != username]
            json.dump(filtered, open(HISTORY_FILE,"w"), indent=2)
    except: pass
    return jsonify({"ok":True})

@app.route("/history/delete", methods=["POST"])
@login_required
def delete_history_item():
    data = request.json or {}
    url_to_del = data.get("url","")
    username = session.get("username","")
    try:
        if os.path.exists(HISTORY_FILE):
            all_h = json.load(open(HISTORY_FILE))
            # Only delete if it belongs to this user
            all_h = [h for h in all_h if not (h.get("url")==url_to_del and h.get("username")==username)]
            json.dump(all_h, open(HISTORY_FILE,"w"), indent=2)
    except: pass
    return jsonify({"ok":True})

@app.route("/api/users", methods=["GET"])
@login_required
def api_users():
    """Admin only: list all users"""
    if session.get("role") != "Admin":
        return jsonify({"error":"Admin only"}), 403
    users = load_users()
    # Don't send password hashes
    safe = {u: {k:v for k,v in data.items() if k!="password"} for u,data in users.items()}
    return jsonify(safe)

@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    data = request.json or {}
    old_p = data.get("old_password","").strip()
    new_p = data.get("new_password","").strip()
    username = session.get("username","")
    ok, result = verify_user(username, old_p)
    if not ok:
        return jsonify({"ok":False, "error":"Current password incorrect"})
    if len(new_p) < 6:
        return jsonify({"ok":False, "error":"New password must be 6+ characters"})
    users = load_users()
    users[username]["password"] = hash_password(new_p)
    save_users(users)
    return jsonify({"ok":True, "msg":"Password changed successfully"})

@app.route("/api/me")
@login_required
def api_me():
    username = session.get("username","")
    user_info = get_user_info(username)
    history_count = len(load_history(username))
    return jsonify({
        "username": username,
        "role": session.get("role","User"),
        "scan_count": user_info.get("scan_count",0),
        "last_login": user_info.get("last_login","Never"),
        "created": user_info.get("created",""),
        "history_count": history_count,
        "session_since": session.get("login_time",""),
    })

if __name__=="__main__":
    print("="*60)
    print("  NEXUS — Professional Business Intelligence Scraper")
    print("  Open → http://localhost:5000")
    print(f"  Login: admin/admin123 | user1/pass1234 | analyst/analyst2024")
    print(f"  Selenium: {'✅' if SELENIUM_OK else '❌ pip install selenium webdriver-manager'}")
    print("="*60)
    app.run(debug=False,port=5000,threaded=True)