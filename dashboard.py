import os
import time
import re
import asyncio
from urllib.parse import urlparse
import ipaddress
from dotenv import load_dotenv
import httpx
import bcrypt
from nicegui import app, ui
import mysql.connector
from mysql.connector import pooling
from google import genai

load_dotenv()

# --- THEME COLORS ---
PRIMARY = "#10b981"      # Cyber Emerald
PRIMARY_HOVER = "#059669"
BG_DARK = "#090d16"      # Deep canvas
CARD_BG = "#111827"      # Slate card
CARD_BORDER = "#1f293d"  # Subtle border
TEXT_MUTED = "#94a3b8"   # Slate 400

# --- GEMINI CLIENT ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# --- DATABASE CONNECTION POOL ---
_db_pool = None

def get_db_pool():
    global _db_pool
    if _db_pool is None:
        try:
            _db_pool = pooling.MySQLConnectionPool(
                pool_name="phish_detector_pool",
                pool_size=5,
                pool_reset_session=True,
                host="gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
                port=4000,
                user="2axaGUcuFZV4H9Q.root",
                password=os.environ.get("DB_PASSWORD"),
                database="test"
            )
        except Exception as e:
            print("DB Pool init error:", repr(e))
            return None
    return _db_pool

def get_db_connection():
    conn = None
    pool = get_db_pool()
    if pool:
        try:
            conn = pool.get_connection()
        except Exception as e:
            print("Failed to get connection from pool:", repr(e))
    if not conn:
        conn = mysql.connector.connect(
            host="gateway01.ap-southeast-1.prod.aws.tidbcloud.com",
            port=4000,
            user="2axaGUcuFZV4H9Q.root",
            password=os.environ.get("DB_PASSWORD"),
            database="test"
        )
    try:
        cur = conn.cursor()
        cur.execute("SET time_zone = '+05:30'")
        cur.close()
    except Exception as e:
        print("Set time_zone error:", repr(e))
    return conn

def _insert_security_check_sync(target, check_type, result, breach_count):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_checks (email, check_type, result, breach_count)
            VALUES (%s, %s, %s, %s)
            """,
            (target, check_type, result, breach_count)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving {check_type} check:", repr(e))
        return False

def _fetch_recent_checks_sync():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT email, check_type, result, breach_count, checked_at
            FROM security_checks
            ORDER BY checked_at DESC
            LIMIT 10
            """
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print("Error fetching recent checks:", repr(e))
        return []

def _clear_security_checks_sync():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_checks")
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print("Error clearing security checks:", repr(e))
        return False


# --- PASSWORD UTILITIES ---
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed_password):
    try:
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    except Exception:
        return False

def valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True


# --- CURRENT USER RETRIEVAL ---
def get_current_user_info():
    try:
        user_id = app.storage.user.get('user_id')
    except Exception:
        user_id = None

    if user_id:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, password, create_at, last_login FROM users WHERE id = %s",
                (user_id,)
            )
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if row:
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password': row[3],
                    'created_at': row[4],
                    'last_login': str(row[5]) if row[5] else "Just now"
                }
        except Exception as e:
            print("Error retrieving session user:", repr(e))

    # Fallback to the latest user in database if session not set
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, password, create_at, last_login FROM users ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            return {
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'password': row[3],
                'created_at': row[4],
                'last_login': str(row[5]) if row[5] else "Just now"
            }
    except Exception as e:
        print("Error in fallback user retrieval:", repr(e))

    return {
        'id': 60001,
        'username': 'Vaiz',
        'email': 'shaikhv750@gmail.com',
        'password': '',
        'created_at': '2026-08-11',
        'last_login': time.strftime("%Y-%m-%d %H:%M:%S")
    }

def get_user_initials(username, email):
    if username and " " in username.strip():
        parts = username.strip().split()
        return (parts[0][0] + parts[1][0]).upper()
    if username and email and "@" in email:
        email_prefix = email.split("@")[0].lower()
        if email_prefix.startswith("shaikh") or "shaikh" in email_prefix:
            return (username[0] + "S").upper()
    if username and len(username) >= 2:
        return username[:2].upper()
    return "VS"


# --- AI EXPLANATION ENGINES (ASYNC & HIGH SPEED) ---
async def get_ai_url_explanation(url, score, reasons_text):
    if not client:
        return "AI analysis unavailable (API key not configured)."

    prompt = f"""
You are a top-tier cybersecurity intelligence specialist for an enterprise Phishing & Threat Detector.

Analyze this URL security scan result.

URL: {url}
Risk Score: {score}/100
Detected Findings:
{reasons_text}

Risk Categories:
0-20 = SAFE
21-50 = SUSPICIOUS
51-100 = HIGH RISK

Strict Requirements:
- The classification MUST match the risk score: 0-20 SAFE, 21-50 SUSPICIOUS, 51-100 HIGH RISK.
- Explain specifically why this URL received this risk score based on the detected indicators.
- Provide practical, high-value defensive actions for the user.

Format your response in clean Markdown with exactly these 3 sections:

### 🛡️ CLASSIFICATION
State either **SAFE**, **SUSPICIOUS**, or **HIGH RISK** with a 1-sentence executive verdict.

### 🔍 THREAT ANALYSIS
Detail the specific indicators, attack risks (e.g. credential harvesting, homograph spoofing, insecure transport), and domain integrity.

### 💡 RECOMMENDED ACTIONS
List 3 clear, actionable safety steps the user should immediately take.
"""
    for attempt in range(2):
        try:
            response = await client.aio.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=prompt
            )
            return response.text
        except Exception as e:
            print(f"Gemini URL attempt {attempt + 1} failed:", repr(e))
            if attempt == 0:
                await asyncio.sleep(1)
            else:
                return "AI explanation is temporarily unavailable. Please try again."

    return "AI explanation is currently unavailable."


async def get_ai_email_explanation(email, count, breaches):
    if not client:
        return "AI analysis unavailable (API key not configured)."

    breach_list = ", ".join(breaches[:15])

    prompt = f"""
You are a cybersecurity intelligence specialist.

An email address was detected in {count} known public data breaches.
Affected services: {breach_list}

Analyze the exposure risk and provide clear defensive mitigation.

Format your response in clean Markdown with exactly these 2 sections:

### ⚠️ BREACH IMPACT ANALYSIS
Explain why this email's appearance in these specific data breaches poses a risk (e.g., credential stuffing, phishing targeting, identity correlation).

### 🔒 IMMEDIATE DEFENSE STEPS
Provide 3-4 concrete steps to secure accounts, rotate compromised passwords, enable multi-factor authentication (MFA), and audit credentials.
"""
    for attempt in range(2):
        try:
            response = await client.aio.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=prompt
            )
            return response.text
        except Exception as e:
            print(f"Gemini email attempt {attempt + 1} failed:", repr(e))
            if attempt == 0:
                await asyncio.sleep(1)
            else:
                return "AI explanation is temporarily unavailable. Please try again."

    return "AI explanation is currently unavailable."


# --- HEURISTIC URL DETECTOR ---
def analyze_url(url):
    if not url:
        return {"error": "Please enter a URL to inspect."}

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc or "." not in parsed.netloc:
            return {"error": "Please enter a valid URL with a valid domain name."}

        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        score = 0
        reasons = []

        # 1. IP address check
        try:
            ipaddress.ip_address(parsed.hostname)
            score += 25
            reasons.append("The website uses a raw IP address instead of a verified domain name.")
        except (ValueError, TypeError):
            pass

        # 2. HTTP Protocol check
        if parsed.scheme == "http":
            score += 20
            reasons.append("Insecure HTTP protocol detected (traffic is unencrypted).")

        # 3. Suspicious words check
        suspicious_words = [
            "login", "verify", "verification", "secure", "account",
            "update", "confirm", "password", "bank", "payment"
        ]
        found_words = [w for w in suspicious_words if w in domain or w in path]
        if found_words:
            score += min(len(found_words) * 10, 30)
            reasons.append(f"Suspicious credential/security keywords detected: {', '.join(found_words)}.")

        # 4. @ symbol
        if "@" in url:
            score += 25
            reasons.append("Contains '@' symbol, a common tactic used to disguise destination hosts.")

        # 5. Length check
        if len(url) > 100:
            score += 15
            reasons.append(f"Unusually long URL structure ({len(url)} characters).")

        score = min(score, 100)

        if score <= 20:
            category = "SAFE"
            level_color = "emerald"
        elif score <= 50:
            category = "SUSPICIOUS"
            level_color = "amber"
        else:
            category = "HIGH RISK"
            level_color = "rose"

        return {
            "url": url,
            "domain": domain,
            "score": score,
            "category": category,
            "level_color": level_color,
            "reasons": reasons,
            "error": None
        }
    except Exception as e:
        return {"error": f"Unable to analyze this URL: {str(e)}"}


# --- ASYNC EMAIL BREACH CHECKER ---
async def check_email_async(email):
    if not email:
        return {"found": False, "message": "Please enter an email address."}

    email = email.strip()
    if "@" not in email or "." not in email.split("@")[-1]:
        return {"found": False, "message": "Please enter a valid email address format."}

    url = f"https://api.xposedornot.com/v1/check-email/{email}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            response = await http_client.get(url)

            if response.status_code == 200:
                data = response.json()
                if "breaches" in data and data["breaches"]:
                    breaches = data["breaches"][0]
                    return {
                        "found": True,
                        "count": len(breaches),
                        "breaches": breaches,
                        "message": None
                    }
                return {
                    "found": False,
                    "count": 0,
                    "breaches": [],
                    "message": "No known public breach records found for this identity."
                }
            elif response.status_code == 404:
                return {
                    "found": False,
                    "count": 0,
                    "breaches": [],
                    "message": "No known public breach records found for this identity."
                }
            elif response.status_code == 429:
                return {
                    "found": False,
                    "count": 0,
                    "breaches": [],
                    "message": "Rate limit reached on breach intelligence provider. Try again shortly."
                }
            else:
                return {
                    "found": False,
                    "count": 0,
                    "breaches": [],
                    "message": f"Breach database returned HTTP {response.status_code}."
                }
    except Exception as e:
        print("Email breach check error:", repr(e))
        return {
            "found": False,
            "count": 0,
            "breaches": [],
            "message": "Unable to connect to breach intelligence database."
        }


def setup_theme_styles():
    ui.add_head_html("""
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
                background-color: #090d16 !important;
                color: #f1f5f9;
                margin: 0;
            }
            .mono-text {
                font-family: 'JetBrains Mono', monospace !important;
            }
            .cyber-card {
                background: #111827;
                border: 1px solid #1f293d;
                border-radius: 16px;
                box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
                transition: border-color 0.2s ease, box-shadow 0.2s ease;
            }
            .cyber-card:hover {
                border-color: #2e3d5b;
            }
            .q-field--outlined .q-field__control {
                background-color: #0d1322 !important;
                border-radius: 10px !important;
            }
            .q-field--outlined .q-field__control:hover {
                border-color: #10b981 !important;
            }
            .ai-markdown h3 {
                font-size: 1.05rem;
                font-weight: 700;
                margin-top: 0.85rem;
                margin-bottom: 0.35rem;
                color: #38bdf8;
            }
            .ai-markdown p {
                margin-bottom: 0.5rem;
                color: #cbd5e1;
                font-size: 0.925rem;
                line-height: 1.5;
            }
            .ai-markdown ul {
                margin-top: 0.25rem;
                margin-bottom: 0.5rem;
                padding-left: 1.25rem;
                color: #cbd5e1;
                font-size: 0.925rem;
            }
            .ai-markdown li {
                margin-bottom: 0.25rem;
            }
            .ai-markdown strong {
                color: #f8fafc;
            }
        </style>
    """)


# ==============================================================================
# DASHBOARD PAGE
# ==============================================================================
@ui.page("/dashboard")
def dashboard():
    setup_theme_styles()

    user = get_current_user_info()
    initials = get_user_initials(user.get("username", "Vaiz"), user.get("email", "shaikhv750@gmail.com"))

    # --------------------------------------------------------------------------
    # TOP NAVBAR
    # --------------------------------------------------------------------------
    with ui.header().classes(
        "w-full px-6 py-3 items-center justify-between"
    ).style(
        "background-color: #0b0f19; border-bottom: 1px solid #1e293b; z-index: 50;"
    ):
        with ui.row().classes("items-center gap-3"):
            ui.icon("security", size="28px").style("color: #10b981;")
            with ui.column().classes("gap-0"):
                ui.label("AI PHISHING DETECTOR").classes("font-bold tracking-wider text-base text-white")
                ui.label("Threat Intelligence & Breach Radar").classes("text-xs text-slate-400")

        with ui.row().classes("items-center gap-4"):
            with ui.row().classes(
                "items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold"
            ).style("background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399;"):
                ui.element("span").classes("w-2 h-2 rounded-full bg-emerald-400 animate-pulse")
                ui.label("Threat Radar Active")

            # Avatar Circle with Initials, Red Notification Dot, and Dropdown Menu
            with ui.row().classes("items-center gap-1.5 cursor-pointer"):
                with ui.element("div").classes("relative"):
                    with ui.element("div").classes(
                        "w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-white tracking-wider"
                    ):
                        ui.label(initials)
                    # Red notification dot on avatar
                    ui.element("span").classes(
                        "absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-rose-500 border-2 border-[#0b0f19]"
                    )
                ui.icon("expand_more", size="18px").classes("text-slate-400")

                # Dropdown menu with the exact 3 options (Notification Settings removed!)
                with ui.menu().classes("bg-[#111827] border border-slate-800 rounded-xl p-1.5 shadow-2xl"):
                    with ui.menu_item(on_click=lambda: ui.navigate.to("/account?tab=profile")).classes("hover:bg-slate-800 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-slate-200"):
                            ui.icon("person", size="16px").classes("text-emerald-400")
                            ui.label("Profile Information")
                            ui.element("span").classes("w-1.5 h-1.5 rounded-full bg-rose-500 ml-auto")

                    with ui.menu_item(on_click=lambda: ui.navigate.to("/account/change-password")).classes("hover:bg-slate-800 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-slate-200"):
                            ui.icon("lock", size="16px").classes("text-cyan-400")
                            ui.label("Security & Privacy")

                    ui.separator().classes("bg-slate-800 my-1")

                    with ui.menu_item(on_click=lambda: ui.navigate.to("/login")).classes("hover:bg-rose-500/10 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-rose-400"):
                            ui.icon("logout", size="16px")
                            ui.label("Logout")

    # --------------------------------------------------------------------------
    # MAIN CONTENT CONTAINER
    # --------------------------------------------------------------------------
    with ui.column().classes("w-full max-w-7xl mx-auto px-4 py-6 items-center gap-6"):

        # ----------------------------------------------------------------------
        # TWO PRIMARY SCANNER MODULES
        # ----------------------------------------------------------------------
        with ui.row().classes("w-full justify-center items-start gap-6"):

            # ==================================================================
            # MODULE 1: URL THREAT INSPECTOR
            # ==================================================================
            with ui.card().classes("cyber-card w-full lg:w-[580px] p-6 flex flex-col gap-4"):
                # Header
                with ui.row().classes("w-full items-center justify-between pb-3 border-b border-slate-800"):
                    with ui.row().classes("items-center gap-3"):
                        with ui.element("div").classes(
                            "w-10 h-10 rounded-xl flex items-center justify-center bg-emerald-500/10 border border-emerald-500/20 text-emerald-400"
                        ):
                            ui.icon("link", size="22px")
                        with ui.column().classes("gap-0"):
                            ui.label("URL Threat Inspector").classes("text-lg font-bold text-white")
                            ui.label("Heuristic & Deep AI Domain Verification").classes("text-xs text-slate-400")

                    ui.badge("Live Scan", color="emerald").props("outline").classes("text-xs font-semibold")

                ui.label(
                    "Inspect unknown URLs, shortenings, or suspicious emails links for phishing traits."
                ).classes("text-xs text-slate-400 -mt-1")

                # Input Field
                url_input = ui.input(
                    placeholder="Enter URL to inspect (e.g. https://secure-login-account.com)"
                ).props(
                    'outlined clearable dark dense'
                ).classes("w-full text-sm")

                # Action Button
                analyze_btn = ui.button(
                    "INSPECT URL SECURITY",
                    icon="shield",
                    color="primary"
                ).classes(
                    "w-full py-2.5 font-bold tracking-wide rounded-xl shadow-lg transition-all"
                ).style("background-color: #10b981 !important; color: #022c22;")

                # Output Containers
                url_result_container = ui.column().classes("w-full gap-3")
                ai_url_container = ui.column().classes("w-full gap-3")

                # Clear functionality
                def clear_url_inspector():
                    url_input.value = ""
                    url_result_container.clear()
                    ai_url_container.clear()

                url_input.on("clear", clear_url_inspector)

                def on_url_input_change(e):
                    if not e.value or not e.value.strip():
                        url_result_container.clear()
                        ai_url_container.clear()

                url_input.on_value_change(on_url_input_change)

                async def handle_url_analysis():
                    raw_val = (url_input.value or "").strip()
                    if not raw_val:
                        ui.notify("Please enter a URL to inspect", type="warning", position="top")
                        return

                    analyze_btn.disable()
                    analyze_btn.set_text("Scanning Domain...")
                    url_result_container.clear()
                    ai_url_container.clear()

                    try:
                        result = analyze_url(raw_val)

                        if result.get("error"):
                            with url_result_container:
                                with ui.row().classes("w-full p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 items-center gap-2"):
                                    ui.icon("error", size="20px")
                                    ui.label(result["error"]).classes("text-xs font-semibold")
                            return

                        score = result["score"]
                        category = result["category"]
                        reasons = result["reasons"]
                        target_url = result["url"]

                        if category == "SAFE":
                            badge_bg = "rgba(16, 185, 129, 0.15)"
                            badge_border = "rgba(16, 185, 129, 0.4)"
                            badge_text = "#34d399"
                            bar_color = "#10b981"
                            status_icon = "check_circle"
                        elif category == "SUSPICIOUS":
                            badge_bg = "rgba(245, 158, 11, 0.15)"
                            badge_border = "rgba(245, 158, 11, 0.4)"
                            badge_text = "#fbbf24"
                            bar_color = "#f59e0b"
                            status_icon = "warning"
                        else:
                            badge_bg = "rgba(244, 63, 94, 0.15)"
                            badge_border = "rgba(244, 63, 94, 0.4)"
                            badge_text = "#fb7185"
                            bar_color = "#f43f5e"
                            status_icon = "dangerous"

                        with url_result_container:
                            with ui.column().classes("w-full p-4 rounded-xl bg-slate-900/90 border border-slate-800 gap-3"):
                                with ui.row().classes("w-full items-center justify-between"):
                                    with ui.row().classes("items-center gap-2"):
                                        ui.icon(status_icon, size="24px").style(f"color: {badge_text};")
                                        ui.label(f"{category} THREAT LEVEL").classes("font-extrabold text-sm tracking-wide").style(f"color: {badge_text};")

                                    with ui.row().classes(
                                        "px-2.5 py-0.5 rounded-full text-xs font-bold mono-text"
                                    ).style(f"background: {badge_bg}; border: 1px solid {badge_border}; color: {badge_text};"):
                                        ui.label(f"Risk Score: {score}/100")

                                with ui.column().classes("w-full gap-1"):
                                    with ui.row().classes("w-full justify-between text-[11px] text-slate-400"):
                                        ui.label("Threat Gauge")
                                        ui.label(f"{score}% Potential Risk")
                                    ui.linear_progress(value=score / 100.0, show_value=False).props(
                                        f"color={'positive' if score <= 20 else 'warning' if score <= 50 else 'negative'} rounded"
                                    ).classes("h-2 rounded-full")

                                if reasons:
                                    ui.separator().classes("bg-slate-800 my-1")
                                    ui.label("DETECTED INDICATORS:").classes("text-[11px] font-bold text-slate-400 tracking-wider uppercase")
                                    for r in reasons:
                                        with ui.row().classes("items-start gap-2 text-xs text-slate-300"):
                                            ui.icon("flag", size="16px").style(f"color: {badge_text};")
                                            ui.label(r).classes("flex-1 leading-tight")
                                else:
                                    with ui.row().classes("items-center gap-2 text-xs text-emerald-400"):
                                        ui.icon("verified", size="16px")
                                        ui.label("Clean domain structure. No immediate signature anomalies detected.")

                        asyncio.create_task(save_and_refresh_history(
                            target_url,
                            "URL",
                            "Safe" if score <= 20 else "Suspicious" if score <= 50 else "High Risk",
                            score
                        ))

                        with ai_url_container:
                            loading_row = ui.row().classes("w-full p-4 rounded-xl bg-slate-900/60 border border-slate-800 items-center justify-center gap-3 text-slate-400")
                            with loading_row:
                                ui.spinner("dots", size="24px", color="primary")
                                ui.label("Gemini AI analyzing threat heuristics & attack vectors...").classes("text-xs font-medium text-emerald-400")

                        reasons_str = "\n".join(reasons) if reasons else "No basic indicators detected."
                        ai_text = await get_ai_url_explanation(target_url, score, reasons_str)

                        ai_url_container.clear()
                        with ai_url_container:
                            with ui.column().classes("w-full p-4 rounded-xl bg-slate-900/90 border border-emerald-500/20 gap-2"):
                                with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-800"):
                                    with ui.row().classes("items-center gap-2"):
                                        ui.icon("auto_awesome", size="18px").classes("text-emerald-400")
                                        ui.label("AI CYBERSECURITY ADVISORY").classes("text-xs font-bold text-emerald-300 tracking-wider")
                                    ui.badge("Gemini 3.5 Flash", color="emerald").props("outline dense").classes("text-[10px]")

                                ui.markdown(ai_text).classes("ai-markdown w-full text-xs")

                    finally:
                        analyze_btn.enable()
                        analyze_btn.set_text("INSPECT URL SECURITY")

                analyze_btn.on("click", handle_url_analysis)

            # ==================================================================
            # MODULE 2: EMAIL DATA BREACH RADAR
            # ==================================================================
            with ui.card().classes("cyber-card w-full lg:w-[580px] p-6 flex flex-col gap-4"):
                # Header
                with ui.row().classes("w-full items-center justify-between pb-3 border-b border-slate-800"):
                    with ui.row().classes("items-center gap-3"):
                        with ui.element("div").classes(
                            "w-10 h-10 rounded-xl flex items-center justify-center bg-cyan-500/10 border border-cyan-500/20 text-cyan-400"
                        ):
                            ui.icon("mark_email_unread", size="22px")
                        with ui.column().classes("gap-0"):
                            ui.label("Email Data Breach Radar").classes("text-lg font-bold text-white")
                            ui.label("Compromised Identity & Credential Audit").classes("text-xs text-slate-400")

                    ui.badge("Global Intelligence", color="cyan").props("outline").classes("text-xs font-semibold")

                ui.label(
                    "Scan known global breach dumps and leak repositories for compromised accounts."
                ).classes("text-xs text-slate-400 -mt-1")

                # Input Field
                email_input = ui.input(
                    placeholder="Enter email address (e.g. user@example.com)"
                ).props(
                    'outlined clearable dark dense'
                ).classes("w-full text-sm")

                # Action Button
                check_email_btn = ui.button(
                    "SCAN FOR DATA BREACHES",
                    icon="search",
                    color="primary"
                ).classes(
                    "w-full py-2.5 font-bold tracking-wide rounded-xl shadow-lg transition-all"
                ).style("background-color: #06b6d4 !important; color: #082f49;")

                # Output Containers
                email_result_container = ui.column().classes("w-full gap-3")
                ai_email_container = ui.column().classes("w-full gap-3")

                def clear_email_inspector():
                    email_input.value = ""
                    email_result_container.clear()
                    ai_email_container.clear()

                email_input.on("clear", clear_email_inspector)

                def on_email_input_change(e):
                    if not e.value or not e.value.strip():
                        email_result_container.clear()
                        ai_email_container.clear()

                email_input.on_value_change(on_email_input_change)

                def open_breach_dialog(breaches):
                    with ui.dialog() as dialog, ui.card().classes(
                        "cyber-card p-6 w-[600px] max-w-[92vw] max-h-[85vh] flex flex-col gap-4"
                    ):
                        with ui.row().classes("w-full items-center justify-between pb-3 border-b border-slate-800"):
                            with ui.row().classes("items-center gap-2"):
                                ui.icon("warning", size="22px").classes("text-rose-400")
                                ui.label("Comprehensive Breach Catalog").classes("text-base font-bold text-white")
                            ui.badge(f"{len(breaches)} Sources", color="rose").classes("text-xs font-bold")

                        ui.label(
                            "These services experienced verified data breaches containing records tied to this email:"
                        ).classes("text-xs text-slate-400")

                        with ui.scroll_area().classes("h-[400px] w-full pr-2"):
                            with ui.column().classes("w-full gap-2"):
                                for i, breach in enumerate(breaches, 1):
                                    with ui.row().classes(
                                        "w-full items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs"
                                    ):
                                        with ui.row().classes("items-center gap-2"):
                                            ui.label(f"{i}.").classes("text-slate-500 font-mono")
                                            ui.label(breach).classes("font-semibold text-slate-200")
                                        ui.badge("Compromised", color="negative").props("outline dense").classes("text-[10px]")

                        with ui.row().classes("w-full justify-end pt-2 border-t border-slate-800"):
                            ui.button("Close Catalog", on_click=dialog.close).props("outline").classes(
                                "text-slate-300 hover:text-white text-xs font-semibold px-4"
                            )
                    dialog.open()

                async def handle_email_analysis():
                    raw_email = (email_input.value or "").strip()
                    if not raw_email:
                        ui.notify("Please enter an email address to check", type="warning", position="top")
                        return

                    check_email_btn.disable()
                    check_email_btn.set_text("Checking Breach Databases...")
                    email_result_container.clear()
                    ai_email_container.clear()

                    try:
                        res = await check_email_async(raw_email)

                        if not res["found"]:
                            with email_result_container:
                                with ui.column().classes("w-full p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 gap-2"):
                                    with ui.row().classes("items-center gap-2 text-emerald-400"):
                                        ui.icon("check_circle", size="24px")
                                        ui.label("CLEAN IDENTITY RECORD").classes("font-bold text-sm tracking-wide")
                                    ui.label(
                                        res.get("message") or "This email address was not found in known public breach archives."
                                    ).classes("text-xs text-slate-300 leading-relaxed")

                            asyncio.create_task(save_and_refresh_history(raw_email, "Email", "Safe", 0))
                            return

                        count = res["count"]
                        breaches = res["breaches"]

                        asyncio.create_task(save_and_refresh_history(raw_email, "Email", "Breached", count))

                        with email_result_container:
                            with ui.column().classes("w-full p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 gap-3"):
                                with ui.row().classes("w-full items-center justify-between"):
                                    with ui.row().classes("items-center gap-2"):
                                        ui.icon("gpp_bad", size="24px").classes("text-rose-400")
                                        ui.label("BREACH DETECTED").classes("font-extrabold text-sm tracking-wide text-rose-400")

                                    with ui.row().classes(
                                        "px-2.5 py-0.5 rounded-full text-xs font-bold mono-text bg-rose-500/20 border border-rose-500/40 text-rose-300"
                                    ):
                                        ui.label(f"{count} Incidents Identified")

                                ui.label(
                                    "This email address was compromised in historical data breaches. "
                                    "Associated credentials, emails, or personal details were exposed publicly."
                                ).classes("text-xs text-slate-300 leading-relaxed")

                                with ui.column().classes("w-full gap-1.5"):
                                    ui.label("AFFECTED SERVICES:").classes("text-[11px] font-bold text-slate-400 tracking-wider")
                                    with ui.row().classes("w-full flex-wrap gap-1.5"):
                                        for b in breaches[:8]:
                                            ui.label(b).classes(
                                                "px-2.5 py-0.5 rounded-md bg-slate-900 border border-rose-500/30 text-rose-200 text-xs font-medium"
                                            )
                                        if count > 8:
                                            ui.label(f"+{count - 8} more").classes(
                                                "px-2 py-0.5 rounded-md bg-slate-800 text-slate-400 text-xs font-medium"
                                            )

                                ui.button(
                                    f"VIEW ALL {count} COMPROMISED PLATFORMS",
                                    icon="list",
                                    on_click=lambda: open_breach_dialog(breaches)
                                ).props("outline dense").classes(
                                    "w-full text-rose-400 hover:text-rose-300 border-rose-500/40 text-xs font-semibold py-1.5 mt-1"
                                )

                        with ai_email_container:
                            loading_row = ui.row().classes("w-full p-4 rounded-xl bg-slate-900/60 border border-slate-800 items-center justify-center gap-3 text-slate-400")
                            with loading_row:
                                ui.spinner("dots", size="24px", color="secondary")
                                ui.label("Gemini AI synthesizing breach impact & mitigation guidance...").classes("text-xs font-medium text-cyan-400")

                        ai_text = await get_ai_email_explanation(raw_email, count, breaches)

                        ai_email_container.clear()
                        with ai_email_container:
                            with ui.column().classes("w-full p-4 rounded-xl bg-slate-900/90 border border-cyan-500/20 gap-2"):
                                with ui.row().classes("w-full items-center justify-between pb-2 border-b border-slate-800"):
                                    with ui.row().classes("items-center gap-2"):
                                        ui.icon("auto_awesome", size="18px").classes("text-cyan-400")
                                        ui.label("AI REMEDIATION PLAN").classes("text-xs font-bold text-cyan-300 tracking-wider")
                                    ui.badge("Gemini 3.5 Flash", color="cyan").props("outline dense").classes("text-[10px]")

                                ui.markdown(ai_text).classes("ai-markdown w-full text-xs")

                    finally:
                        check_email_btn.enable()
                        check_email_btn.set_text("SCAN FOR DATA BREACHES")

                check_email_btn.on("click", handle_email_analysis)

        # ----------------------------------------------------------------------
        # MODULE 3: RECENT AUDIT LOG & SECURITY CHECKS
        # ----------------------------------------------------------------------
        with ui.column().classes("w-full max-w-5xl cyber-card p-6 gap-4"):
            with ui.row().classes("w-full items-center justify-between pb-3 border-b border-slate-800"):
                with ui.row().classes("items-center gap-3"):
                    with ui.element("div").classes(
                        "w-9 h-9 rounded-lg flex items-center justify-center bg-slate-800 border border-slate-700 text-slate-300"
                    ):
                        ui.icon("history", size="20px")
                    with ui.column().classes("gap-0"):
                        ui.label("Threat Intelligence Activity Log").classes("text-base font-bold text-white")
                        ui.label("Real-time telemetry and audit records stored securely in TiDB").classes("text-xs text-slate-400")

                clear_history_btn = ui.button("Clear Log", icon="delete_sweep").props(
                    "flat dense"
                ).classes("text-xs text-slate-400 hover:text-rose-400 font-semibold")

            recent_checks_container = ui.column().classes("w-full gap-2")

            async def refresh_recent_checks():
                recent_checks_container.clear()

                checks = await asyncio.to_thread(_fetch_recent_checks_sync)

                with recent_checks_container:
                    if not checks:
                        with ui.column().classes("w-full py-8 items-center justify-center gap-2 text-slate-500"):
                            ui.icon("inventory_2", size="32px").classes("opacity-50")
                            ui.label("No security checks recorded yet. Scan a URL or Email to begin.").classes("text-xs")
                        return

                    for row in checks:
                        target, check_type, result, breach_count, checked_at = row

                        date_str = str(checked_at)[:19] if checked_at else "Just now"

                        if result in ("Safe", "Clean"):
                            res_badge_color = "emerald"
                            res_text = f"Safe ({breach_count}/100)" if check_type == "URL" else "Safe"
                            res_icon = "check_circle"
                        elif result == "Suspicious":
                            res_badge_color = "amber"
                            res_text = f"Suspicious ({breach_count}/100)"
                            res_icon = "warning"
                        else:
                            res_badge_color = "rose"
                            res_text = f"High Risk ({breach_count}/100)" if check_type == "URL" else f"Breached ({breach_count})"
                            res_icon = "dangerous"

                        with ui.row().classes(
                            "w-full items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors gap-3"
                        ):
                            with ui.row().classes("items-center gap-3 flex-1 min-w-0"):
                                ui.icon(
                                    "link" if check_type == "URL" else "email",
                                    size="18px"
                                ).classes("text-slate-400")

                                with ui.column().classes("gap-0 min-w-0 flex-1"):
                                    ui.label(str(target)).classes("text-xs font-semibold text-slate-200 truncate font-mono")
                                    ui.label(f"{check_type} Verification • {date_str}").classes("text-[11px] text-slate-500")

                            with ui.row().classes("items-center gap-2"):
                                ui.badge(res_text, color=res_badge_color).props("outline").classes("text-xs font-semibold")

            async def handle_clear_checks():
                success = await asyncio.to_thread(_clear_security_checks_sync)
                if success:
                    ui.notify("Security checks history cleared.", type="positive", position="top")
                    await refresh_recent_checks()
                else:
                    ui.notify("Failed to clear security checks.", type="negative", position="top")

            clear_history_btn.on("click", handle_clear_checks)

            async def save_and_refresh_history(target, check_type, result, breach_count):
                await asyncio.to_thread(_insert_security_check_sync, target, check_type, result, breach_count)
                await refresh_recent_checks()

            ui.timer(0.1, refresh_recent_checks, once=True)


# ==============================================================================
# ACCOUNT PAGE (PROFILE INFORMATION & CHANGE PASSWORD)
# Matches screenshot: Notification Settings removed, exact 3 options added!
# ==============================================================================
def render_account_view(initial_tab="security"):
    setup_theme_styles()

    user = get_current_user_info()
    initials = get_user_initials(user.get("username", "Vaiz"), user.get("email", "shaikhv750@gmail.com"))

    # Top Navigation Bar (matching screenshot)
    with ui.header().classes(
        "w-full px-8 py-3.5 items-center justify-between"
    ).style(
        "background-color: #0b0f19; border-bottom: 1px solid #1e293b; z-index: 50;"
    ):
        with ui.row().classes("items-center gap-6"):
            ui.link("Dashboard", "/dashboard").classes(
                "text-slate-200 hover:text-white text-sm font-semibold no-underline"
            )

        with ui.row().classes("items-center gap-3"):
            # Avatar circle with VS, red dot, and dropdown
            with ui.row().classes("items-center gap-1.5 cursor-pointer"):
                with ui.element("div").classes("relative"):
                    with ui.element("div").classes(
                        "w-9 h-9 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-white tracking-wider"
                    ):
                        ui.label(initials)
                    ui.element("span").classes(
                        "absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-rose-500 border-2 border-[#0b0f19]"
                    )
                ui.icon("expand_more", size="18px").classes("text-slate-400")

                with ui.menu().classes("bg-[#111827] border border-slate-800 rounded-xl p-1.5 shadow-2xl"):
                    with ui.menu_item(on_click=lambda: ui.navigate.to("/account?tab=profile")).classes("hover:bg-slate-800 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-slate-200"):
                            ui.icon("person", size="16px").classes("text-emerald-400")
                            ui.label("Profile Information")

                    with ui.menu_item(on_click=lambda: ui.navigate.to("/account/change-password")).classes("hover:bg-slate-800 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-slate-200"):
                            ui.icon("lock", size="16px").classes("text-cyan-400")
                            ui.label("Security & Privacy")

                    ui.separator().classes("bg-slate-800 my-1")

                    with ui.menu_item(on_click=lambda: ui.navigate.to("/login")).classes("hover:bg-rose-500/10 rounded-lg text-xs py-2 px-3"):
                        with ui.row().classes("items-center gap-2 text-rose-400"):
                            ui.icon("logout", size="16px")
                            ui.label("Logout")

    # Main Two-Column Container
    with ui.row().classes("w-full max-w-6xl mx-auto px-8 py-10 items-start justify-between gap-12"):

        # LEFT CONTENT PANEL
        left_panel = ui.column().classes("flex-1 min-w-[320px] max-w-xl gap-5")

        # RIGHT ACCOUNT SIDEBAR (The exact 3 options, notification settings removed!)
        with ui.column().classes("w-64 pt-1 gap-2.5"):
            ui.label("Account").classes("text-sm font-bold text-white tracking-wide mb-1")

            # Option 1: Profile Information (with small red dot indicator)
            profile_tab = ui.row().classes(
                "items-center gap-2 cursor-pointer py-1.5 text-sm font-medium transition-colors"
            )

            # Option 2: Security & Privacy
            security_tab = ui.row().classes(
                "items-center gap-2 cursor-pointer py-1.5 text-sm font-medium transition-colors"
            )

            ui.separator().classes("my-2 bg-slate-800")

            # Option 3: Logout
            logout_tab = ui.row().classes(
                "items-center gap-2 cursor-pointer py-1.5 text-sm font-medium text-slate-400 hover:text-rose-400 transition-colors"
            ).on("click", lambda: ui.navigate.to("/login"))
            with logout_tab:
                ui.label("Logout")

        # Active Tab State
        current_tab = {"name": initial_tab}

        def update_view():
            left_panel.clear()
            tab_name = current_tab["name"]

            # Highlight active sidebar option
            if tab_name == "profile":
                profile_tab.classes(replace="text-white font-semibold")
                security_tab.classes(replace="text-slate-400 hover:text-slate-200")
            else:
                security_tab.classes(replace="text-white font-semibold")
                profile_tab.classes(replace="text-slate-400 hover:text-slate-200")

            with left_panel:
                if tab_name == "security":
                    # ==========================================================
                    # SECURITY & PRIVACY (CHANGE PASSWORD) - MATCHING SCREENSHOT
                    # ==========================================================
                    ui.label("Security & Privacy").classes("text-2xl font-bold text-white")

                    ui.label("Change password").classes("text-base font-semibold text-slate-200 mt-3 mb-1")

                    # Current Password
                    with ui.column().classes("w-full gap-1 mt-2"):
                        ui.label("Current Password").classes("text-xs text-slate-400 font-medium")
                        curr_pass_input = ui.input(
                            placeholder="Current Password",
                            password=True,
                            password_toggle_button=True
                        ).props("outlined dense dark").classes("w-full")

                    # New Password
                    with ui.column().classes("w-full gap-1 mt-3"):
                        ui.label("New Password").classes("text-xs text-slate-400 font-medium")
                        new_pass_input = ui.input(
                            placeholder="New Password",
                            password=True,
                            password_toggle_button=True
                        ).props("outlined dense dark").classes("w-full")

                    # Save Changes Button
                    def save_new_password():
                        c_val = (curr_pass_input.value or "").strip()
                        n_val = (new_pass_input.value or "").strip()

                        if not c_val or not n_val:
                            ui.notify("Please enter both current and new passwords.", type="warning", position="top")
                            return

                        u = get_current_user_info()

                        # Verify current password
                        if not check_password(c_val, u.get("password", "")):
                            ui.notify("Incorrect current password.", type="negative", position="top")
                            return

                        # Validate new password
                        if not valid_password(n_val):
                            ui.notify(
                                "Password must be at least 8 characters and contain uppercase, lowercase, number and special character.",
                                type="warning",
                                position="top"
                            )
                            return

                        if c_val == n_val:
                            ui.notify("New password must be different from current password.", type="warning", position="top")
                            return

                        try:
                            hashed = hash_password(n_val)
                            conn = get_db_connection()
                            cursor = conn.cursor()
                            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, u['id']))
                            conn.commit()
                            cursor.close()
                            conn.close()

                            curr_pass_input.value = ""
                            new_pass_input.value = ""
                            ui.notify("Password updated successfully!", type="positive", position="top")
                        except Exception as e:
                            print("Change password database error:", e)
                            ui.notify("Failed to update password. Please try again.", type="negative", position="top")

                    ui.button("Save Changes", on_click=save_new_password).classes(
                        "mt-4 px-6 py-2 rounded-lg text-slate-200 font-medium text-sm transition-all"
                    ).style("background-color: #334155 !important;")

                else:
                    # ==========================================================
                    # PROFILE INFORMATION - EMAIL, LAST TIME OF LOGIN, USERNAME
                    # ==========================================================
                    ui.label("Profile Information").classes("text-2xl font-bold text-white")

                    ui.label("User Account Information").classes("text-base font-semibold text-slate-200 mt-3 mb-1")

                    with ui.column().classes("w-full gap-4 mt-2"):
                        # Email Field
                        with ui.column().classes("w-full gap-1"):
                            ui.label("Email Address").classes("text-xs text-slate-400 font-medium")
                            with ui.row().classes("w-full p-3 rounded-xl bg-slate-900 border border-slate-800 items-center justify-between"):
                                with ui.row().classes("items-center gap-2"):
                                    ui.icon("email", size="18px").classes("text-emerald-400")
                                    ui.label(user.get("email", "")).classes("text-sm font-semibold text-slate-200 font-mono")
                                ui.badge("Active Account", color="positive").props("outline dense").classes("text-[10px]")

                        # Last Time of Login Field (Requested by user!)
                        with ui.column().classes("w-full gap-1"):
                            ui.label("Last Time of Login").classes("text-xs text-slate-400 font-medium")
                            with ui.row().classes("w-full p-3 rounded-xl bg-slate-900 border border-slate-800 items-center gap-2"):
                                ui.icon("schedule", size="18px").classes("text-cyan-400")
                                ui.label(str(user.get("last_login", "Just now"))).classes("text-sm font-semibold text-slate-200 font-mono")

                        # Username Field
                        with ui.column().classes("w-full gap-1"):
                            ui.label("Username").classes("text-xs text-slate-400 font-medium")
                            with ui.row().classes("w-full p-3 rounded-xl bg-slate-900 border border-slate-800 items-center gap-2"):
                                ui.icon("person", size="18px").classes("text-slate-400")
                                ui.label(user.get("username", "User")).classes("text-sm font-semibold text-slate-200")

                        ui.button(
                            "Return to Dashboard",
                            icon="arrow_back",
                            on_click=lambda: ui.navigate.to("/dashboard")
                        ).props("outline").classes("text-emerald-400 border-emerald-500/40 text-xs font-semibold mt-3 w-fit")

        def select_profile():
            current_tab["name"] = "profile"
            update_view()

        def select_security():
            current_tab["name"] = "security"
            update_view()

        with profile_tab:
            ui.label("Profile Information")
            ui.element("span").classes("w-2 h-2 rounded-full bg-rose-500 ml-1")
        profile_tab.on("click", select_profile)

        with security_tab:
            ui.label("Security & Privacy")
        security_tab.on("click", select_security)

        update_view()


@ui.page("/account")
def account_page():
    render_account_view(initial_tab="profile")


@ui.page("/account/change-password")
def change_password_page():
    render_account_view(initial_tab="security")


# Allow standalone execution
if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title="AI Phishing Detector",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        dark=True,
        storage_secret="ai_phishing_detector_storage_secret_key"
    )
