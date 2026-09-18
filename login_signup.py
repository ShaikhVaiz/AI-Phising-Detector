import os
import asyncio
from dotenv import load_dotenv
import re
import bcrypt
import random
import time
from nicegui import app, ui
import mysql.connector
import resend

load_dotenv()
import dashboard
import requests

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
resend.api_key = RESEND_API_KEY

def get_db_connection():
    # Reuse dashboard connection pool for high speed
    return dashboard.get_db_connection()

GREEN = "#10b981"
BG_DARK = "#090d16"
CARD_BG = "#111827"
CARD_BORDER = "#1f293d"

otp_storage = {}
otp_time = {}
otp_verified = False

def valid_email(email):
    pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return re.match(pattern, email)

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

def notify_error(msg):
    ui.notify(msg, type="negative", position="top")

def notify_success(msg):
    ui.notify(msg, type="positive", position="top")

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def send_otp(receiver_email, otp):
    try:
        params = {
            "from": "onboarding@resend.dev",
            "to": [receiver_email],
            "subject": "Password Reset OTP - AI Phishing Detector",
            "html": f"""
                <div style="font-family: sans-serif; background-color: #0b0f19; color: #fff; padding: 30px; border-radius: 10px;">
                    <h2 style="color: #10b981;">AI Phishing Detector Security</h2>
                    <p>You requested a one-time verification code to reset your password:</p>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #10b981; padding: 15px 0;">{otp}</div>
                    <p style="color: #94a3b8;">This OTP is valid for <strong>5 minutes</strong>.</p>
                    <p style="color: #64748b; font-size: 12px;">If you did not request this, please ignore this email immediately.</p>
                </div>
            """
        }
        email = resend.Emails.send(params)
        print("OTP email sent:", email)
        return True
    except Exception as e:
        print("OTP email failed:", repr(e))
        return False

def setup_page_styles():
    ui.add_head_html("""
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Plus Jakarta Sans', sans-serif !important;
                background-color: #090d16 !important;
                color: #f1f5f9;
            }
            .cyber-auth-card {
                background: #111827;
                border: 1px solid #1f293d;
                border-radius: 18px;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
            }
            .q-field--outlined .q-field__control {
                background-color: #0d1322 !important;
                border-radius: 8px !important;
            }
            .q-field--outlined .q-field__control:hover {
                border-color: #10b981 !important;
            }
        </style>
    """)


@ui.page("/")
def index():
    ui.navigate.to("/login")


@ui.page("/login")
def login_page():
    setup_page_styles()

    with ui.column().classes("absolute-center items-center gap-4"):
        # Branding
        with ui.row().classes("items-center gap-2 mb-2"):
            ui.icon("security", size="32px").style("color: #10b981;")
            ui.label("AI PHISHING DETECTOR").classes("font-extrabold text-xl tracking-wider text-white")

        with ui.card().classes("cyber-auth-card p-8").style("width: 380px;"):
            ui.label("Sign In").classes("text-2xl font-bold text-white mb-1")
            ui.label("Access Threat Intelligence Dashboard").classes("text-xs text-slate-400 mb-6")

            email = ui.input(placeholder="name@example.com").classes("w-full").props("outlined dense dark")
            email.props('prepend-icon="email"')

            password = ui.input(
                placeholder="Enter your password",
                password=True,
                password_toggle_button=True
            ).classes("w-full mt-3").props("outlined dense dark")
            password.props('prepend-icon="lock"')

            with ui.row().classes("w-full justify-end mt-2"):
                ui.link("Forgot password?", "/forgot-password").style(
                    "color: #10b981; font-size: 13px; text-decoration: none;"
                ).classes("hover:underline")

            def _authenticate_sync(raw_email, raw_password):
                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute("SELECT id, username, email, password, create_at, last_login FROM users WHERE email=%s", (raw_email,))
                    user = cursor.fetchone()
                    if user and check_password(raw_password, user[3]):
                        try:
                            cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user[0],))
                            db_conn.commit()
                        except Exception as e_up:
                            print("Update last_login error:", e_up)
                        return {
                            'id': user[0],
                            'username': user[1],
                            'email': user[2],
                            'password': user[3],
                            'created_at': user[4],
                            'last_login': str(user[5]) if user[5] else time.strftime("%Y-%m-%d %H:%M:%S")
                        }, None
                    else:
                        return None, "Invalid email or password"
                except Exception as e:
                    print("Login database error:", repr(e))
                    return None, "Database connection error. Please try again."
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            async def do_login():
                e_val = (email.value or "").strip()
                p_val = password.value or ""
                if not e_val or not p_val:
                    notify_error("Please enter both email and password")
                    return

                sign_in_btn.props("loading")
                try:
                    user_info, err = await asyncio.to_thread(_authenticate_sync, e_val, p_val)
                    if err:
                        notify_error(err)
                        return

                    app.storage.user['user_id'] = user_info['id']
                    app.storage.user['username'] = user_info['username']
                    app.storage.user['email'] = user_info['email']
                    app.storage.user['password'] = user_info['password']
                    app.storage.user['last_login'] = user_info['last_login']

                    notify_success(f"Welcome back, {user_info['username']}!")
                    ui.navigate.to("/dashboard")
                finally:
                    sign_in_btn.props(remove="loading")

            sign_in_btn = ui.button("Sign In to Dashboard", on_click=do_login).classes(
                "w-full text-slate-950 font-bold mt-5 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")

            email.on("keydown.enter", do_login)
            password.on("keydown.enter", do_login)

            with ui.row().classes("w-full justify-center mt-5 gap-1 items-center"):
                ui.label("Don't have an account?").classes("text-xs text-slate-400")
                ui.link("Create Account", "/signup").style(
                    "color: #10b981; font-weight: 600; font-size: 13px; text-decoration: none;"
                ).classes("hover:underline")


@ui.page("/signup")
def signup_page():
    setup_page_styles()

    with ui.column().classes("absolute-center items-center gap-4"):
        with ui.row().classes("items-center gap-2 mb-2"):
            ui.icon("security", size="32px").style("color: #10b981;")
            ui.label("AI PHISHING DETECTOR").classes("font-extrabold text-xl tracking-wider text-white")

        with ui.card().classes("cyber-auth-card p-8").style("width: 380px;"):
            ui.label("Create Account").classes("text-2xl font-bold text-white mb-1")
            ui.label("Start monitoring domains and breaches").classes("text-xs text-slate-400 mb-6")

            username = ui.input(placeholder="Username").classes("w-full").props("outlined dense dark")
            username.props('prepend-icon="person"')

            email = ui.input(placeholder="Email address").classes("w-full mt-3").props("outlined dense dark")
            email.props('prepend-icon="email"')

            password = ui.input(
                placeholder="Create password",
                password=True,
                password_toggle_button=True
            ).classes("w-full mt-3").props("outlined dense dark")
            password.props('prepend-icon="lock"')

            confirm = ui.input(
                placeholder="Confirm password",
                password=True,
                password_toggle_button=True
            ).classes("w-full mt-3").props("outlined dense dark")
            confirm.props('prepend-icon="lock_clock"')

            def _register_user_sync(raw_username, raw_email, raw_password):
                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()

                    cursor.execute("SELECT id FROM users WHERE email=%s", (raw_email,))
                    if cursor.fetchone():
                        return False, "Email is already registered"

                    cursor.execute("SELECT id FROM users WHERE username=%s", (raw_username,))
                    if cursor.fetchone():
                        return False, "Username is already taken"

                    hashed_password = hash_password(raw_password)
                    cursor.execute(
                        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                        (raw_username, raw_email, hashed_password)
                    )
                    db_conn.commit()
                    return True, None
                except Exception as e:
                    print("Signup database error:", repr(e))
                    return False, "Database connection error. Please try again."
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            async def do_signup():
                u_val = (username.value or "").strip()
                e_val = (email.value or "").strip()
                p_val = password.value or ""
                c_val = confirm.value or ""

                if not u_val or not e_val or not p_val:
                    notify_error("Please fill all fields")
                    return

                if not valid_email(e_val):
                    notify_error("Please enter a valid email address")
                    return

                if not valid_password(p_val):
                    notify_error(
                        "Password must be at least 8 characters and contain uppercase, lowercase, number and special character."
                    )
                    return

                if p_val != c_val:
                    notify_error("Passwords do not match")
                    return

                register_btn.props("loading")
                try:
                    ok, err = await asyncio.to_thread(_register_user_sync, u_val, e_val, p_val)
                    if not ok:
                        notify_error(err or "Registration failed")
                        return

                    notify_success("Account created successfully! Please sign in.")
                    ui.navigate.to("/login")
                finally:
                    register_btn.props(remove="loading")

            register_btn = ui.button("Register Account", on_click=do_signup).classes(
                "w-full text-slate-950 font-bold mt-5 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")

            username.on("keydown.enter", do_signup)
            email.on("keydown.enter", do_signup)
            password.on("keydown.enter", do_signup)
            confirm.on("keydown.enter", do_signup)

            with ui.row().classes("w-full justify-center mt-5 gap-1 items-center"):
                ui.label("Already registered?").classes("text-xs text-slate-400")
                ui.link("Sign In", "/login").style(
                    "color: #10b981; font-weight: 600; font-size: 13px; text-decoration: none;"
                ).classes("hover:underline")


@ui.page("/forgot-password")
def forgot_password_page():
    setup_page_styles()

    with ui.column().classes("absolute-center items-center gap-4"):
        with ui.row().classes("items-center gap-2 mb-2"):
            ui.icon("security", size="32px").style("color: #10b981;")
            ui.label("AI PHISHING DETECTOR").classes("font-extrabold text-xl tracking-wider text-white")

        with ui.card().classes("cyber-auth-card p-8").style("width: 380px;"):
            ui.label("Password Recovery").classes("text-2xl font-bold text-white mb-1")
            ui.label("Verify identity via one-time passcode").classes("text-xs text-slate-400 mb-5")

            email = ui.input(placeholder="Enter registered email").classes("w-full").props("outlined dense dark")
            email.props('prepend-icon="email"')

            otp = ui.input(placeholder="Enter 6-digit OTP").classes("w-full mt-3").props("outlined dense dark")
            otp.props('prepend-icon="pin"')
            otp.set_visibility(False)

            countdown = ui.label("").style("color: #f43f5e; font-size: 12px; font-weight: 600; margin-top: 6px;")
            countdown.set_visibility(False)

            new_password = ui.input(
                placeholder="New Password",
                password=True,
                password_toggle_button=True
            ).classes("w-full mt-3").props("outlined dense dark")
            new_password.props('prepend-icon="lock"')
            new_password.set_visibility(False)

            confirm_password = ui.input(
                placeholder="Confirm New Password",
                password=True,
                password_toggle_button=True
            ).classes("w-full mt-3").props("outlined dense dark")
            confirm_password.props('prepend-icon="lock_clock"')
            confirm_password.set_visibility(False)

            def _find_user_sync(raw_email):
                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute("SELECT id FROM users WHERE email=%s", (raw_email,))
                    return cursor.fetchone() is not None, None
                except Exception as e:
                    print("OTP database error:", repr(e))
                    return False, "Database connection error. Please try again."
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            def _update_password_sync(raw_email, hashed_pw):
                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute(
                        "UPDATE users SET password=%s WHERE email=%s",
                        (hashed_pw, raw_email)
                    )
                    db_conn.commit()
                    return True, None
                except Exception as e:
                    print("Reset password database error:", repr(e))
                    return False, "Database connection error. Please try again."
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            async def send_otp_clicked():
                global otp_verified
                if otp_verified:
                    notify_success("OTP is already verified.")
                    return

                e_val = (email.value or "").strip()
                if not valid_email(e_val):
                    notify_error("Please enter a valid email address")
                    return

                send_otp_button.props("loading")
                try:
                    user_exists, err = await asyncio.to_thread(_find_user_sync, e_val)
                    if err:
                        notify_error(err)
                        return

                    if not user_exists:
                        notify_error("No account found with this email")
                        return

                    if e_val in otp_time:
                        elapsed = time.time() - otp_time[e_val]
                        if elapsed < 300:
                            remaining = int((300 - elapsed) / 60) + 1
                            notify_error(f"Please wait {remaining} minute(s) before requesting another OTP.")
                            return

                    generated_otp = str(random.randint(100000, 999999))
                    success = await asyncio.to_thread(send_otp, e_val, generated_otp)
                    if not success:
                        notify_error("Failed to dispatch OTP. Please check Resend API configuration.")
                        return

                    otp_storage[e_val] = generated_otp
                    otp_time[e_val] = time.time()

                    otp.set_visibility(True)
                    countdown.set_visibility(True)
                    notify_success("OTP dispatched successfully to your email!")
                finally:
                    send_otp_button.props(remove="loading")

            def verify_otp():
                global otp_verified
                if not (otp.value or "").strip():
                    notify_error("Please enter the 6-digit OTP.")
                    return

                if otp_verified:
                    notify_success("OTP already verified.")
                    return

                e_val = (email.value or "").strip()
                if e_val not in otp_storage:
                    notify_error("Please request an OTP first.")
                    return

                if time.time() - otp_time[e_val] > 300:
                    del otp_storage[e_val]
                    del otp_time[e_val]
                    notify_error("OTP has expired. Please request a new OTP.")
                    return

                if otp.value.strip() != otp_storage[e_val]:
                    notify_error("Incorrect OTP code. Please check your email.")
                    return

                otp_verified = True
                notify_success("OTP verified successfully!")

                send_otp_button.set_visibility(False)
                verify_otp_button.set_visibility(False)
                email.disable()
                otp.disable()

                new_password.set_visibility(True)
                confirm_password.set_visibility(True)
                reset_button.set_visibility(True)
                countdown.set_text("OTP Verified ✓")
                countdown.style("color: #10b981;")
                countdown_timer.cancel()

            async def reset_password():
                n_val = new_password.value or ""
                c_val = confirm_password.value or ""
                if n_val != c_val:
                    notify_error("Passwords do not match")
                    return

                if not valid_password(n_val):
                    notify_error(
                        "Password must contain uppercase, lowercase, number, special character and be at least 8 characters."
                    )
                    return

                reset_button.props("loading")
                try:
                    hashed = hash_password(n_val)
                    e_val = (email.value or "").strip()
                    ok, err = await asyncio.to_thread(_update_password_sync, e_val, hashed)
                    if not ok:
                        notify_error(err or "Failed to update password.")
                        return

                    if e_val in otp_storage:
                        del otp_storage[e_val]
                    if e_val in otp_time:
                        del otp_time[e_val]

                    notify_success("Password updated successfully! Please log in.")
                    ui.navigate.to("/login")
                finally:
                    reset_button.props(remove="loading")

            def update_countdown():
                if otp_verified:
                    return
                e_val = (email.value or "").strip()
                if e_val not in otp_time:
                    countdown.set_text("")
                    return
                remaining = 300 - int(time.time() - otp_time[e_val])
                if remaining <= 0:
                    countdown.set_text("OTP Expired")
                    return
                minutes = remaining // 60
                seconds = remaining % 60
                countdown.set_text(f"OTP expires in {minutes:02d}:{seconds:02d}")

            send_otp_button = ui.button("Send Verification Code", on_click=send_otp_clicked).classes(
                "w-full text-slate-950 font-bold mt-4 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")

            verify_otp_button = ui.button("Verify Code", on_click=verify_otp).classes(
                "w-full text-slate-950 font-bold mt-3 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #06b6d4 !important;")

            reset_button = ui.button("Update Password", on_click=reset_password).classes(
                "w-full text-slate-950 font-bold mt-4 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")
            reset_button.set_visibility(False)

            email.on("keydown.enter", send_otp_clicked)
            otp.on("keydown.enter", verify_otp)
            new_password.on("keydown.enter", reset_password)
            confirm_password.on("keydown.enter", reset_password)

            countdown_timer = ui.timer(1.0, update_countdown)

            with ui.row().classes("w-full justify-center mt-5"):
                ui.link("← Back to Sign In", "/login").style(
                    "color: #10b981; font-size: 13px; text-decoration: none;"
                ).classes("hover:underline")


if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title="AI Phishing Detector - Login",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        dark=True,
        storage_secret="ai_phishing_detector_storage_secret_key",
        reconnect_timeout=30.0
    )
