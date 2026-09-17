import os
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

            def do_login():
                if not email.value or not password.value:
                    notify_error("Please enter both email and password")
                    return

                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute("SELECT * FROM users WHERE email=%s", (email.value.strip(),))
                    user = cursor.fetchone()

                    if user and check_password(password.value, user[3]):
                        try:
                            cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user[0],))
                            db_conn.commit()
                        except Exception as e_up:
                            print("Update last_login error:", e_up)

                        app.storage.user['user_id'] = user[0]
                        app.storage.user['username'] = user[1]
                        app.storage.user['email'] = user[2]
                        app.storage.user['last_login'] = str(user[5]) if len(user) > 5 and user[5] else time.strftime("%Y-%m-%d %H:%M:%S")

                        notify_success(f"Welcome back, {user[1]}!")
                        ui.navigate.to("/dashboard")
                    else:
                        notify_error("Invalid email or password")
                except Exception as e:
                    print("Login database error:", e)
                    notify_error("Database connection error. Please try again.")
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            ui.button("Sign In to Dashboard", on_click=do_login).classes(
                "w-full text-slate-950 font-bold mt-5 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")

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

            def do_signup():
                if not username.value or not email.value or not password.value:
                    notify_error("Please fill all fields")
                    return

                if not valid_email(email.value):
                    notify_error("Please enter a valid email address")
                    return

                if not valid_password(password.value):
                    notify_error(
                        "Password must be at least 8 characters and contain uppercase, lowercase, number and special character."
                    )
                    return

                if password.value != confirm.value:
                    notify_error("Passwords do not match")
                    return

                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()

                    cursor.execute("SELECT * FROM users WHERE email=%s", (email.value.strip(),))
                    if cursor.fetchone():
                        notify_error("Email is already registered")
                        return

                    cursor.execute("SELECT * FROM users WHERE username=%s", (username.value.strip(),))
                    if cursor.fetchone():
                        notify_error("Username is already taken")
                        return

                    hashed_password = hash_password(password.value)
                    cursor.execute(
                        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                        (username.value.strip(), email.value.strip(), hashed_password)
                    )
                    db_conn.commit()

                    notify_success("Account created successfully! Please sign in.")
                    ui.navigate.to("/login")
                except Exception as e:
                    print("Signup database error:", e)
                    notify_error("Database connection error. Please try again.")
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

            ui.button("Register Account", on_click=do_signup).classes(
                "w-full text-slate-950 font-bold mt-5 py-2.5 rounded-lg shadow-lg"
            ).style("background-color: #10b981 !important;")

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

            def send_otp_clicked():
                global otp_verified
                if otp_verified:
                    notify_success("OTP is already verified.")
                    return

                if not valid_email(email.value):
                    notify_error("Please enter a valid email address")
                    return

                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute("SELECT * FROM users WHERE email=%s", (email.value.strip(),))
                    user = cursor.fetchone()
                except Exception as e:
                    print("OTP database error:", e)
                    notify_error("Database connection error. Please try again.")
                    return
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

                if not user:
                    notify_error("No account found with this email")
                    return

                if email.value in otp_time:
                    elapsed = time.time() - otp_time[email.value]
                    if elapsed < 300:
                        remaining = int((300 - elapsed) / 60) + 1
                        notify_error(f"Please wait {remaining} minute(s) before requesting another OTP.")
                        return

                generated_otp = str(random.randint(100000, 999999))
                success = send_otp(email.value.strip(), generated_otp)
                if not success:
                    notify_error("Failed to dispatch OTP. Please check Resend API configuration.")
                    return

                otp_storage[email.value] = generated_otp
                otp_time[email.value] = time.time()

                otp.set_visibility(True)
                countdown.set_visibility(True)
                notify_success("OTP dispatched successfully to your email!")

            def verify_otp():
                global otp_verified
                if not otp.value:
                    notify_error("Please enter the 6-digit OTP.")
                    return

                if otp_verified:
                    notify_success("OTP already verified.")
                    return

                if email.value not in otp_storage:
                    notify_error("Please request an OTP first.")
                    return

                if time.time() - otp_time[email.value] > 300:
                    del otp_storage[email.value]
                    del otp_time[email.value]
                    notify_error("OTP has expired. Please request a new OTP.")
                    return

                if otp.value.strip() != otp_storage[email.value]:
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

            def reset_password():
                if new_password.value != confirm_password.value:
                    notify_error("Passwords do not match")
                    return

                if not valid_password(new_password.value):
                    notify_error(
                        "Password must contain uppercase, lowercase, number, special character and be at least 8 characters."
                    )
                    return

                hashed = hash_password(new_password.value)
                db_conn = None
                cursor = None
                try:
                    db_conn = get_db_connection()
                    cursor = db_conn.cursor()
                    cursor.execute(
                        "UPDATE users SET password=%s WHERE email=%s",
                        (hashed, email.value.strip())
                    )
                    db_conn.commit()
                except Exception as e:
                    print("Reset password database error:", e)
                    notify_error("Database connection error. Please try again.")
                    return
                finally:
                    if cursor:
                        cursor.close()
                    if db_conn:
                        db_conn.close()

                if email.value in otp_storage:
                    del otp_storage[email.value]
                if email.value in otp_time:
                    del otp_time[email.value]

                notify_success("Password updated successfully! Please log in.")
                ui.navigate.to("/login")

            def update_countdown():
                if otp_verified:
                    return
                if email.value not in otp_time:
                    countdown.set_text("")
                    return
                remaining = 300 - int(time.time() - otp_time[email.value])
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
        storage_secret="ai_phishing_detector_storage_secret_key"
    )
