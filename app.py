import calendar
import os
import smtplib
from datetime import date
from email.message import EmailMessage
from functools import wraps

import mysql.connector
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import ADMIN_PASSWORD, DB_CONFIG, FEEDBACK_EMAIL

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "event-management-development-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


def close_db(connection, cursor):
    if cursor:
        cursor.close()
    if connection:
        connection.close()


def column_exists(cursor, table_name, column_name):
    cursor.execute(
        """
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """,
        (DB_CONFIG["database"], table_name, column_name),
    )
    return cursor.fetchone()[0] > 0


def ensure_schema(connection):
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            profile_photo VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            admin_id INT NULL,
            sender_role VARCHAR(20) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    if not column_exists(cursor, "users", "profile_photo"):
        cursor.execute("ALTER TABLE users ADD COLUMN profile_photo VARCHAR(255) NULL")
    connection.commit()
    cursor.close()


def fetch_event(event_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM events WHERE id = %s", (event_id,))
        return cursor.fetchone()
    finally:
        close_db(connection, cursor)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin_id" not in session:
            flash("Administrator access is required.", "error")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_session_state():
    return {
        "current_user": session.get("user_name"),
        "current_admin": session.get("admin_name"),
        "theme": session.get("theme", "light"),
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/role-selection")
def role_selection():
    return render_template("role_selection.html")


@app.route("/test-db")
def test_db():
    connection = None
    try:
        connection = get_db_connection()
        return "Database connected successfully!" if connection.is_connected() else "Database connection failed."
    except mysql.connector.Error:
        return "Database connection failed.", 500
    finally:
        if connection:
            connection.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("signin.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not name or not email or not password or password != confirm_password:
        flash("Complete every field and make sure both passwords match.", "error")
        return render_template("signin.html"), 400

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        ensure_schema(connection)
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("An account with that email already exists.", "error")
            return render_template("signin.html"), 409
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, password_hash),
        )
        user_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO login_users (user_id, email, password_hash) VALUES (%s, %s, %s)",
            (user_id, email, password_hash),
        )
        connection.commit()
        flash("Your account was created. You can now log in.", "success")
        return redirect(url_for("login"))
    except mysql.connector.Error:
        if connection:
            connection.rollback()
        flash("Account creation failed. Please try again.", "error")
        return render_template("signin.html"), 500
    finally:
        close_db(connection, cursor)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        ensure_schema(connection)
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT lu.user_id, lu.password_hash, u.name FROM login_users lu "
            "JOIN users u ON u.id = lu.user_id WHERE lu.email = %s",
            (email,),
        )
        user = cursor.fetchone()
        valid = user and check_password_hash(user["password_hash"], password)
        if not valid:
            cursor.execute("SELECT id, name, password FROM users WHERE email = %s", (email,))
            legacy = cursor.fetchone()
            if legacy and legacy["password"] == password:
                password_hash = generate_password_hash(password)
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", (password_hash, legacy["id"]))
                cursor.execute("SELECT id FROM login_users WHERE user_id = %s", (legacy["id"],))
                if cursor.fetchone():
                    cursor.execute("UPDATE login_users SET password_hash = %s WHERE user_id = %s", (password_hash, legacy["id"]))
                else:
                    cursor.execute("INSERT INTO login_users (user_id, email, password_hash) VALUES (%s, %s, %s)", (legacy["id"], email, password_hash))
                connection.commit()
                user = {"user_id": legacy["id"], "name": legacy["name"]}
        if not user:
            flash("Incorrect email or password.", "error")
            return render_template("login.html"), 401
        session.clear()
        session["user_id"] = user["user_id"]
        session["user_name"] = user["name"]
        session["theme"] = "light"
        return redirect(request.args.get("next") or url_for("user_home"))
    except mysql.connector.Error:
        flash("Login is temporarily unavailable.", "error")
        return render_template("login.html"), 500
    finally:
        close_db(connection, cursor)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("role_selection"))


@app.route("/user-home")
@login_required
def user_home():
    return render_template("user_home.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            if not name or not email:
                flash("Username and email are required.", "error")
                return redirect(url_for("profile"))
            cursor.execute("UPDATE users SET name = %s, email = %s WHERE id = %s", (name, email, session["user_id"]))
            cursor.execute("UPDATE login_users SET email = %s WHERE user_id = %s", (email, session["user_id"]))
            connection.commit()
            session["user_name"] = name
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        cursor.execute("SELECT id, name, email, profile_photo FROM users WHERE id = %s", (session["user_id"],))
        user = cursor.fetchone()
        return render_template("profile.html", user=user)
    except mysql.connector.Error:
        flash("Profile could not be updated.", "error")
        return redirect(url_for("profile"))
    finally:
        close_db(connection, cursor)


@app.route("/profile/photo", methods=["POST"])
@login_required
def profile_photo():
    photo = request.files.get("photo")
    if not photo or not photo.filename:
        flash("Choose an image first.", "error")
        return redirect(url_for("profile"))
    extension = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        flash("Use a PNG, JPG, GIF, or WEBP image.", "error")
        return redirect(url_for("profile"))
    filename = secure_filename(f"user_{session['user_id']}.{extension}")
    upload_dir = os.path.join(app.static_folder, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    photo.save(os.path.join(upload_dir, filename))
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("UPDATE users SET profile_photo = %s WHERE id = %s", (filename, session["user_id"]))
        connection.commit()
        flash("Profile photo updated.", "success")
    finally:
        close_db(connection, cursor)
    return redirect(url_for("profile"))


@app.route("/theme", methods=["POST"])
def theme():
    if "user_id" not in session and "admin_id" not in session:
        flash("Please sign in to change the theme.", "error")
        return redirect(url_for("role_selection"))
    session["theme"] = "dark" if request.form.get("theme") == "dark" else "light"
    return redirect(request.referrer or url_for("profile"))


def event_list(kind):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        operator = "<" if kind == "old" else ">="
        cursor.execute(f"SELECT * FROM events WHERE event_date {operator} %s ORDER BY event_date", (date.today(),))
        return cursor.fetchall()
    finally:
        close_db(connection, cursor)


@app.route("/events")
@login_required
def events():
    try:
        return render_template("upcoming_events.html", events=event_list("upcoming"))
    except mysql.connector.Error:
        flash("Events are temporarily unavailable.", "error")
        return render_template("upcoming_events.html", events=[]), 500


@app.route("/upcoming-events")
@login_required
def upcoming_events():
    return events()


@app.route("/old-events")
@login_required
def old_events():
    try:
        return render_template("old_events.html", events=event_list("old"))
    except mysql.connector.Error:
        flash("Events are temporarily unavailable.", "error")
        return render_template("old_events.html", events=[]), 500


@app.route("/event/<int:event_id>")
@login_required
def event_details(event_id):
    try:
        event = fetch_event(event_id)
    except mysql.connector.Error:
        flash("The event could not be loaded.", "error")
        return redirect(url_for("upcoming_events"))
    if not event:
        return render_template("error.html", message="Event not found."), 404
    return render_template("event_details.html", event=event)


@app.route("/register_event/<int:event_id>", methods=["GET", "POST"])
@login_required
def register_event(event_id):
    event = fetch_event(event_id)
    if not event:
        return render_template("error.html", message="Event not found."), 404
    if event["event_date"] < date.today():
        return render_template("error.html", message="Past events are not open for registration."), 400
    if request.method == "POST":
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            ensure_schema(connection)
            cursor = connection.cursor()
            cursor.execute("SELECT id FROM event_registrations WHERE user_id = %s AND event_id = %s", (session["user_id"], event_id))
            if cursor.fetchone():
                flash("You are already registered for this event.", "error")
                return redirect(url_for("event_details", event_id=event_id))
            cursor.execute("INSERT INTO event_registrations (user_id, event_id) VALUES (%s, %s)", (session["user_id"], event_id))
            connection.commit()
            return redirect(url_for("success", event_id=event_id))
        except mysql.connector.Error:
            if connection:
                connection.rollback()
            flash("Event registration failed.", "error")
            return redirect(url_for("event_details", event_id=event_id))
        finally:
            close_db(connection, cursor)
    return render_template("event_registration.html", event=event)


@app.route("/success")
@login_required
def success():
    event_id = request.args.get("event_id", type=int)
    if event_id is None:
        return render_template("error.html", message="Event ID is required."), 400
    event = fetch_event(event_id)
    if not event:
        return render_template("error.html", message="Event not found."), 404
    return render_template("success.html", event=event)


def calendar_context():
    year = request.args.get("year", date.today().year, type=int)
    month = request.args.get("month", date.today().month, type=int)
    year = max(2000, min(2050, year))
    month = max(1, min(12, month))
    previous_year, previous_month = (year - 1, 12) if month == 1 else (year, month - 1)
    next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)
    return {
        "year": year,
        "month": month,
        "month_name": calendar.month_name[month],
        "weeks": calendar.monthcalendar(year, month),
        "previous": (max(2000, previous_year), previous_month),
        "next": (min(2050, next_year), next_month),
        "can_previous": (year, month) != (2000, 1),
        "can_next": (year, month) != (2050, 12),
    }


@app.route("/calendar")
@login_required
def calendar_page():
    return render_template("calendar.html", calendar_data=calendar_context())


def send_feedback(message, sender_role, sender_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        ensure_schema(connection)
        cursor = connection.cursor()
        user_id = sender_id if sender_role == "user" else None
        admin_id = sender_id if sender_role == "admin" else None
        cursor.execute("INSERT INTO feedback (user_id, admin_id, sender_role, message) VALUES (%s, %s, %s, %s)", (user_id, admin_id, sender_role, message))
        connection.commit()
    except mysql.connector.Error:
        return False
    finally:
        close_db(connection, cursor)

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    if not smtp_host or not smtp_user or not smtp_password:
        return False
    email = EmailMessage()
    email["Subject"] = "Event Management feedback"
    email["From"] = smtp_user
    email["To"] = FEEDBACK_EMAIL
    email.set_content(message)
    try:
        with smtplib.SMTP(smtp_host, int(os.environ.get("SMTP_PORT", "587"))) as smtp:
            smtp.starttls()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(email)
        return True
    except (OSError, smtplib.SMTPException, ValueError):
        return False


@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    if request.method == "GET":
        return render_template("feedback.html")
    message = request.form.get("message", "").strip()
    if not message or len(message.split()) > 500:
        flash("Feedback is required and must be 500 words or fewer.", "error")
        return render_template("feedback.html"), 400
    if not send_feedback(message, "user", session["user_id"]):
        flash("Feedback could not be sent. Configure the email settings first.", "error")
        return render_template("feedback.html"), 500
    flash("Thank you. Your feedback was sent.", "success")
    return redirect(url_for("feedback"))


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not name or not email or password != ADMIN_PASSWORD:
        flash("Invalid password or administrator details.", "error")
        return render_template("admin_login.html"), 401
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        ensure_schema(connection)
        cursor = connection.cursor(dictionary=True)
        password_hash = generate_password_hash(password)
        cursor.execute("SELECT id FROM admins WHERE email = %s", (email,))
        admin = cursor.fetchone()
        if admin:
            cursor.execute("UPDATE admins SET name = %s, password_hash = %s WHERE id = %s", (name, password_hash, admin["id"]))
            admin_id = admin["id"]
        else:
            cursor.execute("INSERT INTO admins (name, email, password_hash) VALUES (%s, %s, %s)", (name, email, password_hash))
            admin_id = cursor.lastrowid
        connection.commit()
        session.clear()
        session["admin_id"] = admin_id
        session["admin_name"] = name
        session["theme"] = "light"
        return redirect(url_for("admin_home"))
    except mysql.connector.Error:
        if connection:
            connection.rollback()
        flash("Administrator login failed.", "error")
        return render_template("admin_login.html"), 500
    finally:
        close_db(connection, cursor)


@app.route("/admin")
@admin_required
def admin_home():
    return render_template("admin_home.html")


@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            cursor.execute("UPDATE admins SET name = %s, email = %s WHERE id = %s", (name, email, session["admin_id"]))
            connection.commit()
            session["admin_name"] = name
            flash("Admin profile updated.", "success")
            return redirect(url_for("admin_profile"))
        cursor.execute("SELECT * FROM admins WHERE id = %s", (session["admin_id"],))
        admin = cursor.fetchone()
        return render_template("admin_profile.html", admin=admin)
    finally:
        close_db(connection, cursor)


@app.route("/admin/profile/photo", methods=["POST"])
@admin_required
def admin_profile_photo():
    photo = request.files.get("photo")
    if not photo or not photo.filename:
        flash("Choose an image first.", "error")
        return redirect(url_for("admin_profile"))
    extension = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        flash("Use a PNG, JPG, GIF, or WEBP image.", "error")
        return redirect(url_for("admin_profile"))
    filename = secure_filename(f"admin_{session['admin_id']}.{extension}")
    upload_dir = os.path.join(app.static_folder, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    photo.save(os.path.join(upload_dir, filename))
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("UPDATE admins SET profile_photo = %s WHERE id = %s", (filename, session["admin_id"]))
        connection.commit()
        flash("Admin profile photo updated.", "success")
    finally:
        close_db(connection, cursor)
    return redirect(url_for("admin_profile"))


@app.route("/admin/add-event", methods=["GET", "POST"])
@admin_required
def add_event():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            event_date = request.form.get("event_date", "")
            location = request.form.get("location", "").strip()
            if not name or not event_date or not location:
                flash("Event name, date, and location are required.", "error")
                return redirect(url_for("add_event"))
            try:
                parsed_date = date.fromisoformat(event_date)
            except ValueError:
                flash("Enter a valid event date.", "error")
                return redirect(url_for("add_event"))
            cursor.execute("INSERT INTO events (name, description, event_date, location) VALUES (%s, %s, %s, %s)", (name, description, parsed_date, location))
            connection.commit()
            flash("Event added successfully.", "success")
            return redirect(url_for("add_event"))
        cursor.execute("SELECT * FROM events ORDER BY event_date")
        events_data = cursor.fetchall()
        return render_template("add_event.html", events=events_data)
    except mysql.connector.Error:
        if connection:
            connection.rollback()
        flash("The event could not be saved.", "error")
        return redirect(url_for("add_event"))
    finally:
        close_db(connection, cursor)


@app.route("/admin/delete-event", methods=["GET", "POST"])
@admin_required
def delete_event():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if request.method == "POST":
            event_id = request.form.get("event_id", type=int)
            if not event_id:
                flash("Select an event first.", "error")
                return redirect(url_for("delete_event"))
            cursor.execute("DELETE FROM event_registrations WHERE event_id = %s", (event_id,))
            cursor.execute("DELETE FROM events WHERE id = %s", (event_id,))
            connection.commit()
            flash("Event deleted successfully.", "success")
            return redirect(url_for("delete_event"))
        cursor.execute("SELECT * FROM events WHERE event_date >= %s ORDER BY event_date", (date.today(),))
        events_data = cursor.fetchall()
        return render_template("delete_event.html", events=events_data)
    except mysql.connector.Error:
        if connection:
            connection.rollback()
        flash("The event could not be deleted.", "error")
        return redirect(url_for("delete_event"))
    finally:
        close_db(connection, cursor)


@app.route("/admin/calendar")
@admin_required
def admin_calendar():
    return render_template("calendar.html", calendar_data=calendar_context(), admin_view=True)


@app.route("/admin/feedback", methods=["GET", "POST"])
@admin_required
def admin_feedback():
    if request.method == "GET":
        return render_template("feedback.html", admin_view=True)
    message = request.form.get("message", "").strip()
    if not message or len(message.split()) > 500:
        flash("Feedback is required and must be 500 words or fewer.", "error")
        return render_template("feedback.html", admin_view=True), 400
    if not send_feedback(message, "admin", session["admin_id"]):
        flash("Feedback could not be sent. Configure the email settings first.", "error")
        return render_template("feedback.html", admin_view=True), 500
    flash("Thank you. Your feedback was sent.", "success")
    return redirect(url_for("admin_feedback"))


@app.route("/admin/about")
@admin_required
def admin_about():
    return render_template("about.html", admin_view=True)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("role_selection"))


if __name__ == "__main__":
    app.run(debug=True)
