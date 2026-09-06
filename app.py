from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from config import DB_CONFIG

app = Flask(__name__)


def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# HOME
@app.route("/")
def home():
    return render_template("index.html")


# TEST DATABASE
@app.route("/test-db")
def test_db():
    try:
        connection = get_db_connection()

        if connection.is_connected():
            connection.close()
            return "Database connected successfully!"

        return "Database connection failed."

    except mysql.connector.Error as error:
        return f"Database Error: {error}"


# EVENTS
@app.route("/events")
def events():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM events")
        events_data = cursor.fetchall()

        cursor.close()
        connection.close()

        return render_template("events.html", events=events_data)

    except mysql.connector.Error as error:
        return f"Database Error: {error}"


# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():

    event_id = request.args.get("event_id")
    event = None

    # Get event details
    if event_id:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM events WHERE id = %s",
            (event_id,)
        )

        event = cursor.fetchone()

        cursor.close()
        connection.close()

    # Account registration
    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            query = """
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
            """

            cursor.execute(query, (name, email, password))

            connection.commit()

            cursor.close()
            connection.close()

            return redirect(url_for("login"))

        except mysql.connector.Error as error:
            return f"Database Error: {error}"

    return render_template(
        "register.html",
        event=event,
        event_id=event_id
    )

# SUCCESS
@app.route("/success")
def success():

    event_id = request.args.get("event_id")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM events WHERE id = %s",
        (event_id,)
    )

    event = cursor.fetchone()

    cursor.close()
    connection.close()

    return render_template("success.html", event=event)


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                "SELECT * FROM users WHERE email = %s AND password = %s",
                (email, password)
            )

            user = cursor.fetchone()

            cursor.close()
            connection.close()

            if user:
                return redirect(url_for("events"))
            else:
                return "Invalid email or password!"

        except mysql.connector.Error as error:
            return f"Database Error: {error}"

    return render_template("login.html")


# START FLASK
if __name__ == "__main__":
    app.run(debug=True)