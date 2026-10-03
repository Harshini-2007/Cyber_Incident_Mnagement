from flask import Flask, render_template, request, session, redirect, url_for, send_file
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Import our ML functions
from anomaly_detector import extract_features, detect_anomalies


app = Flask(__name__)

app.secret_key = "employee-portal-secret-key"


# ---------------- DATABASE CONNECTION ----------------

def get_db_connection():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Harshi@Books",
        database="cyber_security_db"
    )
    return connection


# ---------------- HOME / LOGIN PAGE ----------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )

    user = cursor.fetchone()

    if user:

        if user["password_hash"] and check_password_hash(
            user["password_hash"],
            password
        ):

            cursor.execute(
                """
                INSERT INTO logs
                (user_id, event_type, ip_address, timestamp, description)
                VALUES (%s, %s, %s, NOW(), %s)
                """,
                (
                    user["user_id"],
                    "Login Success",
                    request.remote_addr,
                    "User logged in successfully"
                )
            )

            connection.commit()

            session["user_id"] = user["user_id"]
            session["username"] = user["username"]

            cursor.close()
            connection.close()

            return redirect(url_for("dashboard"))

        else:

            cursor.execute(
                """
                INSERT INTO logs
                (user_id, event_type, ip_address, timestamp, description)
                VALUES (%s, %s, %s, NOW(), %s)
                """,
                (
                    user["user_id"],
                    "Failed Login",
                    request.remote_addr,
                    "Incorrect password entered"
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            return """
            <script>
                alert("Invalid username or password!");
                window.location.href = "/";
            </script>
            """

    cursor.close()
    connection.close()

    return """
    <script>
        alert("Invalid username or password!");
        window.location.href = "/";
    </script>
    """


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# ---------------- FILES ----------------

@app.route("/files")
def files():

    if "user_id" not in session:
        return redirect(url_for("home"))

    return render_template("files.html")


# ---------------- VIEW FILE ----------------

@app.route("/files/view/<filename>")
def view_file(filename):

    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO logs
        (user_id, event_type, ip_address, timestamp, description)
        VALUES (%s, %s, %s, NOW(), %s)
        """,
        (
            session["user_id"],
            "File Access",
            request.remote_addr,
            f"User accessed file: {filename}"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return render_template(
        "view_file.html",
        filename=filename
    )


# ---------------- DOWNLOAD FILE ----------------

@app.route("/files/download/<filename>")
def download_file(filename):

    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO logs
        (user_id, event_type, ip_address, timestamp, description)
        VALUES (%s, %s, %s, NOW(), %s)
        """,
        (
            session["user_id"],
            "File Download",
            request.remote_addr,
            f"User downloaded file: {filename}"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    file_path = os.path.join(
        "static",
        "files",
        filename
    )

    if os.path.exists(file_path):

        return send_file(
            file_path,
            as_attachment=True
        )

    return """
    <script>
        alert("File not found!");
        window.location.href = "/files";
    </script>
    """


# ---------------- CREATE ACCOUNT ----------------

@app.route("/create-account")
def create_account():

    return render_template("create_account.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )

    existing_user = cursor.fetchone()

    if existing_user:

        cursor.close()
        connection.close()

        return """
        <script>
            alert("Username already exists!");
            window.location.href = "/create-account";
        </script>
        """

    password_hash = generate_password_hash(password)

    cursor.execute(
        """
        INSERT INTO users
        (username, email, password_hash)
        VALUES (%s, %s, %s)
        """,
        (
            username,
            email,
            password_hash
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return """
    <script>
        alert("Account created successfully!");
        window.location.href = "/";
    </script>
    """


# ---------------- MY PROFILE ----------------

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(url_for("home"))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT user_id, username, email
        FROM users
        WHERE user_id = %s
        """,
        (session["user_id"],)
    )

    user = cursor.fetchone()

    cursor.execute(
        """
        INSERT INTO logs
        (user_id, event_type, ip_address, timestamp, description)
        VALUES (%s, %s, %s, NOW(), %s)
        """,
        (
            session["user_id"],
            "Profile View",
            request.remote_addr,
            "User viewed profile"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return render_template(
        "profile.html",
        user=user
    )


# ---------------- UPDATE PROFILE ----------------

@app.route("/profile/update", methods=["POST"])
def update_profile():

    if "user_id" not in session:
        return redirect(url_for("home"))

    email = request.form["email"]

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET email = %s
        WHERE user_id = %s
        """,
        (
            email,
            session["user_id"]
        )
    )

    cursor.execute(
        """
        INSERT INTO logs
        (user_id, event_type, ip_address, timestamp, description)
        VALUES (%s, %s, %s, NOW(), %s)
        """,
        (
            session["user_id"],
            "Profile Update",
            request.remote_addr,
            "User updated profile information"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return """
    <script>
        alert("Profile updated successfully!");
        window.location.href = "/profile";
    </script>
    """


# ---------------- ACCOUNT SETTINGS ----------------

@app.route("/settings")
def settings():

    if "user_id" not in session:
        return redirect(url_for("home"))

    return render_template("settings.html")


# ---------------- CHANGE PASSWORD ----------------

@app.route("/change-password", methods=["POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("home"))

    current_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT password_hash
        FROM users
        WHERE user_id = %s
        """,
        (session["user_id"],)
    )

    user = cursor.fetchone()

    if not check_password_hash(
        user["password_hash"],
        current_password
    ):

        cursor.execute(
            """
            INSERT INTO logs
            (user_id, event_type, ip_address, timestamp, description)
            VALUES (%s, %s, %s, NOW(), %s)
            """,
            (
                session["user_id"],
                "Failed Password Change",
                request.remote_addr,
                "Incorrect current password entered"
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        return """
        <script>
            alert("Current password is incorrect!");
            window.location.href = "/settings";
        </script>
        """

    if new_password != confirm_password:

        cursor.close()
        connection.close()

        return """
        <script>
            alert("New passwords do not match!");
            window.location.href = "/settings";
        </script>
        """

    new_password_hash = generate_password_hash(new_password)

    cursor.execute(
        """
        UPDATE users
        SET password_hash = %s
        WHERE user_id = %s
        """,
        (
            new_password_hash,
            session["user_id"]
        )
    )

    cursor.execute(
        """
        INSERT INTO logs
        (user_id, event_type, ip_address, timestamp, description)
        VALUES (%s, %s, %s, NOW(), %s)
        """,
        (
            session["user_id"],
            "Password Change",
            request.remote_addr,
            "User changed account password"
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return """
    <script>
        alert("Password changed successfully!");
        window.location.href = "/settings";
    </script>
    """


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    if "user_id" in session:

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO logs
            (user_id, event_type, ip_address, timestamp, description)
            VALUES (%s, %s, %s, NOW(), %s)
            """,
            (
                session["user_id"],
                "Logout",
                request.remote_addr,
                "User logged out"
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

    session.clear()

    return """
    <script>
        alert("You have been logged out.");
        window.location.href = "/";
    </script>
    """


# ---------------- SECURITY MONITORING ----------------

@app.route("/security", methods=["GET", "POST"])
def security():

    # First opening the page → show password screen
    if request.method == "GET":
        return render_template("security_login.html")


    # Get entered security password
    security_password = request.form["security_password"]


    # Check security password
    if security_password != "admin123":

        return """
        <script>
            alert("Incorrect security password!");
            window.location.href = "/security";
        </script>
        """


    # ---------------- CONNECT TO DATABASE ----------------

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)


    # ---------------- GET ALL LOGS ----------------

    cursor.execute(
        """
        SELECT
            logs.log_id,
            logs.user_id,
            logs.event_type,
            logs.ip_address,
            logs.timestamp,
            logs.description,
            users.username

        FROM logs

        LEFT JOIN users
        ON logs.user_id = users.user_id

        ORDER BY logs.timestamp ASC
        """
    )

    logs = cursor.fetchall()


    # ---------------- TOTAL LOGS ----------------

    total_logs = len(logs)


    # ---------------- MACHINE LEARNING ----------------

    # Convert raw logs into numerical features
    features = extract_features(logs)


    # Run Isolation Forest
    analyzed_users = detect_anomalies(features)


    # ---------------- COUNT ANOMALIES ----------------

    suspicious_users = [
        user for user in analyzed_users
        if user.get("status") == "Anomaly"
    ]


    suspicious_logs = len(suspicious_users)


    # Normal users
    normal_users = [
        user for user in analyzed_users
        if user.get("status") == "Normal"
    ]


    normal_logs = len(normal_users)


    # Active alerts = anomalous users
    active_alerts = suspicious_logs


    # ---------------- RECENT LOGS ----------------

    recent_logs = logs[-20:]

    # Reverse so newest log appears first
    recent_logs.reverse()


    cursor.close()
    connection.close()


    # ---------------- OPEN DASHBOARD ----------------

    return render_template(
        "security_dashboard.html",

        total_logs=total_logs,

        normal_logs=normal_logs,

        suspicious_logs=suspicious_logs,

        active_alerts=active_alerts,

        logs=recent_logs,

        analyzed_users=analyzed_users
    )


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)