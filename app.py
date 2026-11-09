import os
import sqlite3
import uuid
import zipfile

from io import BytesIO
from functools import wraps

import boto3

from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# ---------------- CONFIGURATION ----------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))

SECRET_KEY = os.getenv("SECRET_KEY")
BUCKET_NAME = os.getenv("BUCKET_NAME")
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")

DATABASE = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)

if not SECRET_KEY:
    raise ValueError("SECRET_KEY is missing from .env file")

if not BUCKET_NAME:
    raise ValueError("BUCKET_NAME is missing from .env file")

app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

csrf = CSRFProtect(app)

s3 = boto3.client("s3", region_name=AWS_REGION)


# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()


# ---------------- LOGIN PROTECTION ----------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def user_prefix():
    return f"users/{session['user_id']}/"


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO users (username, email, password)
                    VALUES (?, ?, ?)
                """, (username, email, hashed_password))

                conn.commit()

            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful!", "success")
            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("index.html")


# ---------------- LOGOUT ----------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    flash("Logged out successfully.", "success")

    return redirect(url_for("login"))


# ---------------- DASHBOARD ----------------

@app.route("/")
@login_required
def home():

    files = []
    total_storage = 0
    recovery_files = []

    try:

        # Get current backup files
        paginator = s3.get_paginator("list_objects_v2")

        for page in paginator.paginate(
            Bucket=BUCKET_NAME,
            Prefix=user_prefix()
        ):

            for item in page.get("Contents", []):

                key = item["Key"]

                if key.endswith("/"):
                    continue

                size = item["Size"]
                total_storage += size

                filename = key.split("/")[-1]

                # Remove the UUID prefix from displayed filename
                if "_" in filename:
                    display_name = filename.split("_", 1)[1]
                else:
                    display_name = filename

                files.append({
                    "key": key,
                    "name": display_name,
                    "size": round(size / 1024, 2),
                    "date": item["LastModified"].strftime(
                        "%d-%m-%Y %H:%M"
                    )
                })

        # Sort newest files first
        files.sort(key=lambda x: x["date"], reverse=True)

        # Search
        search_query = request.args.get("search", "").strip().lower()

        if search_query:
            files = [
                file for file in files
                if search_query in file["name"].lower()
            ]

        # Get previous S3 object versions for recovery
        try:

            version_paginator = s3.get_paginator("list_object_versions")

            for page in version_paginator.paginate(
                Bucket=BUCKET_NAME,
                Prefix=user_prefix()
            ):

                for version in page.get("Versions", []):

                    key = version["Key"]

                    if key.endswith("/"):
                        continue

                    # Only show older versions, not the current one
                    if not version["IsLatest"]:

                        filename = key.split("/")[-1]

                        if "_" in filename:
                            display_name = filename.split("_", 1)[1]
                        else:
                            display_name = filename

                        recovery_files.append({
                            "key": key,
                            "version_id": version["VersionId"],
                            "name": display_name,
                            "date": version["LastModified"].strftime(
                                "%d-%m-%Y %H:%M"
                            ),
                            "size": round(version["Size"] / 1024, 2)
                        })

        except ClientError as error:
            app.logger.warning(
                "Could not load S3 versions: %s", error
            )

        storage_kb = round(total_storage / 1024, 2)
        storage_mb = round(total_storage / (1024 * 1024), 2)

        return render_template(
            "dashboard.html",
            files=files,
            username=session.get("username"),
            total_storage=storage_kb,
            storage_mb=storage_mb,
            recovery_files=recovery_files,
            search_query=search_query
        )

    except (NoCredentialsError, ClientError) as error:

        app.logger.exception("S3 dashboard error")

        flash("Unable to load S3 files. Check AWS credentials and permissions.", "error")

        return render_template(
            "dashboard.html",
            files=[],
            username=session.get("username"),
            total_storage=0,
            storage_mb=0,
            recovery_files=[],
            search_query=""
        )


# ---------------- UPLOAD ----------------

@app.route("/upload", methods=["POST"])
@login_required
def upload():

    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("home"))

    file = request.files["file"]

    if file.filename == "":
        flash("Please select a file.", "error")
        return redirect(url_for("home"))

    filename = secure_filename(file.filename)

    if not filename:
        flash("Invalid filename.", "error")
        return redirect(url_for("home"))

    unique_filename = f"{uuid.uuid4().hex}_{filename}"

    key = user_prefix() + unique_filename

    try:

        s3.upload_fileobj(
            file,
            BUCKET_NAME,
            key
        )

        flash("File uploaded successfully!", "success")

    except (NoCredentialsError, ClientError):

        app.logger.exception("Upload failed")
        flash("File upload failed. Check AWS permissions.", "error")

    return redirect(url_for("home"))


# ---------------- RESTORE / DOWNLOAD ONE FILE ----------------

@app.route("/restore/<path:key>")
@login_required
def restore(key):

    if not key.startswith(user_prefix()):
        flash("Access denied.", "error")
        return redirect(url_for("home"))

    try:

        file_data = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=key
        )

        filename = key.split("/")[-1]

        if "_" in filename:
            filename = filename.split("_", 1)[1]

        return send_file(
            BytesIO(file_data["Body"].read()),
            as_attachment=True,
            download_name=filename
        )

    except ClientError:

        app.logger.exception("Restore failed")
        flash("Unable to restore file.", "error")
        return redirect(url_for("home"))


# ---------------- DELETE ----------------

@app.route("/delete/<path:key>", methods=["POST"])
@login_required
def delete_file(key):

    if not key.startswith(user_prefix()):
        flash("Access denied.", "error")
        return redirect(url_for("home"))

    try:

        s3.delete_object(
            Bucket=BUCKET_NAME,
            Key=key
        )

        flash("Backup deleted successfully.", "success")

    except ClientError:

        app.logger.exception("Delete failed")
        flash("Unable to delete backup.", "error")

    return redirect(url_for("home"))


# ---------------- DOWNLOAD ALL AS ZIP ----------------

@app.route("/download-all")
@login_required
def download_all():

    memory_file = BytesIO()

    try:

        paginator = s3.get_paginator("list_objects_v2")

        with zipfile.ZipFile(
            memory_file,
            mode="w",
            compression=zipfile.ZIP_DEFLATED
        ) as zip_file:

            count = 0

            for page in paginator.paginate(
                Bucket=BUCKET_NAME,
                Prefix=user_prefix()
            ):

                for item in page.get("Contents", []):

                    key = item["Key"]

                    if key.endswith("/"):
                        continue

                    response = s3.get_object(
                        Bucket=BUCKET_NAME,
                        Key=key
                    )

                    filename = key.split("/")[-1]

                    if "_" in filename:
                        filename = filename.split("_", 1)[1]

                    # Avoid duplicate names in ZIP
                    zip_file.writestr(
                        f"{count + 1}_{filename}",
                        response["Body"].read()
                    )

                    count += 1

        if count == 0:
            flash("No files available to download.", "error")
            return redirect(url_for("home"))

        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype="application/zip",
            as_attachment=True,
            download_name="CloudSafe_Backups.zip"
        )

    except ClientError:

        app.logger.exception("Download all failed")
        flash("Unable to download backup files.", "error")
        return redirect(url_for("home"))


# ---------------- RECOVER PREVIOUS VERSION ----------------

@app.route("/recover", methods=["POST"])
@login_required
def recover_file():

    key = request.form.get("key", "")
    version_id = request.form.get("version_id", "")

    if not key.startswith(user_prefix()) or not version_id:
        flash("Invalid recovery request.", "error")
        return redirect(url_for("home"))

    try:

        # Copy the selected old version to the current object key.
        # This creates a new current version in a versioned bucket.
        s3.copy_object(
            Bucket=BUCKET_NAME,
            Key=key,
            CopySource={
                "Bucket": BUCKET_NAME,
                "Key": key,
                "VersionId": version_id
            }
        )

        flash("Previous file version recovered successfully!", "success")

    except ClientError:

        app.logger.exception("File recovery failed")
        flash(
            "Recovery failed. Check S3 versioning and IAM permissions.",
            "error"
        )

    return redirect(url_for("home"))


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":

    init_db()

    app.run(debug=True)