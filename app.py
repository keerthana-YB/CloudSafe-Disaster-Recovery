
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from werkzeug.utils import secure_filename
from io import BytesIO
import os

app = Flask(__name__)
app.secret_key = "cloudsafe-demo-key"

# AWS configuration
BUCKET_NAME = "cloud-disaster-recovery-backup-2026"
AWS_REGION = "ap-southeast-2"

s3 = boto3.client("s3", region_name=AWS_REGION)


@app.route("/")
def home():
    files = []

    try:
        if not BUCKET_NAME:
            raise ValueError("S3 bucket name is not configured")

        response = s3.list_objects_v2(Bucket=BUCKET_NAME)

        for item in response.get("Contents", []):
            files.append({
                "name": item["Key"],
                "size": round(item["Size"] / 1024, 2)
            })

    except Exception as e:
        flash(f"Cloud connection: {e}", "error")

    return render_template("index.html", files=files)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        flash("Please select a file.", "error")
        return redirect(url_for("home"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("home"))

    filename = secure_filename(file.filename)

    try:
        s3.upload_fileobj(file, BUCKET_NAME, filename)
        flash("File successfully backed up to AWS S3!", "success")

    except Exception as e:
        flash(f"Upload failed: {e}", "error")

    return redirect(url_for("home"))


@app.route("/restore/<path:filename>")
def restore_file(filename):
    try:
        data = BytesIO()
        s3.download_fileobj(BUCKET_NAME, filename, data)
        data.seek(0)

        return send_file(
            data,
            as_attachment=True,
            download_name=os.path.basename(filename)
        )

    except Exception as e:
        flash(f"Restore failed: {e}", "error")
        return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
