from flask import Flask, request, redirect, url_for, session, send_file, render_template_string
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import io
import subprocess
import threading
import requests
import smtplib
from email.mime.text import MIMEText
import time
from dotenv import load_dotenv
load_dotenv()

# ==== CONFIGURATION ====
SECRET_KEY = os.environ.get("SECRET_KEY")
PASSWORD = os.environ.get("PASSWORD")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY").encode()
cipher = Fernet(ENCRYPTION_KEY)

UPLOAD_FOLDER = os.path.abspath("encrypted_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

EMAIL_SENDER = os.environ.get("EMAIL_SENDER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.environ.get("EMAIL_RECEIVER")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# === HTML Templates ===
TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Secure File Server</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f4f6f8;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px;
      color: #333;
    }
    h2 { color: #444; }
    form { margin: 20px 0; }
    input[type="file"] { padding: 8px; }
    input[type="submit"], button {
      padding: 10px 16px;
      margin: 8px;
      font-size: 14px;
      cursor: pointer;
      border: none;
      border-radius: 6px;
      transition: background 0.3s ease;
    }
    input[type="submit"] {
      background-color: #2e86de;
      color: white;
    }
    input[type="submit"]:hover {
      background-color: #1b4f72;
    }
    button {
      background-color: #f0f0f0;
      color: #333;
    }
    button:hover {
      background-color: #ccc;
    }
    button[style*="color:red"] {
      background-color: #ff4d4d;
      color: white;
    }
    button[style*="color:red"]:hover {
      background-color: #cc0000;
    }
    ul {
      list-style: none;
      padding: 0;
      width: 100%;
      max-width: 500px;
    }
    li {
      background-color: white;
      padding: 10px 14px;
      margin: 6px 0;
      border-radius: 6px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    a {
      text-decoration: none;
      color: #2e86de;
      font-weight: bold;
    }
    a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <h2>Welcome, logged in!</h2>
  <form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <input type="submit" value="Upload">
  </form>
  <h2>Encrypted Files:</h2>
  <ul>
    {% for filename in files %}
      <li><a href="{{ url_for('download_file', filename=filename) }}">{{ filename }}</a></li>
    {% endfor %}
  </ul>
  <form method="post" action="/shutdown">
    <button style="color:red">Shutdown Server</button>
  </form>
  <form method="post" action="/logout">
    <button>Logout</button>
  </form>
</body>
</html>"""

LOGIN_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: #f4f6f8;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      color: #333;
    }
    h2 { margin-bottom: 20px; }
    form {
      background-color: white;
      padding: 30px 40px;
      border-radius: 10px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    input[type="password"] {
      padding: 10px;
      margin: 10px 0;
      width: 250px;
      font-size: 14px;
      border: 1px solid #ccc;
      border-radius: 6px;
    }
    input[type="submit"] {
      background-color: #2e86de;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-size: 14px;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    input[type="submit"]:hover {
      background-color: #1b4f72;
    }
  </style>
</head>
<body>
  <h2>Login</h2>
  <form method="post">
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
  </form>
</body>
</html>"""

# === ROUTES ===
@app.route('/', methods=['GET', 'POST'])
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_data = file.read()
            encrypted_data = cipher.encrypt(file_data)
            with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as f:
                f.write(encrypted_data)

    files = os.listdir(UPLOAD_FOLDER)
    return render_template_string(TEMPLATE, files=files)

@app.route('/files/<filename>')
def download_file(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    filepath = os.path.join(UPLOAD_FOLDER, secure_filename(filename))
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['password'] == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        return "❌ Not running with the Werkzeug Server"
    shutdown_func()
    return "🛡️ Server shutting down..."

# ==== EMAIL ====
def send_email(ngrok_url):
    msg = MIMEText(f"🌍 Your secure file server is online at:\n\n{ngrok_url}")
    msg["Subject"] = "Ngrok Server URL"
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("✅ Ngrok link sent via email!")
    except Exception as e:
        print("❌ Email sending failed:", e)

def start_ngrok_and_send_email():
    subprocess.Popen(["C:/ngrok/ngrok.exe", "http", "8000"], stdout=subprocess.DEVNULL)
    time.sleep(5)
    try:
        tunnel_info = requests.get("http://127.0.0.1:4040/api/tunnels").json()
        public_url = tunnel_info['tunnels'][0]['public_url']
        print(f"\n🌍 Your server is online at: {public_url}")
        send_email(public_url)
    except Exception as e:
        print("⚠️ Failed to get ngrok tunnel info or send email:", e)

# ==== MAIN ====
if __name__ == '__main__':
    print(f"🔐 Fixed encryption key: {ENCRYPTION_KEY.decode()}")
    threading.Thread(target=start_ngrok_and_send_email, daemon=True).start()
    app.run(port=8000)
