
from flask import Flask, request, render_template_string
import json
import os
from datetime import datetime, timezone

app = Flask(__name__)

LOG_DIR = "var/log/webhoneypot"
LOG_FILE = os.path.join(LOG_DIR, "events.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Staff Portal</title>
</head>
<body>
  <h2>Staff Portal</h2>
  <form method="post" action="/login">
    <label>Username <input name="username" required></label><br><br>
    <label>Password <input name="password" type="password" required></label><br><br>
    <button type="submit">Sign in</button>
  </form>
  <p>{{ message }}</p>
</body>
</html>
"""

def log_event(event_type, username=""):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "username": username[:100],
        "user_agent": request.headers.get("User-Agent", "")[:200]
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

@app.get("/")
def index():
    log_event("page_view")
    return render_template_string(PAGE, message="")

@app.post("/login")
def login():
    username = request.form.get("username", "")
    log_event("login_attempt", username)
    return render_template_string(
        PAGE, message="Demo only: sign-in is disabled."
    ), 401

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)
