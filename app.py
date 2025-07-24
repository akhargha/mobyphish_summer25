# app.py  ─ logging • login-event • completion • random assignment
import os, random, string, datetime as dt
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from supabase import create_client, Client
from OpenSSL import SSL
import socket
from datetime import datetime

app = Flask(__name__)
CORS(app, origins="*", methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ───────────────────────── helpers ─────────────────────────
def append_log(uid: str, line: str):
    """Append a log entry to the user's log_text field"""
    cur = supabase.table("users").select("log_text").eq("username", uid).limit(1).execute().data
    if not cur:
        return
    existing = cur[0]["log_text"] or ""
    body = (existing + "\n" if existing.strip() else "") + line
    supabase.table("users").update({"log_text": body}).eq("username", uid).execute()

def get_user_id(username: str):
    """Get the user ID from username"""
    result = supabase.table("users").select("id").eq("username", username).limit(1).execute().data
    return result[0]["id"] if result else None

def unseen_task_for(uid: int):
    """Get a random unseen task for the user"""
    seen = {r["task_id"] for r in supabase.table("assignments")
                                    .select("task_id")
                                    .eq("user_id", uid).execute().data}
    pool = [t for t in supabase.table("tasks").select("*").execute().data
            if t["task_id"] not in seen]
    return random.choice(pool) if pool else None

def queue_random(uid: int):
    """Queue a random task for the user if no assignment is pending"""
    # stop if an assignment is still open
    if supabase.table("assignments").select("assignment_id") \
         .eq("user_id", uid).is_("completed_at", "null") \
         .execute().data:
        return None
    pick = unseen_task_for(uid)
    if not pick:
        return None
    now = dt.datetime.utcnow().isoformat()
    
    # Get username for logging
    user_result = supabase.table("users").select("username").eq("id", uid).limit(1).execute().data
    username = user_result[0]["username"] if user_result else str(uid)
    
    row = supabase.table("assignments").insert({
        "user_id": uid,
        "task_id": pick["task_id"],
        "sent_at": now,
        "username": username
    }).execute().data[0]
    
    append_log(username, f"{now}  assigned '{pick['task_name']}' ({pick['site_url']})")
    return {"assignment_id": row["assignment_id"],
            "task_name":   pick["task_name"],
            "site_url":    pick["site_url"]}

def open_assignment_for_site(uid: int, site_url: str):
    """
    Return the OPEN assignment for this user whose task.site_url matches site_url.
    """
    rows = (supabase.table("assignments")
            .select("assignment_id, task_id, sent_at, login_occurred,"
                    "tasks(task_name, site_url)")
            .eq("user_id", uid)
            .is_("completed_at", "null")
            .limit(5)                 # small buffer
            .execute().data)

    for r in rows:
        if r["tasks"]["site_url"] == site_url:
            return r
    return None

# ───────────────────────── CORS pre-flight ─────────────────────────
@app.before_request
def preflight():
    if request.method == "OPTIONS":
        r = jsonify({})
        r.headers["Access-Control-Allow-Origin"]  = "*"
        r.headers["Access-Control-Allow-Headers"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "*"
        return r

# ───────────────────────── /log ─────────────────────────
@app.route("/log", methods=["POST"])
def log_route():
    """Log a message for a user"""
    b = request.get_json(silent=True) or {}
    username, text = b.get("user_id"), b.get("text")
    if not (isinstance(username, str) and isinstance(text, str)):
        return jsonify({"error": "bad payload"}), 400
    append_log(username, text)
    return jsonify({"status": "logged"}), 200

# ───────────────────────── /login-event ─────────────────────────
@app.route("/login-event", methods=["POST"])
def login_event():
    """Mark that a user has logged into a site"""
    data = request.get_json(silent=True) or {}
    username, site = data.get("user_id"), data.get("site_url")
    if not (isinstance(username, str) and isinstance(site, str)):
        return jsonify({"error": "bad payload"}), 400

    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    if not row["login_occurred"]:
        supabase.table("assignments").update({"login_occurred": True}) \
                .eq("assignment_id", row["assignment_id"]).execute()
        append_log(username, f"{dt.datetime.utcnow().isoformat()}  login on '{site}'")

    return jsonify({"status": "marked"}), 200

# ───────────────────────── /assign-random ─────────────────────────
@app.route("/assign-random", methods=["POST"])
def assign_random():
    """Assign a random task to a user"""
    username = (request.get_json(silent=True) or {}).get("user_id")
    if not isinstance(username, str):
        return jsonify({"error": "user_id string required"}), 400
    
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404
    
    nxt = queue_random(uid)
    if not nxt:
        return jsonify({"error": "pending_assignment_exists"}), 409
    return jsonify({"status": "assigned", **nxt}), 200

# ───────────────────────── /complete-task ─────────────────────────
@app.route("/complete-task", methods=["POST"])
def complete_task():
    """Mark a task as completed"""
    d = request.get_json(silent=True) or {}
    username, site = d.get("user_id"), d.get("site_url")
    elapsed, ctype = d.get("elapsed_ms"), d.get("completion_type")

    if not (isinstance(username, str) and isinstance(site, str)
            and isinstance(elapsed, (int, float))
            and ctype in ("task_completed", "reported_phishing")):
        return jsonify({"error": "bad payload"}), 400

    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    now = dt.datetime.utcnow().isoformat()
    supabase.table("assignments").update({
            "completed_at": now,
            "time_taken":   f"{elapsed/1000:.1f}s",
            "completion_type": ctype}) \
        .eq("assignment_id", row["assignment_id"]).execute()

    append_log(username,
        f"{now}  finished '{row['tasks']['task_name']}' "
        f"({ctype}) in {elapsed/1000:.1f}s")

    nxt = queue_random(uid)
    return jsonify({"status": "completed", "next_task": nxt}), 200

# ───────────────────────── /certificate_chain ─────────────────────────
def fetch_cert_chain(hostname: str, port: int = 443):
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(hostname.encode()) 
    conn.connect((hostname, port))
    conn.setblocking(True)
    conn.do_handshake()

    # Retrieve the full chain
    chain = conn.get_peer_cert_chain()
    conn.close()

    certs = []
    for cert in chain:
        x509 = cert.to_cryptography()

        certs.append({
            "subject": {attr.oid._name: attr.value for attr in x509.subject},
            "issuer":  {attr.oid._name: attr.value for attr in x509.issuer},
            "serial_number": format(x509.serial_number, 'x'),
            "version": x509.version.name,
            "not_before": x509.not_valid_before.isoformat(),
            "not_after":  x509.not_valid_after.isoformat(),
        })
    return certs

@app.route("/certificate_chain/<path:hostname>")
def certificate_chain(hostname):
    try:
        certs = fetch_cert_chain(hostname)
    except Exception as e:
        # Could not connect / handshake / parse
        abort(502, description=f"Error fetching certificates: {e}")
    return jsonify(certs)
# ───────────────────────── sanity ─────────────────────────
@app.route("/test")
def test(): 
    """Test endpoint"""
    return jsonify({"utc": dt.datetime.utcnow().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
