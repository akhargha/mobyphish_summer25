# app.py — Flask backend for study logging, task assignment, and certificate inspection.

import os
import random
import string
import datetime as dt
import socket
from zoneinfo import ZoneInfo
from urllib.parse import urlparse

from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from supabase import create_client, Client
from OpenSSL import SSL
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ───────────────────────── Flask / Supabase setup ─────────────────────────

app = Flask(__name__)
CORS(
    app,
    origins="*",
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ───────────────────────── core config ─────────────────────────

HARDCODED_USERNAME = "user27"
EST_TZ = ZoneInfo("America/New_York")

# ───────────────────────── email config (SendGrid) ─────────────────────────
# NOTE: FROM_EMAIL must be a verified / domain-authenticated sender in SendGrid.

FROM_EMAIL = "citytrust@bskyakhargha1.help"  # hardcoded sender
TO_EMAIL = "kharghariaanupam07@gmail.com"    # hardcoded recipient
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

# ───────────────────────── study stage / blocklists ─────────────────────────
# STUDY_STAGE is a hardcoded global for now. Update to 2 or 3 as the study progresses.

STUDY_STAGE = 1  # ← change to 2 or 3 when needed

# Blocklists by stage — hostnames only (no scheme). Lowercase.
STAGE_BLOCKLISTS = {
    1: {},
    2: {"citytrust.com", "cltytrust.com", "citytrustbank.com"},  # fill as needed
    3: {"citytrust.com", "cltytrust.com", "citytrustbank.com"},  # fill as needed
}

# ───────────────────────── basic helpers ─────────────────────────


def current_username() -> str:
    """Return the username for the current session (currently hardcoded)."""
    return HARDCODED_USERNAME


def now_est_iso() -> str:
    """Current time in America/New_York as ISO-8601 with offset (second precision)."""
    return dt.datetime.now(EST_TZ).isoformat(timespec="seconds")


# ───────────────────────── URL helpers (stage filtering) ─────────────────────────


def normalize_host(url_or_host: str) -> str:
    """
    Return the hostname for equality checks.

    Accepts bare domains ('example.com') or URLs ('https://example.com/path').
    Returns a lowercase hostname with any leading '.' stripped.
    """
    if not isinstance(url_or_host, str):
        return ""
    s = url_or_host.strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    try:
        host = urlparse(s).hostname or ""
        return host.lstrip(".")
    except Exception:
        # Fallback: strip and normalize as best-effort.
        return url_or_host.strip().lower().lstrip(".")


def is_blocked_for_stage(site_url: str) -> bool:
    """Check if the given site_url is in the blocklist for the current stage."""
    blockset = STAGE_BLOCKLISTS.get(STUDY_STAGE, set())
    host = normalize_host(site_url)
    return host in blockset


# ───────────────────────── database helpers (logging / users) ─────────────────────────


def append_log(uid: str, line: str):
    """
    Append a log entry (with EST ISO timestamp) to the user's log_text field
    in the users table.
    """
    cur = (
        supabase.table("users")
        .select("log_text")
        .eq("username", uid)
        .limit(1)
        .execute()
        .data
    )
    if not cur:
        return

    stamp = now_est_iso()
    entry = f"{stamp}  {line}"
    existing = cur[0]["log_text"] or ""
    body = (existing + "\n" if existing.strip() else "") + entry

    supabase.table("users").update({"log_text": body}).eq("username", uid).execute()


def get_user_id(username: str):
    """Return numeric user id for the given username, or None if not found."""
    result = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
        .data
    )
    return result[0]["id"] if result else None


# ───────────────────────── email helper (SendGrid) ─────────────────────────


def send_email(subject: str, html_content: str) -> bool:
    """
    Minimal SendGrid sender: uses hardcoded FROM/TO and API key from .env.

    Returns True if SendGrid responds with HTTP 202 (Accepted), otherwise False.
    """
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=[TO_EMAIL],
        subject=subject,
        html_content=html_content,
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print("Status:", response.status_code)  # 202 on success
        return response.status_code == 202
    except Exception as e:
        print("SendGrid error:", str(e))
        return False


# ───────────────────────── stage quotas & task classification ─────────────────────────


def stage_quota(stage: int) -> dict:
    """
    CUMULATIVE quotas by stage.

    Stage 1 increments:  regular=5, url=2, email=2, cert=1  -> total 10
    Stage 2 increments:  regular=5, url=2, email=2, cert=1  -> cumulative 20
    Stage 3 increments:  regular=5, url=2, email=4, cert=1  -> cumulative 32
    """
    increments = {
        1: {"regular": 5, "url": 2, "email": 2, "cert": 1},
        2: {"regular": 5, "url": 2, "email": 2, "cert": 1},
        3: {"regular": 5, "url": 2, "email": 4, "cert": 1},
    }
    total = {"regular": 0, "url": 0, "email": 0, "cert": 0}
    for s in range(1, max(1, min(3, stage)) + 1):
        inc = increments[s]
        total["regular"] += inc["regular"]
        total["url"] += inc["url"]
        total["email"] += inc["email"]
        total["cert"] += inc["cert"]
    return total


def classify_task(task: dict) -> str | None:
    """
    Map a task row to a category: 'regular' | 'url' | 'email' | 'cert' | None.
    """
    is_phish = bool(task.get("is_phishing"))
    ptype = (task.get("phishing_type") or "").strip().upper()

    if not is_phish:
        return "regular"
    if ptype == "URL":
        return "url"
    if ptype == "EMAIL":
        return "email"
    if ptype == "CERT":
        return "cert"
    return None


def task_matches_stage_category(task: dict, category: str) -> bool:
    """
    Apply blocklist rules per category for current stage:

      - regular/url/email: site_url must NOT be in blocklist
      - cert:              site_url MUST be in blocklist
    """
    site = task.get("site_url", "")
    blocked = is_blocked_for_stage(site)

    if category == "cert":
        return blocked
    else:
        # regular/url/email
        return not blocked


def get_user_seen_task_ids(uid: int) -> set[int]:
    """
    Return a set of task_ids that have been assigned to the user (any stage).
    Note: duplicates are allowed in assignment logic; this function is not used
    to filter them out anymore.
    """
    rows = (
        supabase.table("assignments")
        .select("task_id")
        .eq("user_id", uid)
        .execute()
        .data
    )
    return {r["task_id"] for r in rows if r.get("task_id") is not None}


def counts_for_stage(uid: int) -> dict:
    """
    Count how many assignments (already assigned) for the current stage buckets.

    Uses current stage blocklist rules to decide which assigned tasks count
    toward current stage quotas. This allows flipping STUDY_STAGE later and
    getting fresh counts for the new stage.
    """
    rows = (
        supabase.table("assignments")
        .select("task_id, tasks(is_phishing, phishing_type, site_url)")
        .eq("user_id", uid)
        .execute()
        .data
    )

    counts = {"regular": 0, "url": 0, "email": 0, "cert": 0}
    for r in rows:
        t = r.get("tasks") or {}
        cat = classify_task(t)
        if cat and task_matches_stage_category(t, cat):
            counts[cat] += 1
    return counts


def unseen_task_for(uid: int):
    """
    Return ONE task that advances current stage quotas.

    Duplicates are allowed: we do NOT filter out tasks previously assigned.

    Selection order:
      - Choose a category that still has remaining quota (random among remaining)
      - From that category, pick randomly from tasks that satisfy stage rules
      - If none available in that category, try other remaining categories
    """
    desired = stage_quota(STUDY_STAGE)
    current = counts_for_stage(uid)
    remaining = {k: max(desired[k] - current.get(k, 0), 0) for k in desired}

    # All quotas satisfied.
    if sum(remaining.values()) == 0:
        return None

    all_tasks = supabase.table("tasks").select("*").execute().data

    def pool_for(category: str) -> list[dict]:
        return [
            t
            for t in all_tasks
            if classify_task(t) == category and task_matches_stage_category(t, category)
        ]

    categories = [k for k, v in remaining.items() if v > 0]
    random.shuffle(categories)

    for cat in categories:
        pool = pool_for(cat)
        if pool:
            return random.choice(pool)

    return None


def queue_random(uid: int, username: str | None = None):
    """
    Queue a random task for the user if no assignment is pending.

    - Honors per-stage quotas.
    - Writes an assignment row.
    - Optionally sends an email if the task has email_text.
    """
    # Do not queue a new one if there is already a pending assignment
    if (
        supabase.table("assignments")
        .select("assignment_id")
        .eq("user_id", uid)
        .is_("completed_at", "null")
        .execute()
        .data
    ):
        return None

    pick = unseen_task_for(uid)
    if not pick:
        return None

    # Resolve username if not passed in
    if username is None:
        user_result = (
            supabase.table("users")
            .select("username")
            .eq("id", uid)
            .limit(1)
            .execute()
            .data
        )
        username = user_result[0]["username"] if user_result else str(uid)

    # Insert assignment row
    row = (
        supabase.table("assignments")
        .insert(
            {
                "user_id": uid,
                "task_id": pick["task_id"],
                "sent_at": now_est_iso(),  # EST ISO
                "username": username,
            }
        )
        .execute()
        .data[0]
    )

    append_log(username, f"assigned '{pick['task_name']}' ({pick['site_url']})")

    # If this task has email_text, send an email representation of it.
    email_html = pick.get("email_text")
    if email_html:
        subject = (pick.get("task_name") or "New study task").strip() or "New study task"
        sent_ok = send_email(subject, email_html)
        append_log(username, f"email_sent for task '{pick['task_name']}' ok={sent_ok}")

    # Response payload back to the caller
    return {
        "assignment_id": row["assignment_id"],
        "task_name": pick["task_name"],
        "site_url": pick["site_url"],
    }


def open_assignment_for_site(uid: int, site_url: str):
    """
    Return the open (not completed) assignment row for this user and site_url,
    or None if no such assignment exists.
    """
    rows = (
        supabase.table("assignments")
        .select("assignment_id, task_id, sent_at, login_occurred,"
                "tasks(task_name, site_url)")
        .eq("user_id", uid)
        .is_("completed_at", "null")
        .limit(5)
        .execute()
        .data
    )
    for r in rows:
        if r["tasks"]["site_url"] == site_url:
            return r
    return None


# ───────────────────────── CORS pre-flight ─────────────────────────


@app.before_request
def preflight():
    """Handle CORS pre-flight OPTIONS requests."""
    if request.method == "OPTIONS":
        r = jsonify({})
        r.headers["Access-Control-Allow-Origin"] = "*"
        r.headers["Access-Control-Allow-Headers"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "*"
        return r


# ───────────────────────── /log ─────────────────────────


@app.route("/log", methods=["POST"])
def log_route():
    """
    Append an arbitrary log message to the current user's log_text field.
    Expected JSON: { "text": "<string>" }
    """
    b = request.get_json(silent=True) or {}
    text = b.get("text")
    if not isinstance(text, str):
        return jsonify({"error": "bad payload"}), 400
    append_log(current_username(), text)
    return jsonify({"status": "logged"}), 200


# ───────────────────────── /login-event ─────────────────────────


@app.route("/login-event", methods=["POST"])
def login_event():
    """
    Mark that a login event occurred for the current user's pending assignment
    with the given site_url.
    """
    data = request.get_json(silent=True) or {}
    site = data.get("site_url")
    if not isinstance(site, str):
        return jsonify({"error": "bad payload"}), 400

    username = current_username()
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    if not row["login_occurred"]:
        (
            supabase.table("assignments")
            .update({"login_occurred": True})
            .eq("assignment_id", row["assignment_id"])
            .execute()
        )
        append_log(username, f"login on '{site}'")

    return jsonify({"status": "marked"}), 200


# ───────────────────────── /assign-random ─────────────────────────


@app.route("/assign-random", methods=["POST"])
def assign_random():
    """
    Assign a random task for the current user, respecting per-stage quotas.
    If a pending assignment already exists, returns 409 with
    {"error": "pending_assignment_exists"}.
    """
    _ = (request.get_json(silent=True) or {}).get("user_id")  # kept for compatibility
    username = current_username()

    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    nxt = queue_random(uid, username=username)
    if not nxt:
        # To preserve compatibility, keep the same error for "no more tasks" or "pending exists".
        return jsonify({"error": "pending_assignment_exists"}), 409
    return jsonify({"status": "assigned", **nxt}), 200


# ───────────────────────── /complete-task ─────────────────────────


@app.route("/complete-task", methods=["POST"])
def complete_task():
    """
    Mark the current user's assignment for the given site_url as completed,
    record time taken, and immediately queue the next task (if any).
    """
    d = request.get_json(silent=True) or {}
    site = d.get("site_url")
    elapsed, ctype = d.get("elapsed_ms"), d.get("completion_type")

    if not (
        isinstance(site, str)
        and isinstance(elapsed, (int, float))
        and ctype in ("task_completed", "reported_phishing")
    ):
        return jsonify({"error": "bad payload"}), 400

    username = current_username()
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    (
        supabase.table("assignments")
        .update(
            {
                "completed_at": now_est_iso(),  # EST ISO
                "time_taken": f"{elapsed/1000:.1f}s",
                "completion_type": ctype,
            }
        )
        .eq("assignment_id", row["assignment_id"])
        .execute()
    )

    append_log(
        username,
        f"finished '{row['tasks']['task_name']}' ({ctype}) in {elapsed/1000:.1f}s",
    )

    nxt = queue_random(uid, username=username)
    return jsonify({"status": "completed", "next_task": nxt}), 200


# ───────────────────────── /certificate_chain ─────────────────────────


def fetch_cert_chain(hostname: str, port: int = 443):
    """
    Fetch the TLS certificate chain for the given hostname:port using pyOpenSSL,
    returning a list of simplified certificate dicts.
    """
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = SSL.Connection(ctx, sock)
    conn.set_tlsext_host_name(hostname.encode())
    conn.connect((hostname, port))
    conn.setblocking(True)
    conn.do_handshake()

    chain = conn.get_peer_cert_chain()
    conn.close()

    certs = []
    for cert in chain:
        x509 = cert.to_cryptography()
        certs.append(
            {
                "subject": {attr.oid._name: attr.value for attr in x509.subject},
                "issuer": {attr.oid._name: attr.value for attr in x509.issuer},
                "serial_number": format(x509.serial_number, "x"),
                "version": x509.version.name,
                "not_before": x509.not_valid_before.isoformat(),
                "not_after": x509.not_valid_after.isoformat(),
            }
        )
    return certs


@app.route("/certificate_chain/<path:hostname>")
def certificate_chain(hostname):
    """
    Return the TLS certificate chain for the given hostname as JSON.
    """
    try:
        certs = fetch_cert_chain(hostname)
    except Exception as e:
        abort(502, description=f"Error fetching certificates: {e}")
    return jsonify({"status": True, "output": certs})


# ───────────────────────── sanity / healthcheck ─────────────────────────


@app.route("/test")
def test():
    """Simple sanity endpoint to verify server time, user, and stage."""
    return jsonify(
        {
            "est": now_est_iso(),
            "user": current_username(),
            "study_stage": STUDY_STAGE,
        }
    )


# ───────────────────────── main entrypoint ─────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)