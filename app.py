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

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ───────────────────────── core config ─────────────────────────

HARDCODED_USERNAME = "user27"
EST_TZ = ZoneInfo("America/New_York")

# ───────────────────────── email config (SendGrid) ─────────────────────────
# NOTE: FROM_EMAIL_DEFAULT (and any task.email) must be verified / domain-authenticated in SendGrid.

FROM_EMAIL_DEFAULT = "citytrust@bskyakhargha1.help"  # default/fallback sender
TO_EMAIL = "kharghariaanupam07@gmail.com"            # hardcoded recipient
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")

# ───────────────────────── study sites set (for cert endpoint behavior) ─────────────────────────

STUDY_SITES = {
    # CityTrust family
    "citytrust.com", "cltytrust.com", "citytrustbank.com",
    # Meridian family
    "meridiansuites.com", "rneridiansuites.com", "meridiansuite.com",
    # CloudJet family
    "cloudjetairways.com", "cIoudjetairways.com", "cloudjetairway.com",
}

# ───────────────────────── study stage / blocklists ─────────────────────────
# STUDY_STAGE is a hardcoded global for now. Update to 2 or 3 as the study progresses.

def get_study_stage():
    try:
        with open("current_stage.txt", "r") as f:
            return int(f.read().strip())
    except:
        return 0

STUDY_STAGE = get_study_stage()  # ← change to 1, 2 or 3 when needed

# Blocklists by stage — hostnames only (no scheme). Lowercase.
STAGE_BLOCKLISTS = {
    0: set(),  # tutorial phase
    1: {"citytrust.com", "cltytrust.com", "citytrustbank.com"},
    2: {"meridiansuites.com", "rneridiansuites.com", "meridiansuite.com"},  # fill as needed
    3: {"cloudjetairways.com", "cIoudjet.com", "cloudjetairway.com"},  # fill as needed
}


def current_username() -> str:
    """Return the username for the current session (currently hardcoded)."""
    return HARDCODED_USERNAME


def now_est_iso() -> str:
    """Current time in America/New_York as ISO-8601 with offset (second precision)."""
    return dt.datetime.now(EST_TZ).isoformat(timespec="seconds")


def seconds_since_sent(sent_at_raw) -> float:
    """
    Compute how many seconds have elapsed since the assignment's sent_at time.

    sent_at_raw is typically a string like '2025-11-12 23:29:26'
    or '2025-11-12T23:29:26[.ffffff][±HH:MM]'.
    """
    if not sent_at_raw:
        return 0.0

    s = str(sent_at_raw)

    try:
        sent_dt = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            sent_dt = dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return 0.0

    if sent_dt.tzinfo is None:
        sent_dt = sent_dt.replace(tzinfo=EST_TZ)

    now = dt.datetime.now(EST_TZ)
    elapsed = (now - sent_dt).total_seconds()
    return max(elapsed, 0.0)


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


def has_open_cert_task_for_site(uid: int, hostname: str) -> bool:
    """
    True iff user has an open assignment whose task is a CERT phishing task
    and task.site_url matches hostname exactly.
    """
    rows = (
        supabase.table("assignments")
        .select("assignment_id, tasks(is_phishing, phishing_type, site_url)")
        .eq("user_id", uid)
        .is_("completed_at", "null")
        .limit(20)
        .execute()
        .data
    )

    for r in rows or []:
        t = r.get("tasks") or {}
        if (
            t.get("is_phishing") is True
            and str(t.get("phishing_type") or "").strip().upper() == "CERT"
            and str(t.get("site_url") or "") == hostname
        ):
            return True

    return False


# ───────────────────────── email helper (SendGrid) ─────────────────────────

def send_email(from_email: str | None, subject: str, html_content: str) -> bool:
    """
    Minimal SendGrid sender.

    from_email:
        - If provided, used as the sender (should come from tasks.email).
        - If None/empty, falls back to FROM_EMAIL_DEFAULT.
    """
    sender = (from_email or "").strip() or FROM_EMAIL_DEFAULT

    message = Mail(
        from_email=sender,
        to_emails=[TO_EMAIL],
        subject=subject,
        html_content=html_content,
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"SendGrid status={response.status_code} from={sender}")  # 202 on success
        return response.status_code == 202
    except Exception as e:
        print("SendGrid error:", str(e))
        return False


# ───────────────────────── stage quotas & task classification ─────────────────────────

def stage_quota(stage: int) -> dict:
    """
    CUMULATIVE quotas by stage.

    Stage 0 (Tutorial):  regular=3, url=1, email=1, cert=0  -> total 5
    Stage 1 increments:  regular=5, url=2, email=2, cert=1  -> cumulative 15
    Stage 2 increments:  regular=5, url=2, email=2, cert=1  -> cumulative 25
    Stage 3 increments:  regular=5, url=2, email=4, cert=1  -> cumulative 37
    """
    increments = {
        0: {"regular": 3, "url": 1, "email": 1, "cert": 0},
        1: {"regular": 5, "url": 2, "email": 2, "cert": 1},
        2: {"regular": 5, "url": 2, "email": 2, "cert": 1},
        3: {"regular": 5, "url": 2, "email": 4, "cert": 1},
    }
    total = {"regular": 0, "url": 0, "email": 0, "cert": 0}
    for s in range(0, max(0, min(3, stage)) + 1):
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
                "sent_at": now_est_iso(),
                "username": username,
            }
        )
        .execute()
        .data[0]
    )

    append_log(username, f"assigned '{pick['task_name']}' ({pick['site_url']})")

    email_html = pick.get("email_text")
    if email_html:
        subject = (pick.get("task_name") or "New study task").strip() or "New study task"
        task_from_email = (pick.get("email") or "").strip() or None

        sent_ok = send_email(task_from_email, subject, email_html)
        append_log(
            username,
            f"email_sent for task '{pick['task_name']}' "
            f"from='{task_from_email or FROM_EMAIL_DEFAULT}' ok={sent_ok}",
        )

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
        .select(
            "assignment_id, task_id, sent_at, login_occurred,"
            "tasks(task_name, site_url, task_type)"
        )
        .eq("user_id", uid)
        .is_("completed_at", "null")
        .limit(5)
        .execute()
        .data
    )

    print(f"[open_assignment_for_site] found {len(rows)} open rows for uid={uid!r}")

    for r in rows:
        tasks = r.get("tasks") or {}
        task_site = tasks.get("site_url")
        print(
            f"[open_assignment_for_site] candidate assignment_id={r.get('assignment_id')} "
            f"task_site={task_site!r}"
        )
        if tasks.get("site_url") == site_url:
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
    (Extra fields like user_id are ignored for compatibility.)
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
    Expected JSON: { "site_url": "<string>", ... }
    (Extra fields like user_id are ignored.)
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

    Payload (for compatibility): { "user_id": <anything> }  // ignored
    If a pending assignment already exists, returns 409 with
    {"error": "pending_assignment_exists"}.
    """
    _ = (request.get_json(silent=True) or {}).get("user_id")
    username = current_username()

    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    nxt = queue_random(uid, username=username)
    if not nxt:
        return jsonify({"error": "pending_assignment_exists"}), 409
    return jsonify({"status": "assigned", **nxt}), 200


# ───────────────────────── /complete-task ─────────────────────────

@app.route("/complete-task", methods=["POST"])
def complete_task():
    """
    Mark the current user's assignment for the given site_url as completed,
    record time taken (based on sent_at -> now), and immediately queue the next task (if any).

    Expected JSON:
      {
        "site_url": "<string>",
        "elapsed_ms": <number>,          # kept for compatibility but not used in timing
        "completion_type": "task_completed" | "reported_phishing"
        ... (extra fields allowed)
      }
    """
    d = request.get_json(silent=True) or {}
    site = d.get("site_url")
    elapsed_ms = d.get("elapsed_ms")
    ctype = d.get("completion_type")
    print("complete-task payload", site, ctype)

    if not (
        isinstance(site, str)
        and isinstance(elapsed_ms, (int, float))
        and ctype in ("task_completed", "reported_phishing")
    ):
        return jsonify({"error": "bad payload"}), 400

    username = current_username()
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        print("[/complete-task] no_pending_assignment — " f"uid={uid!r}, site={site!r}")
        return jsonify({"error": "no_pending_assignment"}), 409

    # Compute elapsed seconds based on sent_at and current time.
    sent_at_raw = row.get("sent_at")
    elapsed_sec = seconds_since_sent(sent_at_raw)

    (
        supabase.table("assignments")
        .update(
            {
                "completed_at": now_est_iso(),
                "time_taken": f"{elapsed_sec:.1f}s",
                "completion_type": ctype,
            }
        )
        .eq("assignment_id", row["assignment_id"])
        .execute()
    )

    append_log(
        username,
        f"finished '{row['tasks']['task_name']}' ({ctype}) in {elapsed_sec:.1f}s "
        f"(sent_at={sent_at_raw})",
    )

    nxt = queue_random(uid, username=username)
    return jsonify({"status": "completed", "next_task": nxt}), 200


# ───────────────────────── /current-task ─────────────────────────

@app.route("/current-task", methods=["POST"])
def current_task():
    """
    Return the current open assignment for this user + site_url, including task_type.

    Expected JSON:
      {
        "site_url": "<string>",
        "user_id": <anything>   # optional / ignored for compatibility
      }

    Response on success:
      {
        "assignment_id": <int>,
        "task_id": <int>,
        "task_name": "<str or null>",
        "task_type": "<str or null>",
        "site_url": "<str or null>"
      }
    """
    data = request.get_json(silent=True) or {}
    site = data.get("site_url")

    if not isinstance(site, str):
        return jsonify({"error": "bad_payload"}), 400

    username = current_username()
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    task = row.get("tasks") or {}
    return jsonify(
        {
            "assignment_id": row.get("assignment_id"),
            "task_id": row.get("task_id"),
            "task_name": task.get("task_name"),
            "task_type": task.get("task_type"),
            "site_url": task.get("site_url"),
        }
    ), 200


# ───────────────────────── /certificate_chain ─────────────────────────

def fetch_cert_chain(hostname: str, port: int = 443):
    """
    Fetch the TLS certificate chain for hostname:port using pyOpenSSL,
    returning a list of simplified certificate dicts.
    """
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

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
    For normal (non-study) sites: return real TLS cert chain.
    For study sites: return 0 by default, but return 1 if user has an open CERT task for this site.
    """
    host = (hostname or "").strip()

    username = current_username()
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404

    if host in STUDY_SITES:
        try:
            is_cert_task = has_open_cert_task_for_site(uid, host)
        except Exception as e:
            abort(502, description=f"DB error checking cert task: {e}")
        return jsonify({"status": True, "output": (1 if is_cert_task else 0)}), 200

    try:
        certs = fetch_cert_chain(host)
    except Exception as e:
        abort(502, description=f"Error fetching certificates: {e}")

    return jsonify({"status": True, "output": certs}), 200


# ───────────────────────── sanity / healthcheck ─────────────────────────

@app.route("/test")
def test():
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
