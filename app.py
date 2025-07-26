# # app.py  ─ logging • login-event • completion • random assignment • user creation
# import os, random, string, datetime as dt
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# from supabase import create_client, Client

# app = Flask(__name__)
# CORS(app, origins="*", methods=["GET", "POST", "OPTIONS"],
#      allow_headers=["Content-Type", "Authorization"])

# SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_KEY = os.getenv("SUPABASE_KEY")
# supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# # ───────────────────────── helpers ─────────────────────────
# def append_log(uid: int, line: str):
#     cur = supabase.table("users").select("log_text").eq("id", uid).limit(1).execute().data
#     if not cur:
#         return
#     existing = cur[0]["log_text"] or ""
#     body = (existing + "\n" if existing.strip() else "") + line
#     supabase.table("users").update({"log_text": body}).eq("id", uid).execute()

# def unseen_task_for(uid: int):
#     seen = {r["task_id"] for r in supabase.table("assignments")
#                                     .select("task_id")
#                                     .eq("user_id", uid).execute().data}
#     pool = [t for t in supabase.table("tasks").select("*").execute().data
#             if t["task_id"] not in seen]
#     return random.choice(pool) if pool else None

# def queue_random(uid: int):
#     # stop if an assignment is still open
#     if supabase.table("assignments").select("assignment_id") \
#          .eq("user_id", uid).is_("completed_at", "null") \
#          .execute().data:
#         return None

#     pick = unseen_task_for(uid)
#     if not pick:
#         return None

#     now = dt.datetime.utcnow().isoformat()
#     row = supabase.table("assignments").insert({
#         "user_id": uid,
#         "task_id": pick["task_id"],
#         "sent_at": now
#     }).execute().data[0]

#     append_log(uid, f"{now}  assigned '{pick['task_name']}' ({pick['site_url']})")
#     return {"assignment_id": row["assignment_id"],
#             "task_name":   pick["task_name"],
#             "site_url":    pick["site_url"]}

# def open_assignment_for_site(uid: int, site_url: str):
#     """
#     Return the OPEN assignment for this user whose task.site_url matches site_url.
#     """
#     rows = (supabase.table("assignments")
#             .select("assignment_id, task_id, sent_at, login_occurred,"
#                     "tasks(task_name, site_url)")
#             .eq("user_id", uid)
#             .is_("completed_at", "null")
#             .limit(5)                 # small buffer
#             .execute().data)

#     for r in rows:
#         if r["tasks"]["site_url"] == site_url:
#             return r
#     return None

# def generate_random_password(length=6):
#     chars = string.ascii_letters + string.digits
#     return ''.join(random.choices(chars, k=length))

# # ───────────────────────── CORS pre-flight ─────────────────────────
# @app.before_request
# def preflight():
#     if request.method == "OPTIONS":
#         r = jsonify({})
#         r.headers["Access-Control-Allow-Origin"]  = "*"
#         r.headers["Access-Control-Allow-Headers"] = "*"
#         r.headers["Access-Control-Allow-Methods"] = "*"
#         return r

# # ───────────────────────── /create-user ─────────────────────────
# @app.route("/create-user", methods=["POST"])
# def create_user():
#     data = request.get_json(silent=True) or {}
#     email = data.get("email")
#     if not isinstance(email, str) or "@" not in email:
#         return jsonify({"error": "valid email required"}), 400

#     # Check if user exists
#     existing = supabase.table("users").select("*").eq("email", email).execute().data
#     if existing:
#         return jsonify({"error": "user already exists"}), 409

#     # Generate username and password
#     username = "user_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
#     password = generate_random_password()

#     # Insert into users table
#     row = supabase.table("users").insert({
#         "email": email,
#         "username": username,
#         "password": password,
#         "log_text": ""
#     }).execute().data[0]

#     append_log(row["id"], f"{dt.datetime.utcnow().isoformat()}  user created")

#     # Return the credentials (so Qualtrics can email/display them)
#     return jsonify({
#         "user_id": row["id"],
#         "username": username,
#         "password": password
#     }), 201

# # ───────────────────────── /verify-login ─────────────────────────
# @app.route("/verify-login", methods=["POST"])
# def verify_login():
#     d = request.get_json(silent=True) or {}
#     username = d.get("username", "").strip().lower()
#     password = d.get("password", "").strip()

#     if not username or not password:
#         return jsonify({"error": "username and password are required"}), 400

#     res = supabase.table("users").select("id, username, password") \
#         .eq("username", username).limit(1).execute().data

#     if not res:
#         return jsonify({"error": "invalid username"}), 401

#     user = res[0]
#     if user["password"] != password:
#         return jsonify({"error": "invalid password"}), 401

#     return jsonify({"user_id": user["id"]}), 200


# # ───────────────────────── /log ─────────────────────────
# @app.route("/log", methods=["POST"])
# def log_route():
#     b = request.get_json(silent=True) or {}
#     uid, text = b.get("user_id"), b.get("text")
#     if not (isinstance(uid, int) and isinstance(text, str)):
#         return jsonify({"error": "bad payload"}), 400
#     append_log(uid, text)
#     return jsonify({"status": "logged"}), 200

# # ───────────────────────── /login-event ─────────────────────────
# @app.route("/login-event", methods=["POST"])
# def login_event():
#     data = request.get_json(silent=True) or {}
#     uid, site = data.get("user_id"), data.get("site_url")
#     if not (isinstance(uid, int) and isinstance(site, str)):
#         return jsonify({"error": "bad payload"}), 400

#     row = open_assignment_for_site(uid, site)
#     if not row:
#         return jsonify({"error": "no_pending_assignment"}), 409

#     if not row["login_occurred"]:
#         supabase.table("assignments").update({"login_occurred": True}) \
#                 .eq("assignment_id", row["assignment_id"]).execute()
#         append_log(uid, f"{dt.datetime.utcnow().isoformat()}  login on '{site}'")

#     return jsonify({"status": "marked"}), 200

# # ───────────────────────── /assign-random ─────────────────────────
# @app.route("/assign-random", methods=["POST"])
# def assign_random():
#     uid = (request.get_json(silent=True) or {}).get("user_id")
#     if not isinstance(uid, int):
#         return jsonify({"error": "user_id int required"}), 400
#     nxt = queue_random(uid)
#     if not nxt:
#         return jsonify({"error": "pending_assignment_exists"}), 409
#     return jsonify({"status": "assigned", **nxt}), 200

# # ───────────────────────── /complete-task ─────────────────────────
# @app.route("/complete-task", methods=["POST"])
# def complete_task():
#     d = request.get_json(silent=True) or {}
#     uid, site = d.get("user_id"), d.get("site_url")
#     elapsed, ctype = d.get("elapsed_ms"), d.get("completion_type")

#     if not (isinstance(uid, int) and isinstance(site, str)
#             and isinstance(elapsed, (int, float))
#             and ctype in ("task_completed", "reported_phishing")):
#         return jsonify({"error": "bad payload"}), 400

#     row = open_assignment_for_site(uid, site)
#     if not row:
#         return jsonify({"error": "no_pending_assignment"}), 409

#     now = dt.datetime.utcnow().isoformat()
#     supabase.table("assignments").update({
#             "completed_at": now,
#             "time_taken":   f"{elapsed/1000:.1f}s",
#             "completion_type": ctype}) \
#         .eq("assignment_id", row["assignment_id"]).execute()

#     append_log(uid,
#         f"{now}  finished '{row['tasks']['task_name']}' "
#         f"({ctype}) in {elapsed/1000:.1f}s")

#     nxt = queue_random(uid)
#     return jsonify({"status": "completed", "next_task": nxt}), 200

# # ───────────────────────── sanity ─────────────────────────
# @app.route("/test")
# def test(): return jsonify({"utc": dt.datetime.utcnow().isoformat()})

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5001, debug=True)

# app.py - Improved Flask backend with Supabase best practices
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
import random
import string
import datetime as dt
import logging
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from postgrest.exceptions import APIError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins="*", methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    logger.error("SUPABASE_URL and SUPABASE_KEY environment variables are required")
    raise ValueError("Missing required environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ───────────────────────── Error Handling Decorator ─────────────────────────
def handle_db_errors(f):
    """Decorator to handle database errors gracefully"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except APIError as e:
            logger.error(f"Database error in {f.__name__}: {e}")
            return jsonify({"error": "database_error", "message": str(e)}), 500
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {e}")
            return jsonify({"error": "internal_error", "message": "An unexpected error occurred"}), 500
    return decorated_function

# ───────────────────────── Input Validation ─────────────────────────
def validate_email(email):
    """Basic email validation"""
    if not isinstance(email, str) or "@" not in email or len(email) < 5:
        return False
    return True

def validate_user_id(user_id):
    """Validate user_id is a positive integer"""
    return isinstance(user_id, int) and user_id > 0

def validate_site_url(site_url):
    """Basic URL validation"""
    return isinstance(site_url, str) and len(site_url.strip()) > 0

# ───────────────────────── Helper Functions ─────────────────────────
def append_log(uid: int, line: str):
    """Append a log entry to user's log_text with error handling"""
    try:
        # Get current log text
        result = supabase.table("users").select("log_text").eq("id", uid).limit(1).execute()
        
        if not result.data:
            logger.warning(f"User {uid} not found when appending log")
            return False
            
        existing = result.data[0]["log_text"] or ""
        body = (existing + "\n" if existing.strip() else "") + line
        
        # Update log text
        supabase.table("users").update({"log_text": body}).eq("id", uid).execute()
        logger.info(f"Log appended for user {uid}: {line}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to append log for user {uid}: {e}")
        return False

def get_unseen_tasks(uid: int):
    """Get list of tasks not yet assigned to user"""
    try:
        # Get all task IDs assigned to user
        assigned_result = supabase.table("assignments") \
            .select("task_id") \
            .eq("user_id", uid) \
            .execute()
        
        seen_task_ids = {r["task_id"] for r in assigned_result.data}
        logger.info(f"User {uid} has seen {len(seen_task_ids)} tasks")
        
        # Get all available tasks
        all_tasks_result = supabase.table("tasks").select("*").execute()
        all_tasks = all_tasks_result.data
        logger.info(f"Total tasks in database: {len(all_tasks)}")
        
        # Filter to unseen tasks
        unseen_tasks = [task for task in all_tasks if task["task_id"] not in seen_task_ids]
        logger.info(f"User {uid} has {len(unseen_tasks)} unseen tasks")
        
        return unseen_tasks
        
    except Exception as e:
        logger.error(f"Error getting unseen tasks for user {uid}: {e}")
        return []

def get_open_assignments(uid: int):
    """Get all open (incomplete) assignments for user"""
    try:
        result = supabase.table("assignments") \
            .select("assignment_id, task_id, sent_at, login_occurred") \
            .eq("user_id", uid) \
            .is_("completed_at", None) \
            .execute()
        
        # Filter for assignments that have been sent (not just created)
        open_assignments = [a for a in result.data if a.get("sent_at") is not None]
        logger.info(f"User {uid} has {len(open_assignments)} open assignments")
        
        return open_assignments
        
    except Exception as e:
        logger.error(f"Error getting open assignments for user {uid}: {e}")
        return []

def create_assignment(uid: int, task):
    """Create a new assignment for user with given task"""
    try:
        now = dt.datetime.utcnow().isoformat()
        
        result = supabase.table("assignments").insert({
            "user_id": uid,
            "task_id": task["task_id"],
            "sent_at": now
        }).execute()
        
        if not result.data:
            logger.error(f"Failed to create assignment for user {uid}")
            return None
            
        assignment = result.data[0]
        
        # Log the assignment
        log_message = f"{now} - assigned '{task['task_name']}' ({task['site_url']})"
        append_log(uid, log_message)
        
        logger.info(f"Created assignment {assignment['assignment_id']} for user {uid}")
        
        return {
            "assignment_id": assignment["assignment_id"],
            "task_name": task["task_name"],
            "site_url": task["site_url"]
        }
        
    except Exception as e:
        logger.error(f"Error creating assignment for user {uid}: {e}")
        return None

def queue_next_task(uid: int):
    """Queue the next random task for user if no open assignments exist"""
    try:
        # Check for existing open assignments
        open_assignments = get_open_assignments(uid)
        
        if open_assignments:
            logger.info(f"User {uid} already has {len(open_assignments)} open assignments")
            return None
        
        # Get unseen tasks
        unseen_tasks = get_unseen_tasks(uid)
        
        if not unseen_tasks:
            logger.info(f"No unseen tasks available for user {uid}")
            return None
        
        # Randomly select a task
        selected_task = random.choice(unseen_tasks)
        logger.info(f"Selected task {selected_task['task_id']} for user {uid}")
        
        # Create assignment
        return create_assignment(uid, selected_task)
        
    except Exception as e:
        logger.error(f"Error queuing next task for user {uid}: {e}")
        return None

def find_open_assignment_by_site(uid: int, site_url: str):
    """Find open assignment for user by site URL"""
    try:
        result = supabase.table("assignments") \
            .select("assignment_id, task_id, sent_at, login_occurred, tasks(task_name, site_url)") \
            .eq("user_id", uid) \
            .is_("completed_at", None) \
            .limit(10) \
            .execute()
        
        logger.info(f"Looking for site '{site_url}' among {len(result.data)} open assignments for user {uid}")
        
        # Log all available sites for debugging
        available_sites = []
        for assignment in result.data:
            if assignment.get("tasks"):
                task_site = assignment["tasks"].get("site_url", "")
                available_sites.append(task_site)
                logger.info(f"  Available site: '{task_site}' (assignment {assignment['assignment_id']})")
                
                if task_site == site_url:
                    logger.info(f"Found exact match for site '{site_url}' in assignment {assignment['assignment_id']}")
                    return assignment
        
        logger.warning(f"No exact match found for site '{site_url}'. Available sites: {available_sites}")
        return None
        
    except Exception as e:
        logger.error(f"Error finding assignment by site for user {uid}: {e}")
        return None

def generate_random_password(length=8):
    """Generate a random password with letters and digits"""
    chars = string.ascii_letters + string.digits
    # Use list comprehension for compatibility with older Python versions
    return ''.join(random.choice(chars) for _ in range(length))

def generate_username():
    """Generate a unique username"""
    return "user_" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))

# ───────────────────────── CORS Pre-flight ─────────────────────────
@app.before_request
def handle_preflight():
    """Handle CORS preflight requests"""
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        return response

# ───────────────────────── API Endpoints ─────────────────────────

@app.route("/create-user", methods=["POST"])
@handle_db_errors
def create_user():
    """Create a new user with email, username, and password"""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    
    # Validate email
    if not validate_email(email):
        return jsonify({"error": "valid_email_required"}), 400
    
    # Check if user already exists
    existing_result = supabase.table("users").select("id").eq("email", email).execute()
    if existing_result.data:
        return jsonify({"error": "user_already_exists"}), 409
    
    # Generate credentials
    username = generate_username()
    password = generate_random_password()
    
    # Ensure username is unique (unlikely collision, but good practice)
    existing_username = supabase.table("users").select("id").eq("username", username).execute()
    while existing_username.data:
        username = generate_username()
        existing_username = supabase.table("users").select("id").eq("username", username).execute()
    
    # Create user
    result = supabase.table("users").insert({
        "email": email,
        "username": username,
        "password": password,
        "log_text": ""
    }).execute()
    
    if not result.data:
        return jsonify({"error": "failed_to_create_user"}), 500
    
    user = result.data[0]
    
    # Log user creation
    creation_log = f"{dt.datetime.utcnow().isoformat()} - user created"
    append_log(user["id"], creation_log)
    
    logger.info(f"Created user {user['id']} with email {email}")
    
    return jsonify({
        "user_id": user["id"],
        "username": username,
        "password": password
    }), 201

@app.route("/verify-login", methods=["POST"])
@handle_db_errors
def verify_login():
    """Verify user login credentials"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"error": "username_and_password_required"}), 400
    
    # Find user by username
    result = supabase.table("users") \
        .select("id, username, password") \
        .eq("username", username) \
        .limit(1) \
        .execute()
    
    if not result.data:
        logger.warning(f"Login attempt with invalid username: {username}")
        return jsonify({"error": "invalid_credentials"}), 401
    
    user = result.data[0]
    
    if user["password"] != password:
        logger.warning(f"Login attempt with invalid password for user: {username}")
        return jsonify({"error": "invalid_credentials"}), 401
    
    logger.info(f"Successful login for user {user['id']}")
    return jsonify({"user_id": user["id"]}), 200

@app.route("/log", methods=["POST"])
@handle_db_errors
def log_entry():
    """Add a log entry for a user"""
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    text = data.get("text", "").strip()
    
    if not validate_user_id(uid) or not text:
        return jsonify({"error": "valid_user_id_and_text_required"}), 400
    
    # Add timestamp to log entry
    timestamped_text = f"{dt.datetime.utcnow().isoformat()} - {text}"
    
    if append_log(uid, timestamped_text):
        return jsonify({"status": "logged"}), 200
    else:
        return jsonify({"error": "failed_to_log"}), 500

@app.route("/login-event", methods=["POST"])
@handle_db_errors
def login_event():
    """Record a login event for a specific site"""
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    site_url = data.get("site_url", "").strip()
    
    if not validate_user_id(uid) or not validate_site_url(site_url):
        return jsonify({"error": "valid_user_id_and_site_url_required"}), 400
    
    # Find open assignment for this site
    assignment = find_open_assignment_by_site(uid, site_url)
    
    if not assignment:
        logger.warning(f"No pending assignment found for user {uid} on site {site_url}")
        return jsonify({"error": "no_pending_assignment"}), 409
    
    # Mark login occurred if not already marked
    if not assignment.get("login_occurred"):
        supabase.table("assignments") \
            .update({"login_occurred": True}) \
            .eq("assignment_id", assignment["assignment_id"]) \
            .execute()
        
        log_message = f"login on '{site_url}'"
        append_log(uid, log_message)
        
        logger.info(f"Login event recorded for user {uid} on site {site_url}")
    
    return jsonify({"status": "login_recorded"}), 200

@app.route("/assign-random", methods=["POST"])
@handle_db_errors
def assign_random_task():
    """Assign a random task to user if no open assignments exist"""
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    
    if not validate_user_id(uid):
        return jsonify({"error": "valid_user_id_required"}), 400
    
    # Try to queue next task
    next_task = queue_next_task(uid)
    
    if not next_task:
        # Check why assignment failed
        open_assignments = get_open_assignments(uid)
        
        if open_assignments:
            logger.info(f"User {uid} has pending assignments, cannot assign new task")
            return jsonify({"error": "pending_assignment_exists"}), 409
        else:
            logger.info(f"No tasks available for user {uid}")
            return jsonify({"error": "no_tasks_available"}), 404
    
    logger.info(f"Successfully assigned task to user {uid}")
    return jsonify({"status": "assigned", **next_task}), 200

@app.route("/complete-task", methods=["POST"])
@handle_db_errors
def complete_task():
    """Mark a task as completed and optionally assign next task"""
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    site_url = data.get("site_url", "").strip()
    elapsed_ms = data.get("elapsed_ms")
    completion_type = data.get("completion_type", "").strip()
    
    # Validate input
    if not validate_user_id(uid) or not validate_site_url(site_url):
        return jsonify({"error": "valid_user_id_and_site_url_required"}), 400
    
    if not isinstance(elapsed_ms, (int, float)) or elapsed_ms < 0:
        return jsonify({"error": "valid_elapsed_ms_required"}), 400
    
    if completion_type not in ("task_completed", "reported_phishing"):
        return jsonify({"error": "invalid_completion_type"}), 400
    
    # Find open assignment for this site
    assignment = find_open_assignment_by_site(uid, site_url)
    
    if not assignment:
        logger.warning(f"No pending assignment found for user {uid} on site {site_url}")
        return jsonify({"error": "no_pending_assignment"}), 409
    
    # Mark assignment as completed
    now = dt.datetime.utcnow().isoformat()
    elapsed_seconds = elapsed_ms / 1000
    
    supabase.table("assignments").update({
        "completed_at": now,
        "time_taken": f"{elapsed_seconds:.1f}s",
        "completion_type": completion_type
    }).eq("assignment_id", assignment["assignment_id"]).execute()
    
    # Log completion
    task_name = assignment.get("tasks", {}).get("task_name", "unknown task")
    log_message = f"completed '{task_name}' ({completion_type}) in {elapsed_seconds:.1f}s"
    append_log(uid, log_message)
    
    logger.info(f"User {uid} completed task {assignment['task_id']} in {elapsed_seconds:.1f}s")
    
    # Try to assign next task
    next_task = queue_next_task(uid)
    
    return jsonify({
        "status": "completed",
        "next_task": next_task
    }), 200

# ───────────────────────── Health Check & Debug Endpoints ─────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        supabase.table("users").select("count", count="exact").execute()
        return jsonify({
            "status": "healthy",
            "timestamp": dt.datetime.utcnow().isoformat(),
            "database": "connected"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "timestamp": dt.datetime.utcnow().isoformat(),
            "database": "disconnected",
            "error": str(e)
        }), 503

# ───────────────────────── Debug Endpoints (for development) ─────────────────────────

@app.route("/debug/user-assignments", methods=["POST"])
@handle_db_errors
def debug_user_assignments():
    """Get all assignments for a user (debug endpoint)"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
    
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    
    if not validate_user_id(uid):
        return jsonify({"error": "valid_user_id_required"}), 400
    
    # Get all assignments with task details
    result = supabase.table("assignments") \
        .select("*, tasks(task_name, site_url)") \
        .eq("user_id", uid) \
        .order("assignment_id") \
        .execute()
    
    return jsonify({
        "user_id": uid,
        "assignments": result.data,
        "count": len(result.data)
    }), 200

@app.route("/debug/site-lookup", methods=["POST"])
@handle_db_errors  
def debug_site_lookup():
    """Debug endpoint to check what assignments exist for a specific site"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
        
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    site_url = data.get("site_url", "").strip()
    
    if not validate_user_id(uid):
        return jsonify({"error": "valid_user_id_required"}), 400
        
    if not validate_site_url(site_url):
        return jsonify({"error": "valid_site_url_required"}), 400
    
    # Get all assignments for this user (completed and incomplete)
    all_assignments = supabase.table("assignments") \
        .select("assignment_id, task_id, sent_at, login_occurred, completed_at, completion_type, tasks(task_name, site_url)") \
        .eq("user_id", uid) \
        .execute()
    
    # Get only open assignments
    open_assignments = supabase.table("assignments") \
        .select("assignment_id, task_id, sent_at, login_occurred, tasks(task_name, site_url)") \
        .eq("user_id", uid) \
        .is_("completed_at", None) \
        .execute()
    
    # Get all tasks that match this site_url
    matching_tasks = supabase.table("tasks") \
        .select("*") \
        .eq("site_url", site_url) \
        .execute()
    
    # Check for exact site URL matches in assignments
    site_matches = []
    partial_matches = []
    
    for assignment in all_assignments.data:
        if assignment.get("tasks"):
            task_site = assignment["tasks"].get("site_url", "")
            if task_site == site_url:
                site_matches.append(assignment)
            elif site_url.lower() in task_site.lower() or task_site.lower() in site_url.lower():
                partial_matches.append(assignment)
    
    return jsonify({
        "user_id": uid,
        "requested_site": site_url,
        "total_assignments": len(all_assignments.data),
        "open_assignments": len(open_assignments.data),
        "exact_site_matches": site_matches,
        "partial_site_matches": partial_matches,
        "tasks_with_this_site": matching_tasks.data,
        "all_assignments": all_assignments.data,
        "all_open_assignments": open_assignments.data
    }), 200

@app.route("/debug/user-open-assignments", methods=["POST"])
@handle_db_errors
def debug_user_open_assignments():
    """Get open assignments for a user (debug endpoint)"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
    
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    
    if not validate_user_id(uid):
        return jsonify({"error": "valid_user_id_required"}), 400
    
    open_assignments = get_open_assignments(uid)
    
    return jsonify({
        "user_id": uid,
        "open_assignments": open_assignments,
        "count": len(open_assignments)
    }), 200

@app.route("/debug/tasks", methods=["GET"])
@handle_db_errors
def debug_all_tasks():
    """Get all tasks (debug endpoint)"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
    
    result = supabase.table("tasks").select("*").execute()
    
    return jsonify({
        "tasks": result.data,
        "count": len(result.data)
    }), 200

@app.route("/debug/users", methods=["GET"])
@handle_db_errors
def debug_all_users():
    """Get all users (debug endpoint)"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
    
    # Don't return passwords in debug endpoint
    result = supabase.table("users").select("id, email, username, created_at").execute()
    
    return jsonify({
        "users": result.data,
        "count": len(result.data)
    }), 200

# ───────────────────────── Application Startup ─────────────────────────

if __name__ == "__main__":
    # Validate environment and database connection on startup
    try:
        logger.info("Starting application...")
        logger.info(f"Supabase URL: {SUPABASE_URL}")
        
        # Test database connection
        test_result = supabase.table("users").select("count", count="exact").execute()
        logger.info(f"Database connection successful. Users table count: {test_result.count}")
        
        # Start Flask app
        app.run(host="0.0.0.0", port=5001, debug=True)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
