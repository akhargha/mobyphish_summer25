import os
import socket
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import random
import string
import datetime as dt
import logging
from functools import wraps
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from supabase import create_client, Client
from postgrest.exceptions import APIError
from OpenSSL import SSL
from datetime import datetime

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

def validate_username(username):
    """Validate username is a non-empty string"""
    return isinstance(username, str) and len(username.strip()) > 0

def validate_site_url(site_url):
    """Basic URL validation"""
    return isinstance(site_url, str) and len(site_url.strip()) > 0

def validate_hostname(hostname):
    """Basic hostname validation"""
    if not isinstance(hostname, str) or not hostname.strip():
        return False
    # Basic hostname validation - could be more comprehensive
    hostname = hostname.strip()
    if len(hostname) > 253 or not hostname.replace('.', '').replace('-', '').isalnum():
        return False
    return True

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

def append_log_by_username(username: str, line: str):
    """Append a log entry using username (for backward compatibility)"""
    try:
        result = supabase.table("users").select("log_text").eq("username", username).limit(1).execute()
        
        if not result.data:
            logger.warning(f"User {username} not found when appending log")
            return False
            
        existing = result.data[0]["log_text"] or ""
        body = (existing + "\n" if existing.strip() else "") + line
        
        supabase.table("users").update({"log_text": body}).eq("username", username).execute()
        logger.info(f"Log appended for user {username}: {line}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to append log for user {username}: {e}")
        return False

def get_user_id(username: str):
    """Get the user ID from username"""
    try:
        result = supabase.table("users").select("id").eq("username", username).limit(1).execute()
        if result.data:
            return result.data[0]["id"]
        logger.warning(f"User not found: {username}")
        return None
    except Exception as e:
        logger.error(f"Error getting user ID for {username}: {e}")
        return None

def get_username(uid: int):
    """Get username from user ID"""
    try:
        result = supabase.table("users").select("username").eq("id", uid).limit(1).execute()
        if result.data:
            return result.data[0]["username"]
        logger.warning(f"User not found: {uid}")
        return None
    except Exception as e:
        logger.error(f"Error getting username for {uid}: {e}")
        return None

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
        username = get_username(uid) or str(uid)
        
        result = supabase.table("assignments").insert({
            "user_id": uid,
            "task_id": task["task_id"],
            "sent_at": now,
            "username": username
        }).execute()
        
        if not result.data:
            logger.error(f"Failed to create assignment for user {uid}")
            return None
            
        assignment = result.data[0]
        
        # Log the assignment
        log_message = f"{now}  assigned '{task['task_name']}' ({task['site_url']})"
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
    """Queue the next sequential task for user if no open assignments exist"""
    try:
        # Check for existing open assignments
        open_assignments = get_open_assignments(uid)
        
        if open_assignments:
            logger.info(f"User {uid} already has {len(open_assignments)} open assignments")
            return None
        
        # Get all task IDs that user has been assigned (completed or not)
        assigned_result = supabase.table("assignments") \
            .select("task_id") \
            .eq("user_id", uid) \
            .execute()
        
        assigned_task_ids = {r["task_id"] for r in assigned_result.data}
        logger.info(f"User {uid} has been assigned {len(assigned_task_ids)} tasks already")
        
        # Get all tasks ordered by task_id (sequential order)
        all_tasks_result = supabase.table("tasks") \
            .select("*") \
            .order("task_id") \
            .execute()
        
        # Find the first task that hasnt been assigned to this user
        for task in all_tasks_result.data:
            if task["task_id"] not in assigned_task_ids:
                logger.info(f"Selected next sequential task {task['task_id']} for user {uid}")
                return create_assignment(uid, task)
        
        # No more tasks available
        logger.info(f"All tasks have been assigned to user {uid}")
        return None
        
    except Exception as e:
        logger.error(f"Error queuing next sequential task for user {uid}: {e}")
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
    return ''.join(random.choice(chars) for _ in range(length))

def generate_username():
    """Generate a unique username"""
    return "user_" + ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))

def fetch_cert_chain(hostname: str, port: int = 443):
    """Fetch SSL certificate chain for a hostname"""
    try:
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
        
        logger.info(f"Successfully fetched {len(certs)} certificates for {hostname}")
        return certs
        
    except Exception as e:
        logger.error(f"Failed to fetch certificate chain for {hostname}: {e}")
        raise

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

# ───────────────────────── User Management Endpoints ─────────────────────────

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

# ───────────────────────── Logging Endpoints ─────────────────────────

@app.route("/log", methods=["POST"])
@handle_db_errors
def log_entry():
    """Add a log entry for a user (supports both user_id and username)"""
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    username = data.get("username")  # For backward compatibility
    text = data.get("text", "").strip()
    
    if not text:
        return jsonify({"error": "text_required"}), 400
    
    # Handle both user_id (integer) and user_id (username string) for backward compatibility
    if isinstance(uid, str) and validate_username(uid):
        # Legacy mode: user_id is actually a username
        timestamped_text = f"{dt.datetime.utcnow().isoformat()}  {text}"
        if append_log_by_username(uid, timestamped_text):
            return jsonify({"status": "logged"}), 200
        else:
            return jsonify({"error": "user_not_found"}), 404
    elif validate_user_id(uid):
        # New mode: user_id is an integer
        timestamped_text = f"{dt.datetime.utcnow().isoformat()} - {text}"
        if append_log(uid, timestamped_text):
            return jsonify({"status": "logged"}), 200
        else:
            return jsonify({"error": "user_not_found"}), 404
    elif validate_username(username):
        # Alternative: username parameter
        timestamped_text = f"{dt.datetime.utcnow().isoformat()} - {text}"
        if append_log_by_username(username, timestamped_text):
            return jsonify({"status": "logged"}), 200
        else:
            return jsonify({"error": "user_not_found"}), 404
    else:
        return jsonify({"error": "valid_user_id_or_username_required"}), 400

# ───────────────────────── Task Management Endpoints ─────────────────────────

@app.route("/login-event", methods=["POST"])
@handle_db_errors
def login_event():
    """Record a login event for a specific site (supports both user_id formats)"""
    data = request.get_json(silent=True) or {}
    user_identifier = data.get("user_id")
    site_url = data.get("site_url", "").strip()
    
    if not validate_site_url(site_url):
        return jsonify({"error": "valid_site_url_required"}), 400
    
    # Handle both integer user_id and username string
    if isinstance(user_identifier, str) and validate_username(user_identifier):
        # Legacy mode: user_id is actually a username
        uid = get_user_id(user_identifier)
        username = user_identifier
    elif validate_user_id(user_identifier):
        # New mode: user_id is integer
        uid = user_identifier
        username = get_username(uid)
    else:
        return jsonify({"error": "valid_user_id_required"}), 400
    
    if not uid:
        return jsonify({"error": "user_not_found"}), 404
    
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
        
        log_message = f"{dt.datetime.utcnow().isoformat()}  login on '{site_url}'"
        append_log(uid, log_message)
        
        logger.info(f"Login event recorded for user {uid} on site {site_url}")
    
    return jsonify({"status": "marked"}), 200

@app.route("/assign-random", methods=["POST"])
@handle_db_errors
def assign_random_task():
    """Assign a sequential task to user (supports both user_id formats)"""
    data = request.get_json(silent=True) or {}
    user_identifier = data.get("user_id")
    
    # Handle both integer user_id and username string
    if isinstance(user_identifier, str) and validate_username(user_identifier):
        # Legacy mode: user_id is actually a username
        uid = get_user_id(user_identifier)
    elif validate_user_id(user_identifier):
        # New mode: user_id is integer
        uid = user_identifier
    else:
        return jsonify({"error": "valid_user_id_required"}), 400
    
    if not uid:
        return jsonify({"error": "user_not_found"}), 404
    
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
    """Mark a task as completed (supports both user_id formats)"""
    data = request.get_json(silent=True) or {}
    user_identifier = data.get("user_id")
    site_url = data.get("site_url", "").strip()
    elapsed_ms = data.get("elapsed_ms")
    completion_type = data.get("completion_type", "").strip()
    
    # Validate basic input
    if not validate_site_url(site_url):
        return jsonify({"error": "valid_site_url_required"}), 400
    
    if not isinstance(elapsed_ms, (int, float)) or elapsed_ms < 0:
        return jsonify({"error": "valid_elapsed_ms_required"}), 400
    
    if completion_type not in ("task_completed", "reported_phishing"):
        return jsonify({"error": "invalid_completion_type"}), 400
    
    # Handle both integer user_id and username string
    if isinstance(user_identifier, str) and validate_username(user_identifier):
        # Legacy mode: user_id is actually a username
        uid = get_user_id(user_identifier)
        username = user_identifier
    elif validate_user_id(user_identifier):
        # New mode: user_id is integer
        uid = user_identifier
        username = get_username(uid)
    else:
        return jsonify({"error": "valid_user_id_required"}), 400
    
    if not uid:
        return jsonify({"error": "user_not_found"}), 404
    
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
    log_message = f"{now}  finished '{task_name}' ({completion_type}) in {elapsed_seconds:.1f}s"
    append_log(uid, log_message)
    
    logger.info(f"User {uid} completed task {assignment['task_id']} in {elapsed_seconds:.1f}s")
    
    # Try to assign next task
    next_task = queue_next_task(uid)
    
    return jsonify({
        "status": "completed",
        "next_task": next_task
    }), 200

# ───────────────────────── Certificate Management ─────────────────────────

@app.route("/certificate_chain/<path:hostname>", methods=["GET"])
@handle_db_errors
def certificate_chain(hostname):
    """Fetch SSL certificate chain for a hostname"""
    # Validate hostname
    if not validate_hostname(hostname):
        return jsonify({"error": "invalid_hostname"}), 400
    
    try:
        certs = fetch_cert_chain(hostname.strip())
        logger.info(f"Successfully returned {len(certs)} certificates for {hostname}")
        return jsonify(certs)
        
    except Exception as e:
        logger.error(f"Certificate fetch failed for {hostname}: {e}")
        return jsonify({
            "error": "certificate_fetch_failed", 
            "message": f"Error fetching certificates: {e}",
            "hostname": hostname
        }), 502

# ───────────────────────── Health Check & System Endpoints ─────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        test_result = supabase.table("users").select("count", count="exact").execute()
        return jsonify({
            "status": "healthy",
            "timestamp": dt.datetime.utcnow().isoformat(),
            "database": "connected",
            "user_count": test_result.count
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "timestamp": dt.datetime.utcnow().isoformat(),
            "database": "disconnected",
            "error": str(e)
        }), 503

@app.route("/test", methods=["GET"])
def test_endpoint():
    """Test endpoint (legacy compatibility)"""
    return jsonify({
        "utc": dt.datetime.utcnow().isoformat(),
        "status": "test_endpoint_active"
    })

# ───────────────────────── Debug Endpoints (Development) ─────────────────────────

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

@app.route("/debug/certificate-test/<path:hostname>", methods=["GET"])
@handle_db_errors
def debug_certificate_test(hostname):
    """Test certificate fetching with detailed debug info"""
    if not app.debug:
        return jsonify({"error": "debug_endpoint_disabled"}), 403
    
    if not validate_hostname(hostname):
        return jsonify({"error": "invalid_hostname"}), 400
    
    try:
        start_time = dt.datetime.utcnow()
        certs = fetch_cert_chain(hostname.strip())
        end_time = dt.datetime.utcnow()
        
        return jsonify({
            "hostname": hostname,
            "certificate_count": len(certs),
            "certificates": certs,
            "fetch_time_ms": (end_time - start_time).total_seconds() * 1000,
            "status": "success"
        })
        
    except Exception as e:
        return jsonify({
            "hostname": hostname,
            "error": str(e),
            "error_type": type(e).__name__,
            "status": "failed"
        }), 502

# ───────────────────────── Legacy Compatibility Endpoints ─────────────────────────

@app.route("/assign-random-legacy", methods=["POST"])
@handle_db_errors
def assign_random_legacy():
    """Legacy endpoint that matches File 1's exact behavior"""
    data = request.get_json(silent=True) or {}
    username = data.get("user_id")  # Note: File 1 used "user_id" but expected username
    
    if not isinstance(username, str):
        return jsonify({"error": "user_id string required"}), 400
    
    uid = get_user_id(username)
    if not uid:
        return jsonify({"error": "user_not_found"}), 404
    
    # Check if assignment already exists
    open_assignments = get_open_assignments(uid)
    if open_assignments:
        return jsonify({"error": "pending_assignment_exists"}), 409
    
    next_task = queue_next_task(uid)
    if not next_task:
        return jsonify({"error": "no_tasks_available"}), 404
    
    return jsonify({"status": "assigned", **next_task}), 200

# ───────────────────────── Application Startup ─────────────────────────

if __name__ == "__main__":
    # Validate environment and database connection on startup
    try:
        logger.info("Starting merged Flask application...")
        logger.info(f"Supabase URL: {SUPABASE_URL}")
        
        # Test database connection
        test_result = supabase.table("users").select("count", count="exact").execute()
        logger.info(f"Database connection successful. Users table count: {test_result.count}")
        
        # Test SSL certificate functionality
        try:
            logger.info("Testing SSL certificate functionality...")
            test_certs = fetch_cert_chain("google.com")
            logger.info(f"SSL certificate test successful. Retrieved {len(test_certs)} certificates.")
        except Exception as e:
            logger.warning(f"SSL certificate test failed (non-critical): {e}")
        
        logger.info("Application startup complete. Available endpoints:")
        logger.info("  User Management: /create-user, /verify-login")
        logger.info("  Task Management: /assign-random, /complete-task, /login-event")
        logger.info("  Logging: /log")
        logger.info("  Certificates: /certificate_chain/<hostname>")
        logger.info("  Health: /health, /test")
        logger.info("  Debug: /debug/* (development mode only)")
        
        # Start Flask app
        app.run(host="0.0.0.0", port=5001, debug=True)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
