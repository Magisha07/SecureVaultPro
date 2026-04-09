from backend_sheets import (
    email_exists,
    GoogleSheetsConnectionError,
    get_user as get_account_by_username,
    is_valid_email,
    normalize_email,
    register_user as register_sheet_user,
    update_user as update_sheet_user,
)

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_file,
)
import os
import secrets
import re
import hashlib
import bcrypt
import time
import pyotp
import base64
import io
import unicodedata
import mimetypes
import tempfile
from werkzeug.utils import secure_filename
try:
    import qrcode
except ImportError:
    qrcode = None

from main import _create_services, seed_test_data, get_crypto_engine_for_user
from crypto_engine import HybridCryptoEngine
from security_monitor import SecurityMonitor
from seal import (
    EVENT_LOGIN,
    EVENT_LOGOUT,
    EVENT_UPLOAD,
    EVENT_SEARCH,
    EVENT_DOWNLOAD,
    EVENT_VIEW_LOGS,
    EVENT_REGISTER,
    EVENT_IDS_BLOCK,
    EVENT_OTP_SENT,
    EVENT_OTP_VERIFIED,
)


app = Flask(__name__)

# Use a strong secret key for sessions & CSRF.
# In production, load from environment or a secure secret manager.
app.secret_key = os.environ.get("SECUREVAULT_SECRET_KEY") or secrets.token_hex(32)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DOWNLOAD_TOTP_MAX_ATTEMPTS = 3
DOWNLOAD_TOTP_LOCK_SECONDS = 120
ALLOWED_UPLOAD_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "txt",
    "md",
    "csv",
    "json",
    "xml",
    "log",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "ppt",
    "pptx",
    "xls",
    "xlsx",
}
PREVIEW_SESSION_KEY = "preview_temp_file"
PREVIEW_TTL_SECONDS = 300
TOTP_LOCK_MESSAGE = "TOTP failed 3 times. Try again after 2 minutes."
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_AUTH_MAX_ATTEMPTS = 3
ADMIN_AUTH_LOCK_SECONDS = 120
SEAL_EVENT_MAP = {
    "LOGIN_SUCCESS": EVENT_LOGIN,
    "LOGIN_FAILED": EVENT_IDS_BLOCK,
    "TOTP_SUCCESS": EVENT_OTP_VERIFIED,
    "TOTP_FAILED": EVENT_IDS_BLOCK,
    "DOWNLOAD": EVENT_DOWNLOAD,
    "VIEW": EVENT_DOWNLOAD,
}


def load_env_file(path: str) -> None:
    """
    Load key=value pairs from a local .env file into process environment.
    Existing environment variables are preserved.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


load_env_file(os.path.join(BASE_DIR, ".env"))


def sheets_error_message(action: str) -> str:
    return (
        f"Unable to {action} right now because Google Sheets could not be reached. "
        "Please check your credentials, internet connection, and sheet access, then try again."
    )


def get_stored_totp_secret(username: str) -> str | None:
    try:
        account = get_account_by_username(username)
    except GoogleSheetsConnectionError as exc:
        print("GOOGLE SHEETS ERROR:", exc)
        raise
    if not account:
        return None
    secret = account.get("totp_secret")
    return secret if secret else None


def normalize_totp_secret(secret: str) -> str:
    return "".join((secret or "").split()).upper()


def normalize_totp_code(user_code: str) -> str:
    normalized_digits = []
    for ch in user_code:
        if ch.isdigit():
            try:
                normalized_digits.append(str(unicodedata.decimal(ch)))
            except Exception:
                normalized_digits.append(ch)
    return "".join(normalized_digits)


def ensure_user_totp_secret(username: str) -> str | None:
    """
    Ensure the user has one stable TOTP secret persisted in storage.
    """
    try:
        account = get_account_by_username(username)
    except GoogleSheetsConnectionError as exc:
        print("GOOGLE SHEETS ERROR:", exc)
        raise
    if not account:
        return None

    stored_secret = normalize_totp_secret(account.get("totp_secret", ""))
    if stored_secret:
        return stored_secret

    stored_secret = pyotp.random_base32()
    update_sheet_user(
        username,
        password_hash=account.get("password_hash"),
        totp_secret=stored_secret,
        totp_confirmed=False,
    )
    return stored_secret


def verify_current_totp(stored_secret: str, user_code: str) -> bool:
    """
    Verify a TOTP code using the same persisted secret used for QR provisioning.
    """
    normalized_secret = normalize_totp_secret(stored_secret)
    normalized_code = normalize_totp_code(user_code)
    if not normalized_secret or not re.fullmatch(r"[0-9]{6}", normalized_code):
        return False
    try:
        return bool(pyotp.TOTP(normalized_secret).verify(normalized_code, valid_window=1))
    except Exception:
        return False


def verify_totp_code(stored_secret: str, user_code: str) -> bool:
    """
    Verify TOTP code with +/- 30s tolerance (valid_window=1).
    Uses the exact stored secret without re-encoding.
    """
    if not stored_secret:
        return False
    try:
        # Normalize user input to tolerate spaces or non-ASCII digit glyphs.
        normalized_digits = []
        for ch in user_code:
            if ch.isdigit():
                try:
                    normalized_digits.append(str(unicodedata.decimal(ch)))
                except Exception:
                    normalized_digits.append(ch)
        normalized_code = "".join(normalized_digits)
        if not re.fullmatch(r"[0-9]{6}", normalized_code):
            return False
        normalized_secret = "".join(stored_secret.split()).upper()
        totp = pyotp.TOTP(normalized_secret)
        now = time.time()
        # Primary check (±30s). If it fails, allow one extra step for clock drift.
        if totp.verify(normalized_code, for_time=now, valid_window=1):
            return True
        return bool(totp.verify(normalized_code, for_time=now, valid_window=2))
    except Exception:
        return False


def make_totp_qr_data_uri(username: str, secret: str) -> str:
    if qrcode is None:
        return ""
    issuer = "SecureVault"
    uri = pyotp.TOTP(normalize_totp_secret(secret)).provisioning_uri(
        name=username, issuer_name=issuer
    )
    qr = qrcode.QRCode(border=2, box_size=6)
    qr.add_data(uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def get_download_totp_lock_remaining() -> int:
    """
    Return remaining cooldown time in seconds for download verification.
    """
    blocked_until = float(session.get("download_blocked_until", 0.0) or 0.0)
    remaining = blocked_until - time.time()
    if remaining <= 0:
        return 0
    return int(remaining) if remaining.is_integer() else int(remaining) + 1


def reset_download_totp_state() -> None:
    """
    Clear failed-attempt and lock state for download verification.
    """
    session["totp_failures"] = 0
    session.pop("pending_doc_id", None)
    session.pop("download_blocked_until", None)


def refresh_totp_lock_state() -> None:
    blocked_until = float(session.get("download_blocked_until", 0.0) or 0.0)
    if blocked_until and time.time() >= blocked_until:
        reset_download_totp_state()


# ----- Backend services (re-use console logic) -----
auth, kms, seal, data_tier, otp_service, ids = _create_services()
seed_test_data(auth, kms, seal, data_tier)
security_monitor = SecurityMonitor(
    BASE_DIR,
    hashlib.sha256(app.secret_key.encode("utf-8")).digest(),
)


def ensure_default_admin_account() -> None:
    try:
        account = get_account_by_username(ADMIN_USERNAME)
    except GoogleSheetsConnectionError:
        app.logger.exception("Unable to verify default admin account")
        return

    if account:
        if account.get("role") != "admin":
            try:
                update_sheet_user(ADMIN_USERNAME, role="admin", active=True)
            except GoogleSheetsConnectionError:
                app.logger.exception("Unable to update default admin role")
        return

    try:
        register_sheet_user(
            ADMIN_USERNAME,
            "admin@securevault.local",
            bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode("utf-8"),
            pyotp.random_base32(),
            totp_confirmed=False,
            active=True,
            role="admin",
        )
    except Exception:
        app.logger.exception("Unable to create default admin account")


ensure_default_admin_account()


# ----- Helpers -----
def current_user() -> str | None:
    return session.get("user")


def is_authenticated() -> bool:
    return current_user() is not None


def current_role() -> str:
    role = str(session.get("role", "user")).strip().lower()
    return role if role in {"admin", "user"} else "user"


def is_admin() -> bool:
    return current_role() == "admin"


def is_admin_totp_verified() -> bool:
    return bool(session.get("admin_totp_verified")) if is_admin() else False


def admin_home_endpoint() -> str:
    return "security_dashboard" if is_admin() else "dashboard"


def admin_redirect_response():
    flash("Admin verification is required to continue.", "warning")
    return redirect(url_for("admin_verify_totp"))


def clear_admin_pending_auth() -> None:
    session.pop("pending_admin_user", None)
    session.pop("pending_admin_role", None)


def get_lock_remaining(session_key: str) -> int:
    blocked_until = float(session.get(session_key, 0.0) or 0.0)
    remaining = blocked_until - time.time()
    if remaining <= 0:
        return 0
    return int(remaining) if remaining.is_integer() else int(remaining) + 1


def clear_auth_attempt_state(prefix: str) -> None:
    session[f"{prefix}_failures"] = 0
    session.pop(f"{prefix}_blocked_until", None)


def register_auth_failure(
    prefix: str,
    *,
    user: str,
    alert_action: str,
    alert_details: str,
) -> int:
    failures = int(session.get(f"{prefix}_failures", 0) or 0) + 1
    session[f"{prefix}_failures"] = failures
    if failures >= ADMIN_AUTH_MAX_ATTEMPTS:
        session[f"{prefix}_blocked_until"] = time.time() + ADMIN_AUTH_LOCK_SECONDS
        security_monitor.add_ids_alert_with_details(user, alert_action, "high", alert_details)
    return failures


def register_login_failure(user: str) -> int:
    failures = int(session.get("login_failures", 0) or 0) + 1
    session["login_failures"] = failures
    if failures >= 3:
        security_monitor.add_ids_alert_with_details(
            user,
            "MULTIPLE_LOGIN_FAILURES",
            "high",
            "Three or more consecutive login failures detected.",
        )
    return failures


def log_security_event(
    user: str,
    action: str,
    status: str,
    extra: dict | None = None,
    *,
    event_type: str | None = None,
    message: str | None = None,
) -> None:
    resolved_event = event_type or SEAL_EVENT_MAP.get(action, EVENT_VIEW_LOGS)
    resolved_message = message or f"{action} [{status}]"
    seal.append(resolved_event, resolved_message, user, extra=extra)
    security_monitor.add_seal_log(user, action, status, extra or {})


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        if not is_admin():
            abort(403)
        if not is_admin_totp_verified():
            return admin_redirect_response()
        return view_func(*args, **kwargs)

    return wrapper


# ----- CSRF protection (simple, session-based) -----
def _ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


@app.before_request
def load_auth_session_and_check_csrf():
    # Re-bind application auth session to match Flask session (single-user demo).
    auth_sid = session.get("auth_sid")
    if auth_sid:
        auth.set_session(auth_sid)

    actor = (
        current_user()
        or session.get("pending_admin_user")
        or request.headers.get("X-Forwarded-For")
        or request.remote_addr
        or "anonymous"
    )
    if request.endpoint not in {None, "static"}:
        security_monitor.track_request(actor)

    # CSRF protection for state-changing methods
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Allow JSON APIs in future by extending this check
        form_token = request.form.get("csrf_token")
        session_token = session.get("csrf_token")
        if not session_token or not form_token or form_token != session_token:
            # Do not crash; show user-friendly error
            flash("Security check failed. Please try again.", "danger")
            fallback_endpoint = admin_home_endpoint() if is_authenticated() else "login"
            return redirect(request.referrer or url_for(fallback_endpoint))


@app.context_processor
def inject_globals():
    return {
        "csrf_token": _ensure_csrf_token(),
        "current_user": current_user(),
        "is_admin": is_admin(),
        "admin_totp_verified": is_admin_totp_verified(),
        "current_role": current_role(),
        "ids_alert_count": security_monitor.ids_alert_count(),
        "seal_log_count": security_monitor.seal_log_count(),
    }


def is_allowed_upload(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_UPLOAD_EXTENSIONS


def normalize_search_keyword(value: str) -> str:
    return (value or "").strip().lower()


def extract_search_terms(value: str) -> list[str]:
    normalized = normalize_search_keyword(value)
    if not normalized:
        return []
    terms: list[str] = []
    seen = set()
    for token in re.split(r"[^a-z0-9]+", normalized):
        if not token or token in seen:
            continue
        terms.append(token)
        seen.add(token)
    return terms


def encode_encrypted_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_stable_kms_key(username: str, password_hash: str) -> bytes:
    master_secret = (
        os.environ.get("SECUREVAULT_KMS_MASTER_KEY")
        or os.environ.get("SECUREVAULT_SECRET_KEY")
        or "securevault-local-master-key"
    )
    material = (
        f"{master_secret}:{username.strip()}:{(password_hash or '').strip()}".encode(
            "utf-8"
        )
    )
    return hashlib.sha256(material).digest()


def ensure_kms_key_for_user(username: str, account: dict | None) -> bytes | None:
    if kms.has_key(username):
        return kms.get_key_for_encrypt(username)
    password_hash = (account or {}).get("password_hash", "")
    if not password_hash:
        return None
    stable_key = build_stable_kms_key(username, password_hash)
    kms.store_key(username, stable_key)
    return stable_key


def get_owned_doc_or_404(user: str, doc_id: str) -> dict:
    owner = data_tier.get_owner(doc_id)
    if not owner or owner != user:
        abort(404)
    metadata = data_tier.get_document_metadata(doc_id)
    if not metadata:
        abort(404)
    return metadata


def get_doc_mimetype(filename: str) -> str:
    guessed_type, _ = mimetypes.guess_type(filename or "")
    return guessed_type or "application/octet-stream"


def get_file_category(filename: str, mimetype: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if mimetype.startswith("text/") or ext in {"txt", "md", "csv", "json", "xml", "log"}:
        return "text"
    if ext == "pdf" or mimetype == "application/pdf":
        return "pdf"
    if mimetype.startswith("image/") or ext in {"jpg", "jpeg", "png", "gif", "webp"}:
        return "image"
    if ext in {"doc", "docx"}:
        return "doc"
    if ext in {"ppt", "pptx"}:
        return "ppt"
    if ext in {"xls", "xlsx"}:
        return "excel"
    return "binary"


def is_text_preview_file(filename: str, mimetype: str) -> bool:
    return get_file_category(filename, mimetype) == "text"


def is_inline_preview_supported(filename: str, mimetype: str) -> bool:
    return get_file_category(filename, mimetype) in {"pdf", "image"}


def clear_preview_temp_file() -> None:
    preview_meta = session.pop(PREVIEW_SESSION_KEY, None)
    if not preview_meta:
        return
    preview_path = preview_meta.get("path", "")
    if preview_path:
        try:
            os.remove(preview_path)
        except OSError:
            pass


def create_preview_temp_file(user: str, filename: str, mimetype: str, payload: bytes) -> str:
    clear_preview_temp_file()
    suffix = os.path.splitext(filename or "")[1] or ".bin"
    temp_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=suffix)
    temp_file.write(payload or b"")
    temp_file.flush()
    temp_file.close()

    token = secrets.token_urlsafe(24)
    session[PREVIEW_SESSION_KEY] = {
        "token": token,
        "owner": user,
        "filename": filename,
        "mimetype": mimetype,
        "path": temp_file.name,
        "expires_at": int(time.time()) + PREVIEW_TTL_SECONDS,
    }
    return token


def clear_expired_preview_temp_file() -> None:
    preview_meta = session.get(PREVIEW_SESSION_KEY) or {}
    if not preview_meta:
        return
    expires_at = int(preview_meta.get("expires_at") or 0)
    if expires_at and time.time() > expires_at:
        clear_preview_temp_file()


def ensure_user_totp_ready(user: str):
    try:
        account = get_account_by_username(user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets TOTP lookup failed for %s", user)
        flash(sheets_error_message("verify your account"), "danger")
        return None, redirect(url_for("dashboard"))
    if not account:
        flash("Account not found.", "danger")
        return None, redirect(url_for("dashboard"))
    if not account.get("totp_confirmed"):
        flash(
            "Before viewing or downloading files, please sync your account with the Authenticator app.",
            "warning",
        )
        return None, redirect(url_for("authenticator_setup", next="dashboard"))
    return account, None


def decrypt_document_for_user(user: str, doc_id: str):
    payload = data_tier.get_encrypted_payload(doc_id)
    if not payload:
        return None, "File corrupted or missing encryption data. Please re-upload."

    try:
        key = kms.get_key_if_released(user)
        if key is None:
            return None, "Key not available after TOTP."
        ciphertext, nonce = payload
        engine = HybridCryptoEngine(key)
        print("Decrypt user:", user)
        print("Decrypt doc:", doc_id)
        print("KEY:", base64.b64encode(key).decode("ascii"))
        print("NONCE:", base64.b64encode(nonce).decode("ascii"))
        print("CIPHERTEXT LENGTH:", len(ciphertext))
        try:
            plain = engine.decrypt(ciphertext, nonce)
        except Exception as exc:
            print("DECRYPT ERROR:", exc)
            app.logger.exception("Decryption failed for %s", doc_id)
            return None, "Decryption failed. Please re-upload file."
        return plain, None
    finally:
        kms.revoke_release(user)


def build_decrypted_file_response(
    plaintext: bytes,
    filename: str,
    mimetype: str,
    *,
    as_attachment: bool,
):
    return send_file(
        io.BytesIO(plaintext or b""),
        mimetype=mimetype or "application/octet-stream",
        as_attachment=as_attachment,
        download_name=filename,
        max_age=0,
    )


def search_document_ids_for_user(user: str, keyword: str) -> list[str]:
    key = kms.get_key_for_encrypt(user)
    if not key:
        return []

    engine = HybridCryptoEngine(key)
    ore_token = engine.generate_ore_token_for_search(keyword)
    print("Search keyword:", keyword)
    print("Generated token:", base64.b64encode(ore_token).decode("ascii"))
    print("Stored tokens:", data_tier.debug_tokens())

    doc_ids = data_tier.search_by_ore_token(ore_token)
    print("Before filter:", doc_ids)
    doc_ids = [d for d in doc_ids if data_tier.get_owner(d) == user]

    owned_docs = data_tier.list_owned_documents(user)
    for doc in owned_docs:
        filename_terms = extract_search_terms(doc.get("original_filename", ""))
        if keyword in filename_terms and doc.get("doc_id") not in doc_ids:
            doc_ids.append(doc.get("doc_id", ""))

    print("Results:", doc_ids)
    return doc_ids


def verify_totp_for_doc_action(user: str, doc_id: str, action_label: str):
    refresh_totp_lock_state()
    blocked_remaining = get_download_totp_lock_remaining()
    if blocked_remaining > 0:
        security_monitor.add_ids_alert_with_details(
            user,
            "TOTP_LOCKED",
            "high",
            f"{action_label.title()} blocked after repeated failed TOTP verification.",
        )
        flash(TOTP_LOCK_MESSAGE, "danger")
        return False

    allowed, msg = ids.record_and_check(f"{action_label}:{doc_id}")
    if not allowed:
        seal.append(EVENT_IDS_BLOCK, msg, user)
        security_monitor.add_ids_alert_with_details(
            user,
            f"IDS_BLOCK:{action_label.upper()}",
            "medium",
            msg,
        )
        flash(msg, "danger")
        return False

    try:
        account = get_account_by_username(user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets TOTP lookup failed for %s", user)
        flash(sheets_error_message("verify your account"), "danger")
        return False

    code = request.form.get("totp_code", "").strip()
    try:
        totp_secret = ensure_user_totp_secret(user) or (account or {}).get("totp_secret")
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets TOTP secret load failed for %s", user)
        flash(sheets_error_message("verify your account"), "danger")
        return False

    seal.append(EVENT_OTP_SENT, f"TOTP verification attempt for {action_label} {doc_id}", user)
    verified = verify_current_totp(totp_secret, code)
    if verified:
        released_key = kms.release_key_after_otp(user)
        if released_key is None:
            flash("Key not available after TOTP.", "danger")
            return False
        seal.append(EVENT_OTP_VERIFIED, f"TOTP verified for {action_label} {doc_id}", user)
        log_security_event(
            user,
            "TOTP_SUCCESS",
            "SUCCESS",
            {"action": action_label, "doc_id": doc_id},
            event_type=EVENT_OTP_VERIFIED,
            message=f"TOTP success for {action_label} on {doc_id}",
        )
        session["totp_failures"] = 0
        session.pop("download_blocked_until", None)
        return True

    failures = int(session.get("totp_failures", 0)) + 1
    session["totp_failures"] = failures
    seal.append(
        EVENT_IDS_BLOCK,
        f"TOTP failed for {action_label} {doc_id} (attempt {failures})",
        user,
    )
    log_security_event(
        user,
        "TOTP_FAILED",
        "FAILED",
        {"action": action_label, "doc_id": doc_id, "attempt": failures},
        event_type=EVENT_IDS_BLOCK,
        message=f"TOTP failed for {action_label} on {doc_id} (attempt {failures})",
    )
    remaining_attempts = DOWNLOAD_TOTP_MAX_ATTEMPTS - failures
    if failures >= DOWNLOAD_TOTP_MAX_ATTEMPTS:
        session["download_blocked_until"] = time.time() + DOWNLOAD_TOTP_LOCK_SECONDS
        security_monitor.add_ids_alert_with_details(
            user,
            "TOTP_FAILED_3_TIMES",
            "high",
            f"Three failed TOTP attempts while trying to {action_label} document {doc_id}.",
        )
        flash(TOTP_LOCK_MESSAGE, "danger")
    else:
        flash(
            f"Invalid authenticator code. {remaining_attempts} attempt(s) remaining.",
            "danger",
        )
    return False


# ----- Routes -----
@app.route("/")
def index():
    if is_authenticated():
        return redirect(url_for("security_dashboard" if is_admin() else "dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        # Basic presence checks
        if not username or not email or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if username.lower() == ADMIN_USERNAME:
            flash("The admin account is system-managed and cannot be created from this form.", "danger")
            return render_template("register.html")

        # Email format
        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        # Password match
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        # Password strength: 8+, upper, lower, digit, special
        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"[0-9]", password)
            or not re.search(r"[^A-Za-z0-9]", password)
        ):
            flash(
                "Password must be at least 8 characters long and include uppercase, "
                "lowercase, number, and special character.",
                "danger",
            )
            return render_template("register.html")

        # Uniqueness checks
        try:
            if get_account_by_username(username):
                flash("Username is already taken. Please choose another.", "danger")
                return render_template("register.html")

            if email_exists(email):
                flash("Email is already registered. Please use another.", "danger")
                return render_template("register.html")
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets lookup failed during registration for %s", username)
            flash(sheets_error_message("check account details"), "danger")
            return render_template("register.html")

        # Persist profile/account and password hash for durable login across restarts.
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")
        totp_secret = pyotp.random_base32()
        try:
            register_sheet_user(
                username,
                email,
                password_hash,
                totp_secret,
                totp_confirmed=False,
                active=True,
                role="user",
            )
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("register.html")
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets registration failed for %s", username)
            flash(sheets_error_message("register"), "danger")
            return render_template("register.html")

        registered_account = {
            "username": username,
            "password_hash": password_hash,
        }
        if not ensure_kms_key_for_user(username, registered_account):
            flash("Unable to initialize an encryption key for this account.", "danger")
            return render_template("register.html")

        seal.append(EVENT_REGISTER, f"New user registered: {username}", username)
        security_monitor.add_seal_log(username, "REGISTER", "SUCCESS", {"role": "user"})
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        clear_admin_pending_auth()
        session["admin_totp_verified"] = False
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html")

        # Check account exists and is active
        try:
            account = get_account_by_username(username)
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets login lookup failed for %s", username)
            flash(sheets_error_message("sign in"), "danger")
            return render_template("login.html")

        is_admin_username = bool(account and account.get("role") == "admin") or username.lower() == ADMIN_USERNAME
        admin_lock_remaining = get_lock_remaining("admin_login_blocked_until") if is_admin_username else 0
        if admin_lock_remaining > 0:
            flash(
                f"Admin account temporarily locked. Try again in {admin_lock_remaining} seconds.",
                "danger",
            )
            return render_template("login.html", admin_login_lock_remaining=admin_lock_remaining)

        if not account or not account.get("active"):
            user_label = username or "anonymous"
            register_login_failure(user_label)
            log_security_event(
                user_label,
                "LOGIN_FAILED",
                "FAILED",
                {"reason": "account_missing_or_inactive"},
                event_type=EVENT_IDS_BLOCK,
                message="Login failed: invalid or inactive account",
            )
            security_monitor.add_ids_alert_with_details(
                user_label,
                "INVALID_LOGIN",
                "medium",
                "Invalid username or inactive account during password authentication.",
            )
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        stored_hash = account.get("password_hash")

        if not stored_hash:
            register_login_failure(username)
            log_security_event(
                username,
                "LOGIN_FAILED",
                "FAILED",
                {"reason": "missing_password_hash"},
                event_type=EVENT_IDS_BLOCK,
                message="Login failed: stored password hash missing",
            )
            security_monitor.add_ids_alert_with_details(
                username,
                "INVALID_LOGIN",
                "medium",
                "Password hash missing for account.",
            )
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            register_login_failure(username)
            log_security_event(
                username,
                "LOGIN_FAILED",
                "FAILED",
                {"reason": "password_mismatch"},
                event_type=EVENT_IDS_BLOCK,
                message="Login failed: password mismatch",
            )
            security_monitor.add_ids_alert_with_details(
                username,
                "INVALID_LOGIN",
                "medium",
                "Password mismatch during login.",
            )
            if is_admin_username:
                failures = register_auth_failure(
                    "admin_login",
                    user=username,
                    alert_action="MULTIPLE_LOGIN_FAILURES",
                    alert_details="Three failed admin password attempts triggered a 2 minute lockout.",
                )
                remaining = get_lock_remaining("admin_login_blocked_until")
                if remaining > 0:
                    flash(
                        f"Admin account locked for 2 minutes after {failures} failed attempts.",
                        "danger",
                    )
                    return render_template("login.html", admin_login_lock_remaining=remaining)
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        role = account.get("role", "user")
        is_admin_user = role == "admin"
        auth.sync_user(username, password, is_admin=is_admin_user)
        session["login_failures"] = 0

        if not ensure_kms_key_for_user(username, account):
            flash("Encryption key is not available for this account.", "danger")
            return render_template("login.html")

        clear_auth_attempt_state("admin_login")

        if is_admin_user:
            clear_admin_pending_auth()
            session["pending_admin_user"] = username
            session["pending_admin_role"] = role
            session["admin_totp_verified"] = False
            flash("Password verified. Complete TOTP to access admin security controls.", "info")
            return redirect(url_for("admin_verify_totp"))

        sid = auth.create_session_for_user(username)
        if not sid:
            flash("Unable to create a session for this account.", "danger")
            return render_template("login.html")

        ids.reset()
        log_security_event(
            username,
            "LOGIN_SUCCESS",
            "SUCCESS",
            {"role": role},
            event_type=EVENT_LOGIN,
            message=f"User {username} logged in",
        )

        session["user"] = username
        session["auth_sid"] = sid
        session["role"] = role
        session["admin_totp_verified"] = False

        if not account.get("totp_confirmed"):
            flash(
                "Set up your Authenticator app by scanning your QR code before decrypting files.",
                "warning",
            )
        flash(f"Welcome back, {username}.", "success")
        return redirect(url_for("security_dashboard" if is_admin_user else "dashboard"))

    return render_template("login.html")


@app.route("/admin-verify-totp", methods=["GET", "POST"])
def admin_verify_totp():
    pending_user = session.get("pending_admin_user")
    pending_role = session.get("pending_admin_role")
    if not pending_user or pending_role != "admin":
        if is_authenticated() and is_admin() and is_admin_totp_verified():
            return redirect(url_for("security_dashboard"))
        flash("Start with your admin username and password first.", "warning")
        return redirect(url_for("login"))

    try:
        account = get_account_by_username(pending_user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets admin TOTP lookup failed for %s", pending_user)
        flash(sheets_error_message("verify the admin account"), "danger")
        return render_template("admin_verify_totp.html", pending_user=pending_user, lock_remaining=0)

    if not account:
        clear_admin_pending_auth()
        flash("Admin account not found.", "danger")
        return redirect(url_for("login"))

    try:
        secret = ensure_user_totp_secret(pending_user) or account.get("totp_secret", "")
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets admin TOTP secret lookup failed for %s", pending_user)
        flash(sheets_error_message("load the admin authenticator"), "danger")
        return render_template("admin_verify_totp.html", pending_user=pending_user, lock_remaining=0)

    is_configured = bool(account.get("totp_confirmed"))
    qr_data_uri = make_totp_qr_data_uri(pending_user, normalize_totp_secret(secret)) if not is_configured else ""
    lock_remaining = get_lock_remaining("admin_totp_blocked_until")
    if request.method == "POST":
        if lock_remaining > 0:
            flash(
                f"Admin verification locked. Try again in {lock_remaining} seconds.",
                "danger",
            )
            return render_template(
                "admin_verify_totp.html",
                pending_user=pending_user,
                lock_remaining=lock_remaining,
                is_configured=is_configured,
                qr_data_uri=qr_data_uri,
                secret=secret,
            )

        code = request.form.get("totp_code", "").strip()

        if not verify_current_totp(secret, code):
            failures = register_auth_failure(
                "admin_totp",
                user=pending_user,
                alert_action="TOTP_FAILED_3_TIMES",
                alert_details="Three failed admin TOTP attempts triggered a 2 minute lockout.",
            )
            log_security_event(
                pending_user,
                "TOTP_FAILED",
                "FAILED",
                {"attempt": failures, "scope": "admin_login"},
                event_type=EVENT_IDS_BLOCK,
                message=f"Admin TOTP failed for {pending_user} (attempt {failures})",
            )
            security_monitor.add_ids_alert_with_details(
                pending_user,
                "ADMIN_TOTP_FAILED",
                "high" if failures >= ADMIN_AUTH_MAX_ATTEMPTS else "medium",
                f"Failed admin TOTP verification attempt {failures}.",
            )
            remaining = get_lock_remaining("admin_totp_blocked_until")
            if remaining > 0:
                flash("Admin verification locked for 2 minutes after repeated failures.", "danger")
            else:
                flash("Invalid authenticator code.", "danger")
            return render_template(
                "admin_verify_totp.html",
                pending_user=pending_user,
                lock_remaining=remaining,
                is_configured=is_configured,
                qr_data_uri=qr_data_uri,
                secret=secret,
            )

        if not is_configured:
            try:
                update_sheet_user(pending_user, totp_confirmed=True)
            except GoogleSheetsConnectionError:
                app.logger.exception("Google Sheets admin TOTP confirmation failed for %s", pending_user)
                flash(sheets_error_message("save admin authenticator setup"), "danger")
                return render_template(
                    "admin_verify_totp.html",
                    pending_user=pending_user,
                    lock_remaining=0,
                    is_configured=is_configured,
                    qr_data_uri=qr_data_uri,
                    secret=secret,
                )

        clear_auth_attempt_state("admin_totp")
        sid = auth.create_session_for_user(pending_user)
        if not sid:
            flash("Unable to create an authenticated admin session.", "danger")
            return render_template(
                "admin_verify_totp.html",
                pending_user=pending_user,
                lock_remaining=0,
                is_configured=is_configured,
                qr_data_uri=qr_data_uri,
                secret=secret,
            )

        ids.reset()
        session["user"] = pending_user
        session["auth_sid"] = sid
        session["role"] = "admin"
        session["admin_totp_verified"] = True
        clear_admin_pending_auth()
        log_security_event(
            pending_user,
            "TOTP_SUCCESS",
            "SUCCESS",
            {"scope": "admin_login"},
            event_type=EVENT_OTP_VERIFIED,
            message=f"Admin TOTP verified for {pending_user}",
        )
        log_security_event(
            pending_user,
            "LOGIN_SUCCESS",
            "SUCCESS",
            {"role": "admin", "auth": "password+totp"},
            event_type=EVENT_LOGIN,
            message=f"Admin {pending_user} completed zero-trust login",
        )
        flash("Admin verification successful.", "success")
        return redirect(url_for("security_dashboard"))

    return render_template(
        "admin_verify_totp.html",
        pending_user=pending_user,
        lock_remaining=lock_remaining,
        is_configured=is_configured,
        qr_data_uri=qr_data_uri,
        secret=secret,
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        mobile = request.form.get("mobile", "").strip()
        totp_code = request.form.get("totp_code", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not mobile or not totp_code or not password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("forgot_password.html")

        try:
            account = get_account_by_username(username)
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets password reset lookup failed for %s", username)
            flash(sheets_error_message("reset your password"), "danger")
            return render_template("forgot_password.html")
        if not account or mobile != account.get("mobile"):
            seal.append(EVENT_IDS_BLOCK, f"Password reset denied for {username}: mobile mismatch", "system")
            flash("Account details do not match.", "danger")
            return render_template("forgot_password.html")

        if not account.get("totp_confirmed") or not verify_current_totp(
            account.get("totp_secret", ""), totp_code
        ):
            seal.append(EVENT_IDS_BLOCK, f"Password reset denied for {username}: invalid TOTP", "system")
            flash(
                "Invalid authenticator code. Try again and ensure your phone time is set to automatic.",
                "danger",
            )
            return render_template("forgot_password.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("forgot_password.html")

        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"[0-9]", password)
            or not re.search(r"[^A-Za-z0-9]", password)
        ):
            flash(
                "Password must be at least 8 characters long and include uppercase, "
                "lowercase, number, and special character.",
                "danger",
            )
            return render_template("forgot_password.html")

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode("utf-8")
        try:
            update_sheet_user(
                username,
                password_hash=password_hash,
            )
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets password reset update failed for %s", username)
            flash(sheets_error_message("reset your password"), "danger")
            return render_template("forgot_password.html")
        seal.append(EVENT_OTP_VERIFIED, f"Password reset completed for {username}", "system")
        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/logout")
def logout():
    user = current_user()
    if user:
        seal.append(EVENT_LOGOUT, f"User {user} logged out", user)
        security_monitor.add_seal_log(user, "LOGOUT", "SUCCESS", {"role": current_role()})
        kms.revoke_release(user)
        auth.logout()

    clear_preview_temp_file()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/authenticator/setup", methods=["GET", "POST"])
@login_required
def authenticator_setup():
    user = current_user()
    try:
        account = get_account_by_username(user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets authenticator lookup failed for %s", user)
        flash(sheets_error_message("load your authenticator settings"), "danger")
        return redirect(url_for("dashboard"))
    if not account:
        flash("Account not found.", "danger")
        return redirect(url_for("dashboard"))

    next_target = request.args.get("next", "download").strip().lower()
    if next_target not in {"download", "dashboard"}:
        next_target = "download"

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        try:
            secret = ensure_user_totp_secret(user)
        except GoogleSheetsConnectionError:
            app.logger.exception("Google Sheets authenticator secret load failed for %s", user)
            flash(sheets_error_message("load your authenticator settings"), "danger")
            return redirect(url_for("dashboard"))
        if not secret:
            flash("Authenticator secret is missing for this account.", "danger")
            return redirect(url_for("dashboard"))

        valid = verify_current_totp(secret, code)

        if not valid:
            seal.append(EVENT_IDS_BLOCK, "Invalid setup TOTP verification attempt", user)
            flash(
                "Invalid authenticator code. Try again with the latest code and ensure your phone time is set to automatic.",
                "danger",
            )
        else:
            try:
                update_sheet_user(
                    user,
                    totp_confirmed=True,
                )
            except GoogleSheetsConnectionError:
                app.logger.exception("Google Sheets authenticator update failed for %s", user)
                flash(sheets_error_message("save authenticator setup"), "danger")
                return redirect(url_for("authenticator_setup", next=next_target))
            seal.append(EVENT_OTP_VERIFIED, "TOTP setup completed", user)
            flash("Authenticator setup complete.", "success")
            return redirect(url_for(next_target))

    try:
        account = get_account_by_username(user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets authenticator reload failed for %s", user)
        flash(sheets_error_message("load your authenticator settings"), "danger")
        return redirect(url_for("dashboard"))
    try:
        secret = ensure_user_totp_secret(user)
    except GoogleSheetsConnectionError:
        app.logger.exception("Google Sheets authenticator secret refresh failed for %s", user)
        flash(sheets_error_message("load your authenticator settings"), "danger")
        return redirect(url_for("dashboard"))
    if not secret:
        flash("Authenticator secret is missing for this account.", "danger")
        return redirect(url_for("dashboard"))
    qr_data_uri = make_totp_qr_data_uri(user, normalize_totp_secret(secret))
    return render_template(
        "authenticator_setup.html",
        qr_data_uri=qr_data_uri,
        secret=secret,
        is_configured=bool(account and account.get("totp_confirmed")),
        next_target=next_target,
    )


@app.route("/dashboard")
@login_required
def dashboard():
    if is_admin():
        return redirect(url_for("security_dashboard"))
    user = current_user()
    my_docs = data_tier.list_owned_documents(user) if user else []
    log_count = seal.count()
    print("User:", user)
    print("Docs:", my_docs)
    return render_template(
        "dashboard.html",
        my_docs=my_docs,
        log_count=log_count,
    )


@app.route("/security-dashboard")
@admin_required
def security_dashboard():
    user = current_user() or "admin"
    log_security_event(
        user,
        "SECURITY_DASHBOARD_VIEW",
        "SUCCESS",
        {"ids_count": security_monitor.ids_alert_count(), "seal_count": security_monitor.seal_log_count()},
        event_type=EVENT_VIEW_LOGS,
        message="Admin viewed security dashboard",
    )
    ids_alerts = security_monitor.recent_ids_alerts(limit=5)
    seal_logs = security_monitor.recent_seal_logs(limit=5)
    return render_template(
        "security_dashboard.html",
        ids_alerts=ids_alerts,
        ids_alert_count=security_monitor.ids_alert_count(),
        seal_logs=seal_logs,
        seal_log_count=security_monitor.seal_log_count(),
    )


@app.route("/ids")
@admin_required
def ids_alerts():
    user = current_user() or "admin"
    log_security_event(
        user,
        "IDS_ALERTS_VIEW",
        "SUCCESS",
        {"count": security_monitor.ids_alert_count()},
        event_type=EVENT_VIEW_LOGS,
        message="Admin viewed IDS alerts",
    )
    return render_template("ids.html", alerts=security_monitor.recent_ids_alerts(limit=250))


@app.route("/seal")
@admin_required
def seal_logs():
    user = current_user() or "admin"
    log_security_event(
        user,
        "SEAL_LOGS_VIEW",
        "SUCCESS",
        {"count": security_monitor.seal_log_count()},
        event_type=EVENT_VIEW_LOGS,
        message="Admin viewed SEAL logs",
    )
    return render_template("seal_logs.html", logs=security_monitor.recent_seal_logs(limit=250))


@app.route("/seal/<int:log_id>")
@admin_required
def seal_detail(log_id: int):
    row = security_monitor.get_seal_log(log_id)
    if not row:
        abort(404)
    integrity_ok = security_monitor.verify_seal_log_integrity(row)
    user = current_user() or "admin"
    log_security_event(
        user,
        "SEAL_DETAIL_VIEW",
        "SUCCESS",
        {"log_id": log_id, "integrity_ok": integrity_ok},
        event_type=EVENT_VIEW_LOGS,
        message=f"Admin opened SEAL log {log_id}",
    )
    return render_template(
        "seal_detail.html",
        log=row,
        integrity_ok=integrity_ok,
        raw_log_data=row,
    )


@app.route("/documents")
@login_required
def documents():
    user = current_user()
    docs = data_tier.list_owned_documents(user) if user else []
    print("User:", user)
    print("Docs:", docs)
    return render_template("documents.html", docs=docs)


@app.route("/delete/<doc_id>", methods=["POST"])
@login_required
def delete_file(doc_id: str):
    user = current_user()
    get_owned_doc_or_404(user, doc_id)
    try:
        deleted = data_tier.delete_file(doc_id)
        if deleted:
            clear_preview_temp_file()
            flash("File deleted successfully.", "success")
        else:
            flash("Failed to delete file.", "danger")
    except Exception as exc:
        print("DELETE ERROR:", exc)
        flash("Failed to delete file.", "danger")
    return redirect(url_for("documents"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user = current_user()
    if request.method == "POST":
        file = request.files.get("file")
        keyword = normalize_search_keyword(request.form.get("keyword", ""))

        if not file or file.filename == "":
            flash("Please choose a file to upload.", "danger")
            return render_template("upload.html")

        original_filename = secure_filename(file.filename or "")
        if not original_filename:
            flash("Invalid file name.", "danger")
            return render_template("upload.html")
        if not is_allowed_upload(original_filename):
            allowed = ", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))
            flash(f"Unsupported file type. Allowed: {allowed}.", "danger")
            return render_template("upload.html")

        key = ensure_kms_key_for_user(user, get_account_by_username(user))
        if not key:
            flash("No encryption key found for user. Contact administrator.", "danger")
            return render_template("upload.html")

        engine = HybridCryptoEngine(key)
        plaintext = file.stream.read()
        if not plaintext:
            flash("Uploaded file is empty.", "danger")
            return render_template("upload.html")

        ciphertext, nonce = engine.encrypt(plaintext)
        file_type = get_doc_mimetype(original_filename)
        file_category = get_file_category(original_filename, file_type)

        name_part = os.path.splitext(original_filename)[0]
        keyword_terms = extract_search_terms(keyword)
        filename_terms = extract_search_terms(name_part)
        searchable_terms = keyword_terms + [
            term for term in filename_terms if term not in keyword_terms
        ]
        if not searchable_terms:
            searchable_terms = ["misc"]

        print("Upload keyword:", keyword)
        print("Upload terms:", searchable_terms)
        print("Upload file type:", file_type)
        print("Upload file category:", file_category)
        ore_tokens = [engine.generate_ore_token(term) for term in searchable_terms]
        doc_id = data_tier.store(
            ciphertext=ciphertext,
            nonce=nonce,
            ore_tokens=ore_tokens,
            owner=user,
            original_filename=original_filename,
            file_type=file_type,
        )

        seal.append(EVENT_UPLOAD, f"Uploaded document {doc_id}", user)
        security_monitor.add_seal_log(
            user,
            "FILE_UPLOAD",
            "SUCCESS",
            {"doc_id": doc_id, "filename": original_filename, "file_type": file_type},
        )
        flash(
            f"File '{original_filename}' encrypted and stored as {doc_id}.enc.",
            "success",
        )
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    user = current_user()
    results = None
    keyword = ""

    if request.method == "POST":
        keyword = normalize_search_keyword(request.form.get("keyword", ""))
        print("Keyword:", keyword)
        if not keyword:
            flash("Keyword is required.", "danger")
            return render_template("search.html", results=None, keyword="")

        allowed, msg = ids.record_and_check(keyword)
        if not allowed:
            seal.append(EVENT_IDS_BLOCK, msg, user)
            flash(msg, "danger")
            return render_template("search.html", results=None, keyword=keyword)

        if not ensure_kms_key_for_user(user, get_account_by_username(user)):
            flash("No encryption key found. Contact administrator.", "danger")
            return render_template("search.html", results=None, keyword=keyword)

        doc_ids = search_document_ids_for_user(user, keyword)

        seal.append(
            EVENT_SEARCH, f"Search '{keyword}' returned {len(doc_ids)} result(s)", user
        )

        results = []
        for doc_id in doc_ids:
            meta = data_tier.get_document_metadata(doc_id) or {}
            results.append(
                {
                    "doc_id": doc_id,
                    "original_filename": meta.get("original_filename", doc_id),
                }
            )
        print("Results:", results)
        if not results:
            flash("No documents found for this keyword.", "info")

    return render_template("search.html", results=results, keyword=keyword)


@app.route("/download", methods=["GET"])
@login_required
def download():
    flash("Use Download in Your Documents for direct file download.", "info")
    return redirect(url_for("documents"))


@app.route("/preview/<token>", methods=["GET"])
@login_required
def preview_temp_file(token: str):
    user = current_user()
    preview_meta = session.get(PREVIEW_SESSION_KEY) or {}
    if (
        not preview_meta
        or preview_meta.get("token") != token
        or preview_meta.get("owner") != user
    ):
        abort(404)

    expires_at = int(preview_meta.get("expires_at") or 0)
    if expires_at and time.time() > expires_at:
        clear_preview_temp_file()
        abort(404)

    preview_path = preview_meta.get("path", "")
    if not preview_path or not os.path.exists(preview_path):
        clear_preview_temp_file()
        abort(404)

    return send_file(
        preview_path,
        as_attachment=False,
        mimetype=preview_meta.get("mimetype") or "application/octet-stream",
        download_name=preview_meta.get("filename") or "preview.bin",
        max_age=0,
    )


@app.route("/view-encrypted/<doc_id>", methods=["GET"])
@login_required
def view_encrypted(doc_id: str):
    user = current_user()
    get_owned_doc_or_404(user, doc_id)
    payload = data_tier.get_encrypted_payload(doc_id)
    if not payload:
        abort(404)
    ciphertext, _nonce = payload
    metadata = data_tier.get_document_metadata(doc_id) or {}
    return render_template(
        "view_encrypted.html",
        doc_id=doc_id,
        original_filename=metadata.get("original_filename", "unknown"),
        ciphertext=encode_encrypted_bytes(ciphertext),
    )


@app.route("/view/<doc_id>", methods=["GET", "POST"])
@login_required
def view_document(doc_id: str):
    user = current_user()
    metadata = get_owned_doc_or_404(user, doc_id)
    account, redirect_response = ensure_user_totp_ready(user)
    if redirect_response:
        return redirect_response

    clear_expired_preview_temp_file()
    refresh_totp_lock_state()
    blocked_remaining = get_download_totp_lock_remaining()
    preview_mode = None
    preview_text = None
    preview_url = None
    preview_is_image = False

    if request.method == "POST":
        if verify_totp_for_doc_action(user, doc_id, "view"):
            plain, err = decrypt_document_for_user(user, doc_id)
            if err:
                flash(err, "danger")
            else:
                filename = metadata.get("original_filename", f"{doc_id}.bin")
                mimetype = metadata.get("file_type") or get_doc_mimetype(filename)
                file_category = get_file_category(filename, mimetype)
                if file_category == "text":
                    preview_mode = "text"
                    preview_text = plain.decode("utf-8", errors="replace")
                elif file_category == "image":
                    preview_mode = "inline"
                    preview_token = create_preview_temp_file(user, filename, mimetype, plain)
                    preview_url = url_for("preview_temp_file", token=preview_token)
                    preview_is_image = True
                elif file_category == "pdf":
                    seal.append(EVENT_DOWNLOAD, f"Viewed {doc_id}", user)
                    log_security_event(
                        user,
                        "VIEW",
                        "SUCCESS",
                        {"doc_id": doc_id, "filename": filename, "mode": "pdf"},
                        event_type=EVENT_DOWNLOAD,
                        message=f"Viewed document {doc_id}",
                    )
                    reset_download_totp_state()
                    return build_decrypted_file_response(
                        plain,
                        filename,
                        "application/pdf",
                        as_attachment=False,
                    )
                else:
                    seal.append(EVENT_DOWNLOAD, f"Viewed {doc_id}", user)
                    log_security_event(
                        user,
                        "VIEW",
                        "SUCCESS",
                        {"doc_id": doc_id, "filename": filename, "mode": "binary"},
                        event_type=EVENT_DOWNLOAD,
                        message=f"Viewed document {doc_id}",
                    )
                    reset_download_totp_state()
                    return build_decrypted_file_response(
                        plain,
                        filename,
                        mimetype,
                        as_attachment=True,
                    )

                if preview_mode or file_category == "pdf":
                    seal.append(EVENT_DOWNLOAD, f"Viewed {doc_id}", user)
                    log_security_event(
                        user,
                        "VIEW",
                        "SUCCESS",
                        {
                            "doc_id": doc_id,
                            "filename": filename,
                            "mode": "image" if preview_is_image else "text",
                        },
                        event_type=EVENT_DOWNLOAD,
                        message=f"Viewed document {doc_id}",
                    )
                    flash("Document decrypted successfully. See below.", "success")
                    session["totp_failures"] = 0
                    session.pop("download_blocked_until", None)

        blocked_remaining = get_download_totp_lock_remaining()

    return render_template(
        "view.html",
        doc=metadata,
        blocked_remaining=blocked_remaining,
        failed_attempts=int(session.get("totp_failures", 0) or 0),
        max_attempts=DOWNLOAD_TOTP_MAX_ATTEMPTS,
        needs_totp_setup=not bool(account and account.get("totp_confirmed")),
        preview_mode=preview_mode,
        preview_text=preview_text,
        preview_url=preview_url,
        preview_is_image=preview_is_image,
    )


@app.route("/download/<doc_id>", methods=["GET", "POST"])
@login_required
def download_document(doc_id: str):
    user = current_user()
    metadata = get_owned_doc_or_404(user, doc_id)
    account, redirect_response = ensure_user_totp_ready(user)
    if redirect_response:
        return redirect_response

    refresh_totp_lock_state()
    blocked_remaining = get_download_totp_lock_remaining()

    if request.method == "POST":
        if verify_totp_for_doc_action(user, doc_id, "download"):
            plain, err = decrypt_document_for_user(user, doc_id)
            if err:
                flash(err, "danger")
            else:
                filename = metadata.get("original_filename", f"{doc_id}.bin")
                mimetype = metadata.get("file_type") or get_doc_mimetype(filename)
                seal.append(EVENT_DOWNLOAD, f"Downloaded {doc_id}", user)
                log_security_event(
                    user,
                    "DOWNLOAD",
                    "SUCCESS",
                    {"doc_id": doc_id, "filename": filename},
                    event_type=EVENT_DOWNLOAD,
                    message=f"Downloaded document {doc_id}",
                )
                download_alert = security_monitor.track_download(user)
                if download_alert:
                    log_security_event(
                        user,
                        "MULTIPLE_DOWNLOADS",
                        "ALERT",
                        download_alert,
                        event_type=EVENT_IDS_BLOCK,
                        message="Repeated downloads triggered IDS monitoring",
                    )
                reset_download_totp_state()
                return build_decrypted_file_response(
                    plain,
                    filename,
                    mimetype,
                    as_attachment=True,
                )

        blocked_remaining = get_download_totp_lock_remaining()

    return render_template(
        "download_document.html",
        doc=metadata,
        blocked_remaining=blocked_remaining,
        failed_attempts=int(session.get("totp_failures", 0) or 0),
        max_attempts=DOWNLOAD_TOTP_MAX_ATTEMPTS,
        needs_totp_setup=not bool(account and account.get("totp_confirmed")),
    )


@app.route("/logs", methods=["GET", "POST"])
@admin_required
def logs():
    return redirect(url_for("seal_logs"))


# ----- Error handlers -----
@app.errorhandler(403)
def forbidden(_error):
    return (
        render_template(
            "error.html",
            title="Access Denied",
            message="You do not have permission to access this resource.",
        ),
        403,
    )


@app.errorhandler(RuntimeError)
def runtime_error(error):
    return (
        render_template(
            "error.html",
            title="Configuration Error",
            message=str(error),
        ),
        500,
    )


@app.errorhandler(404)
def not_found(_error):
    return (
        render_template(
            "error.html",
            title="Page Not Found",
            message="The page you are looking for does not exist.",
        ),
        404,
    )


@app.errorhandler(500)
def server_error(_error):
    return (
        render_template(
            "error.html",
            title="Server Error",
            message="An unexpected error occurred. Please try again.",
        ),
        500,
    )


if __name__ == "__main__":
    # In production, debug should be False and app should be served by WSGI server.
    app.run(debug=True)
