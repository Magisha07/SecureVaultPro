import json
import os
import re
from typing import Any

import gspread
from oauth2client.service_account import ServiceAccountCredentials


SCOPE = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SPREADSHEET_NAME = "SecureVault_DB"
WORKSHEET_NAME = (os.environ.get("SECUREVAULT_WORKSHEET_NAME") or "").strip()
DEFAULT_WORKSHEET_FALLBACK = "Sheet1"
SERVICE_ACCOUNT_FILE = os.path.abspath(
    os.path.join(
        BASE_DIR,
        (
    os.environ.get("SECUREVAULT_GOOGLE_CREDENTIALS") or "securevault-api-key.json"
        ).strip(),
    )
)
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
CURRENT_COLUMNS = [
    "username",
    "email",
    "password_hash",
    "totp_secret",
    "totp_confirmed",
    "active",
    "role",
]
LEGACY_COLUMNS = [
    "username",
    "email",
    "mobile",
    "password_hash",
    "totp_secret",
    "totp_confirmed",
    "active",
    "role",
]


class GoogleSheetsConnectionError(RuntimeError):
    """Raised when Google Sheets authorization or access fails."""


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.fullmatch(normalize_email(email)))


def _authorize_client():
    try:
        print(f"GOOGLE CREDENTIALS PATH: {SERVICE_ACCOUNT_FILE}")
        if not os.path.exists(SERVICE_ACCOUNT_FILE):
            raise FileNotFoundError(
                f"Google service account file was not found: {SERVICE_ACCOUNT_FILE}"
            )
        with open(SERVICE_ACCOUNT_FILE, "r", encoding="utf-8") as credentials_file:
            credentials_data = json.load(credentials_file)
        print("GOOGLE CLIENT EMAIL:", credentials_data.get("client_email"))
        creds = ServiceAccountCredentials.from_json_keyfile_name(
            SERVICE_ACCOUNT_FILE, SCOPE
        )
        client = gspread.authorize(creds)
        print("Google Sheets client authorization succeeded.")
        return client
    except Exception as exc:
        print("GOOGLE SHEETS ERROR:", exc)
        raise GoogleSheetsConnectionError(
            f"Failed to authorize Google Sheets using '{SERVICE_ACCOUNT_FILE}'. "
            "Confirm the JSON key is valid and that both Google Sheets API and Google Drive API are enabled."
        ) from exc


def get_sheet():
    try:
        client = _authorize_client()
        spreadsheet = client.open(SPREADSHEET_NAME)
        print("Connected to sheet:", spreadsheet.title)
        if WORKSHEET_NAME:
            worksheet = spreadsheet.worksheet(WORKSHEET_NAME)
        else:
            worksheet = spreadsheet.sheet1
    except Exception as exc:
        print("GOOGLE SHEETS ERROR:", exc)
        worksheet_name = WORKSHEET_NAME or DEFAULT_WORKSHEET_FALLBACK
        raise GoogleSheetsConnectionError(
            f"Failed to open Google Sheet '{SPREADSHEET_NAME}' worksheet '{worksheet_name}'. Details: {exc}"
        ) from exc
    print(f"GOOGLE SPREADSHEET: {spreadsheet.title}")
    print(f"GOOGLE WORKSHEET: {worksheet.title}")
    print("USING GOOGLE SHEET:", worksheet)
    return worksheet


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = {str(key).strip(): value for key, value in record.items()}
    normalized["username"] = str(normalized.get("username", "")).strip()
    normalized["email"] = normalize_email(str(normalized.get("email", "")))
    normalized["mobile"] = str(normalized.get("mobile", "")).strip()
    normalized["password_hash"] = str(normalized.get("password_hash", "")).strip()
    normalized["totp_secret"] = str(normalized.get("totp_secret", "")).strip()
    normalized["totp_confirmed"] = _to_bool(normalized.get("totp_confirmed", False))
    normalized["active"] = _to_bool(normalized.get("active", True))
    role = str(normalized.get("role", "")).strip().lower()
    normalized["role"] = role if role in {"admin", "user"} else "user"
    return normalized


def _get_sheet_headers(sheet) -> list[str]:
    return [value.strip() for value in sheet.row_values(1)]


def _build_row_for_headers(headers: list[str], values_by_header: dict[str, Any]) -> list[Any]:
    row = []
    for header in headers:
        if header == "mobile":
            row.append("")
        else:
            row.append(values_by_header.get(header, ""))
    return row


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y"}:
        return True
    if text in {"0", "false", "no", "n", ""}:
        return False
    return bool(value)


def ensure_headers(sheet) -> None:
    normalized_headers = _get_sheet_headers(sheet)
    if normalized_headers == CURRENT_COLUMNS or normalized_headers == LEGACY_COLUMNS:
        return
    if not any(normalized_headers):
        sheet.update(range_name="A1:G1", values=[CURRENT_COLUMNS])
        return
    if len(normalized_headers) < len(CURRENT_COLUMNS):
        padded_headers = normalized_headers + CURRENT_COLUMNS[len(normalized_headers) :]
        sheet.update(range_name="A1:G1", values=[padded_headers])


def fetch_all_users() -> list[dict[str, Any]]:
    sheet = get_sheet()
    ensure_headers(sheet)
    records = sheet.get_all_records()
    print("All records:", records)
    print("ALL USERS:", records)
    return [_normalize_record(record) for record in records if isinstance(record, dict)]


def get_user(username: str) -> dict[str, Any] | None:
    normalized_username = (username or "").strip()
    if not normalized_username:
        return None
    for record in fetch_all_users():
        if record.get("username") == normalized_username:
            return record
    return None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    normalized = normalize_email(email)
    if not normalized:
        return None
    for record in fetch_all_users():
        if record.get("email") == normalized:
            return record
    return None


def email_exists(email: str) -> bool:
    normalized = normalize_email(email)
    if not normalized:
        return False
    for record in fetch_all_users():
        if normalize_email(record.get("email", "")) == normalized:
            return True
    return False


def username_exists(username: str) -> bool:
    normalized_username = (username or "").strip()
    if not normalized_username:
        return False
    for record in fetch_all_users():
        if record.get("username") == normalized_username:
            return True
    return False


def register_user(
    username: str,
    email: str,
    password_hash: str,
    totp_secret: str,
    *,
    totp_confirmed: bool = False,
    active: bool = True,
    role: str = "user",
) -> None:
    normalized_username = (username or "").strip()
    normalized_email = normalize_email(email)
    normalized_role = (role or "user").strip().lower()
    if not normalized_username:
        raise ValueError("Username is required.")
    if not is_valid_email(normalized_email):
        raise ValueError("A valid email address is required.")
    if normalized_role not in {"admin", "user"}:
        raise ValueError("Role must be either 'admin' or 'user'.")
    if username_exists(normalized_username):
        raise ValueError("Username already exists in Google Sheets.")
    if email_exists(normalized_email):
        raise ValueError("Email already exists in Google Sheets.")

    sheet = get_sheet()
    ensure_headers(sheet)
    headers = _get_sheet_headers(sheet)
    sheet.append_row(
        _build_row_for_headers(
            headers,
            {
                "username": normalized_username,
                "email": normalized_email,
                "password_hash": password_hash,
                "totp_secret": totp_secret,
                "totp_confirmed": 1 if totp_confirmed else 0,
                "active": 1 if active else 0,
                "role": normalized_role,
            },
        ),
        value_input_option="RAW",
    )


def update_user(
    username: str,
    *,
    email: str | None = None,
    mobile: str | None = None,
    password_hash: str | None = None,
    totp_secret: str | None = None,
    totp_confirmed: bool | None = None,
    active: bool | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    normalized_username = (username or "").strip()
    if not normalized_username:
        raise ValueError("Username is required.")

    sheet = get_sheet()
    ensure_headers(sheet)
    headers = _get_sheet_headers(sheet)
    values = sheet.get_all_values()
    if not values:
        raise ValueError("Google Sheet is missing headers.")

    try:
        row_index = next(
            idx
            for idx, row in enumerate(values[1:], start=2)
            if len(row) > 0 and row[0].strip() == normalized_username
        )
    except StopIteration as exc:
        raise ValueError(f"User '{normalized_username}' not found in Google Sheets.") from exc

    existing_user = get_user(normalized_username) or {}
    next_email = normalize_email(email if email is not None else existing_user.get("email", ""))
    if email is not None and not is_valid_email(next_email):
        raise ValueError("A valid email address is required.")

    if email is not None:
        duplicate = get_user_by_email(next_email)
        if duplicate and duplicate.get("username") != normalized_username:
            raise ValueError("Email already exists in Google Sheets.")

    updated_user = {
        "username": normalized_username,
        "email": next_email,
        "mobile": (mobile if mobile is not None else existing_user.get("mobile", "")).strip(),
        "password_hash": (
            password_hash
            if password_hash is not None
            else str(existing_user.get("password_hash", "")).strip()
        ),
        "totp_secret": (
            totp_secret
            if totp_secret is not None
            else str(existing_user.get("totp_secret", "")).strip()
        ),
        "totp_confirmed": (
            _to_bool(totp_confirmed)
            if totp_confirmed is not None
            else _to_bool(existing_user.get("totp_confirmed", False))
        ),
        "active": (
            _to_bool(active)
            if active is not None
            else _to_bool(existing_user.get("active", True))
        ),
        "role": (
            str(role).strip().lower()
            if role is not None
            else str(existing_user.get("role", "user")).strip().lower()
        ),
    }
    if updated_user["role"] not in {"admin", "user"}:
        raise ValueError("Role must be either 'admin' or 'user'.")

    row = _build_row_for_headers(
        headers,
        {
            "username": updated_user["username"],
            "email": updated_user["email"],
            "password_hash": updated_user["password_hash"],
            "totp_secret": updated_user["totp_secret"],
            "totp_confirmed": 1 if updated_user["totp_confirmed"] else 0,
            "active": 1 if updated_user["active"] else 0,
            "role": updated_user["role"],
        },
    )
    end_column = chr(ord("A") + len(headers) - 1)
    sheet.update(range_name=f"A{row_index}:{end_column}{row_index}", values=[row])
    return _normalize_record(updated_user)
