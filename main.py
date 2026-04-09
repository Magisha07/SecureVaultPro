
from __future__ import annotations
import os
import sys

from auth import UserAuth
from crypto_engine import HybridCryptoEngine
from ids import BehavioralIDS
from otp_service import OTPService
from kms import KMS
from seal import (
    SEAL,
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
from data_tier import SecureDataTier


# ----- Global services (simulated backend) -----
def _create_services():
    """Initialize all modules. SEAL and KMS use fixed keys for demo."""
    auth = UserAuth()
    kms = KMS()
    # Single SEAL key for audit log encryption (in production: separate key management)
    seal_key = b"0123456789ABCDEF0123456789ABCDEF"
    seal = SEAL(seal_key)
    base_dir = os.path.abspath(os.path.dirname(__file__))
    data_tier = SecureDataTier(storage_dir=os.path.join(base_dir, "uploads"))
    otp_service = OTPService(digits=6, validity_seconds=300)
    ids = BehavioralIDS(bucket_capacity=10, refill_rate=2.0, pattern_window=5)
    return auth, kms, seal, data_tier, otp_service, ids


def seed_test_data(auth: UserAuth, kms: KMS, seal: SEAL, data_tier: SecureDataTier):
    """Insert demo users and sample encrypted data for academic demonstration."""
    # Admin and normal user
    auth.register("admin", "admin123", is_admin=True)
    auth.register("user1", "pass123", is_admin=False)
    # Keys for encrypt/decrypt (KMS stores per user)
    kms.store_key("admin", KMS.generate_key())
    kms.store_key("user1", KMS.generate_key())
    # Sample log entries
    seal.append(EVENT_REGISTER, "Admin account created", "system")
    seal.append(EVENT_REGISTER, "User user1 registered", "system")
    seal.append(EVENT_LOGIN, "Admin logged in", "admin")
    seal.append(EVENT_UPLOAD, "Sample document uploaded", "user1")
    seal.append(EVENT_SEARCH, "Search by keyword: sample", "user1")
    # Sample encrypted document (user1 owns it)
    key_u1 = kms.get_key_for_encrypt("user1")
    existing_u1_docs = data_tier.list_owned("user1")
    if key_u1 and not existing_u1_docs:
        engine = HybridCryptoEngine(key_u1)
        plain = b"Sample confidential report - Q4 2024"
        ct, nonce = engine.encrypt(plain)
        token = engine.generate_ore_token("sample")
        data_tier.store(
            ciphertext=ct,
            nonce=nonce,
            ore_tokens=[token],
            owner="user1",
            original_filename="sample_report.txt",
        )


def get_crypto_engine_for_user(kms: KMS, username: str, for_decrypt: bool):
    """Return HybridCryptoEngine for user. For decrypt, key must be released (after OTP)."""
    key = kms.get_key_if_released(username) if for_decrypt else kms.get_key_for_encrypt(username)
    if not key:
        return None
    return HybridCryptoEngine(key)


def menu():
    print("\n--- SecureVault Menu ---")
    print("1. Register")
    print("2. Login")
    print("3. Upload Data")
    print("4. Search Data")
    print("5. Download Data (OTP required)")
    print("6. View Logs (Admin only)")
    print("7. Exit")
    return input("Choice [1-7]: ").strip()


def do_register(auth: UserAuth, seal: SEAL):
    print("\n--- Register ---")
    u = input("Username: ").strip()
    p = input("Password: ").strip()
    if not u or not p:
        print("Username and password required.")
        return
    if auth.register(u, p, is_admin=False):
        seal.append(EVENT_REGISTER, f"New user registered: {u}", u)
        print("Registration successful. Please login.")
    else:
        print("Username already exists.")


def do_login(auth: UserAuth, kms: KMS, seal: SEAL, ids: BehavioralIDS):
    print("\n--- Login ---")
    u = input("Username: ").strip()
    p = input("Password: ").strip()
    if not u or not p:
        print("Username and password required.")
        return
    sid = auth.login(u, p)
    if sid:
        # Ensure user has a key in KMS (first-time login)
        if not kms.has_key(u):
            kms.store_key(u, KMS.generate_key())
        ids.reset()
        seal.append(EVENT_LOGIN, f"User {u} logged in", u)
        print(f"Logged in as {u}. Session ID: {sid}")
    else:
        print("Invalid credentials.")


def do_upload(auth: UserAuth, kms: KMS, seal: SEAL, data_tier: SecureDataTier):
    user = auth.get_current_user()
    if not user:
        print("Please login first.")
        return
    key = kms.get_key_for_encrypt(user)
    if not key:
        print("No encryption key for user. Contact admin.")
        return
    print("\n--- Upload Data ---")
    data = input("Enter data to encrypt and store: ").strip()
    if not data:
        print("No data entered.")
        return
    engine = HybridCryptoEngine(key)
    ciphertext, nonce = engine.encrypt(data.encode())
    # ORE token from a "keyword" for search demo (e.g. first word or user-defined)
    keyword = input("Keyword for search index (default: first word): ").strip() or data.split()[0] if data.split() else "misc"
    ore_token = engine.generate_ore_token(keyword)
    doc_id = data_tier.store(ciphertext, nonce, [ore_token], user)
    seal.append(EVENT_UPLOAD, f"Uploaded document {doc_id}", user)
    print(f"Stored encrypted. Document ID: {doc_id}")


def do_search(auth: UserAuth, kms: KMS, seal: SEAL, data_tier: SecureDataTier, ids: BehavioralIDS):
    user = auth.get_current_user()
    if not user:
        print("Please login first.")
        return
    print("\n--- Search Data ---")
    keyword = input("Search keyword: ").strip()
    if not keyword:
        print("Keyword required.")
        return
    # Behavioral IDS: record access (resource_id = keyword for rate/pattern check)
    allowed, msg = ids.record_and_check(keyword)
    if not allowed:
        seal.append(EVENT_IDS_BLOCK, msg, user)
        print(msg)
        return
    key = kms.get_key_for_encrypt(user)
    if not key:
        print("No encryption key. Contact admin.")
        return
    engine = HybridCryptoEngine(key)
    ore_token = engine.generate_ore_token_for_search(keyword)
    doc_ids = data_tier.search_by_ore_token(ore_token)
    # Filter to own documents only
    doc_ids = [d for d in doc_ids if data_tier.get_owner(d) == user]
    seal.append(EVENT_SEARCH, f"Search '{keyword}' returned {len(doc_ids)} result(s)", user)
    if not doc_ids:
        print("No documents found for this keyword.")
    else:
        print(f"Found document ID(s): {', '.join(doc_ids)}")


def do_download(
    auth: UserAuth,
    kms: KMS,
    seal: SEAL,
    data_tier: SecureDataTier,
    otp_service: OTPService,
    ids: BehavioralIDS,
):
    user = auth.get_current_user()
    if not user:
        print("Please login first.")
        return
    my_docs = data_tier.list_owned(user)
    if not my_docs:
        print("You have no stored documents.")
        return
    print("\n--- Download Data (OTP required) ---")
    print("Your documents:", ", ".join(my_docs))
    doc_id = input("Document ID to download: ").strip()
    if doc_id not in my_docs:
        print("Not your document or invalid ID.")
        return
    allowed, msg = ids.record_and_check(doc_id)
    if not allowed:
        seal.append(EVENT_IDS_BLOCK, msg, user)
        print(msg)
        return
    # Zero-Trust: generate OTP and simulate OOB send
    otp = otp_service.generate(user)
    otp_service.simulate_send_to_console(otp, "Download / Decrypt data")
    seal.append(EVENT_OTP_SENT, f"OTP sent for download {doc_id}", user)
    user_otp = input("Enter OTP from console: ").strip()
    if not otp_service.verify(user_otp):
        print("Invalid or expired OTP. Decryption denied.")
        return
    seal.append(EVENT_OTP_VERIFIED, f"OTP verified for {doc_id}", user)
    # KMS releases key only after OTP
    kms.release_key_after_otp(user)
    engine = get_crypto_engine_for_user(kms, user, for_decrypt=True)
    if not engine:
        print("Key not available.")
        return
    payload = data_tier.get_encrypted_payload(doc_id)
    if not payload:
        print("Document not found.")
        return
    ciphertext, nonce = payload
    try:
        plain = engine.decrypt(ciphertext, nonce)
        seal.append(EVENT_DOWNLOAD, f"Downloaded {doc_id}", user)
        print("Decrypted data:", plain.decode())
    except Exception as e:
        print("Decryption failed:", e)
    finally:
        kms.revoke_release(user)


def do_view_logs(auth: UserAuth, seal: SEAL):
    if not auth.is_admin():
        print("Admin only.")
        return
    print("\n--- View Logs (SEAL - Search by event type) ---")
    seal.append(EVENT_VIEW_LOGS, "Admin viewed logs", auth.get_current_user() or "admin")
    event_type = input("Event type to search (or press Enter for all): ").strip()
    if event_type:
        entries = seal.search_by_event_type(event_type)
        print(f"\nEntries for event '{event_type}':")
    else:
        entries = seal.get_all_decrypted()
        print("\nAll log entries:")
    for e in entries:
        print(" ", e)


def main():
    auth, kms, seal, data_tier, otp_service, ids = _create_services()
    seed_test_data(auth, kms, seal, data_tier)

    print("=" * 60)
    print("  SecureVault – Hybrid ORE with Zero-Trust & Behavioral IDS")
    print("  Console prototype. Demo: admin/admin123, user1/pass123")
    print("=" * 60)

    while True:
        choice = menu()
        if choice == "1":
            do_register(auth, seal)
        elif choice == "2":
            do_login(auth, kms, seal, ids)
        elif choice == "3":
            do_upload(auth, kms, seal, data_tier)
        elif choice == "4":
            do_search(auth, kms, seal, data_tier, ids)
        elif choice == "5":
            do_download(auth, kms, seal, data_tier, otp_service, ids)
        elif choice == "6":
            do_view_logs(auth, seal)
        elif choice == "7":
            if auth.get_current_user():
                seal.append(EVENT_LOGOUT, f"User {auth.get_current_user()} logged out", auth.get_current_user())
                kms.revoke_release(auth.get_current_user())
                auth.logout()
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

