"""
SecureVault - Secure Data Tier
==============================
Persistent encrypted storage for uploaded files.
Stores:
- Ciphertext on disk (uploads/doc_<id>.enc)
- Metadata in uploads/metadata.json
- ORE tokens for keyword search
- Owner mapping for authorization checks
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class SecureDataTier:
    """
    Persistent secure store:
    - records: doc_id -> metadata record
    - ore_index: list of (ore_token, doc_id) for search
    - owner: doc_id -> username
    """

    def __init__(self, storage_dir: Optional[str] = None):
        base_dir = os.path.abspath(os.path.dirname(__file__))
        self._storage_dir = storage_dir or os.path.join(base_dir, "uploads")
        self._metadata_path = os.path.join(self._storage_dir, "metadata.json")

        os.makedirs(self._storage_dir, exist_ok=True)

        self._records: Dict[str, Dict[str, Any]] = {}
        self._ore_index: List[Tuple[bytes, str]] = []
        self._owners: Dict[str, str] = {}
        self._next_id = 1
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not os.path.exists(self._metadata_path):
            return
        try:
            with open(self._metadata_path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except Exception:
            return

        records = raw.get("records", {})
        if not isinstance(records, dict):
            return

        self._records = {}
        self._ore_index = []
        self._owners = {}

        for doc_id, record in records.items():
            if not isinstance(record, dict):
                continue
            self._records[doc_id] = record
            owner = record.get("owner")
            if isinstance(owner, str):
                self._owners[doc_id] = owner
            for token in self._decode_record_tokens(record):
                self._ore_index.append((token, doc_id))

        self._ore_index.sort(key=lambda item: item[0])
        self._next_id = self._compute_next_id()

    def _compute_next_id(self) -> int:
        highest = 0
        for doc_id in self._records.keys():
            if not doc_id.startswith("doc_"):
                continue
            suffix = doc_id.split("_", 1)[1]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
        return highest + 1

    def _persist_metadata(self) -> None:
        payload = {
            "records": self._records,
            "updated_at": int(time.time()),
        }
        tmp_path = f"{self._metadata_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, indent=2)
        os.replace(tmp_path, self._metadata_path)

    def _decode_record_tokens(self, record: Dict[str, Any]) -> List[bytes]:
        token_values = record.get("ore_tokens_b64")
        if not isinstance(token_values, list) or not token_values:
            token_values = [record.get("ore_token_b64", "")]

        decoded: List[bytes] = []
        for token_b64 in token_values:
            if not isinstance(token_b64, str) or not token_b64:
                continue
            try:
                token = base64.b64decode(token_b64.encode("ascii"), validate=True)
            except Exception:
                continue
            if token:
                decoded.append(token)
        return decoded

    def store(
        self,
        ciphertext: bytes,
        nonce: bytes,
        ore_tokens: List[bytes],
        owner: str,
        original_filename: str = "document.bin",
        file_type: str = "application/octet-stream",
    ) -> str:
        """
        Store encrypted payload and metadata. Returns document id.
        """
        doc_id = f"doc_{self._next_id}"
        self._next_id += 1

        encrypted_name = f"{doc_id}.enc"
        file_path = os.path.join(self._storage_dir, encrypted_name)
        with open(file_path, "wb") as handle:
            handle.write(ciphertext)

        unique_tokens: List[bytes] = []
        seen_tokens = set()
        for token in ore_tokens:
            if not token or token in seen_tokens:
                continue
            unique_tokens.append(token)
            seen_tokens.add(token)

        record = {
            "doc_id": doc_id,
            "original_filename": original_filename,
            "file_type": file_type,
            "owner": owner,
            "file_path": file_path,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ore_token_b64": base64.b64encode(unique_tokens[0]).decode("ascii")
            if unique_tokens
            else "",
            "ore_tokens_b64": [
                base64.b64encode(token).decode("ascii") for token in unique_tokens
            ],
            "created_at": int(time.time()),
        }
        self._records[doc_id] = record
        self._owners[doc_id] = owner
        for token in unique_tokens:
            self._ore_index.append((token, doc_id))
        self._ore_index.sort(key=lambda item: item[0])
        self._persist_metadata()
        return doc_id

    def get_encrypted_payload(self, doc_id: str) -> Optional[Tuple[bytes, bytes]]:
        """
        Return (ciphertext, nonce) for doc_id. No plaintext.
        """
        record = self._records.get(doc_id)
        if not record:
            return None
        file_path = record.get("file_path")
        nonce_b64 = record.get("nonce_b64")
        if not file_path or not nonce_b64:
            return None
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "rb") as handle:
                ciphertext = handle.read()
            nonce = base64.b64decode(str(nonce_b64).encode("ascii"), validate=True)
        except Exception:
            return None
        return ciphertext, nonce

    def get_document_metadata(self, doc_id: str) -> Optional[Dict[str, Any]]:
        record = self._records.get(doc_id)
        if not record:
            return None
        return dict(record)

    def get_owner(self, doc_id: str) -> Optional[str]:
        return self._owners.get(doc_id)

    def search_by_ore_token(self, target_token: bytes) -> List[str]:
        """
        Search by ORE token: find doc_ids whose token equals target_token.
        """
        matches: List[str] = []
        seen = set()
        for token, doc_id in self._ore_index:
            if token != target_token or doc_id in seen:
                continue
            matches.append(doc_id)
            seen.add(doc_id)
        return matches

    def list_owned(self, username: str) -> List[str]:
        """
        List document ids owned by user (ids only; no plaintext).
        """
        return [doc_id for doc_id, owner in self._owners.items() if owner == username]

    def list_owned_documents(self, username: str) -> List[Dict[str, Any]]:
        """
        List metadata records for documents owned by user.
        """
        docs: List[Dict[str, Any]] = []
        for record in self._records.values():
            if record.get("owner") != username:
                continue
            docs.append(
                {
                    "doc_id": record.get("doc_id", ""),
                    "original_filename": record.get("original_filename", "unknown"),
                    "file_type": record.get("file_type", "application/octet-stream"),
                    "owner": record.get("owner", ""),
                    "file_path": record.get("file_path", ""),
                }
            )
        docs.sort(key=lambda item: item["doc_id"])
        return docs

    def list_all_ids(self) -> List[str]:
        return list(self._records.keys())

    def debug_tokens(self) -> List[Dict[str, Any]]:
        debug_rows: List[Dict[str, Any]] = []
        for doc_id, record in sorted(self._records.items()):
            debug_rows.append(
                {
                    "doc_id": doc_id,
                    "owner": record.get("owner"),
                    "tokens": record.get("ore_tokens_b64")
                    or [record.get("ore_token_b64", "")],
                }
            )
        return debug_rows

    def delete_file(self, doc_id: str) -> bool:
        record = self._records.get(doc_id)
        if not record:
            return False

        file_path = record.get("file_path", "")
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

        self._records.pop(doc_id, None)
        self._owners.pop(doc_id, None)
        self._ore_index = [
            (token, indexed_doc_id)
            for token, indexed_doc_id in self._ore_index
            if indexed_doc_id != doc_id
        ]
        self._persist_metadata()
        return True
