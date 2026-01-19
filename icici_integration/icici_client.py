import os
import json
import base64
import secrets

import frappe
import requests

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---- CONFIG DEFAULTS ----

DEFAULT_ICICI_URL = "https://apibankingonesandbox.icicibank.in/api/v1/composite-validation"
DEFAULT_X_PRIORITY = "0010"
DEFAULT_SERVICE = "IMPS_NAME_INQUIRY"


def get_icici_config() -> tuple:
    """
    Read ICICI config from site_config.json (frappe.conf).
    Falls back to sandbox defaults.

    Add these keys in site_config.json for production:
        "icici_url": "https://..../composite-validation",
        "icici_api_key": "xxxxxxxx",
        "icici_x_priority": "0010",
        "icici_service": "IMPS_NAME_INQUIRY"
    """
    conf = getattr(frappe, "conf", {}) or {}
    
    url = conf.get("icici_url") or DEFAULT_ICICI_URL
    api_key = conf.get("icici_api_key") or ""
    x_priority = conf.get("icici_x_priority") or DEFAULT_X_PRIORITY
    service = conf.get("icici_service") or DEFAULT_SERVICE
    
    if not api_key:
        frappe.throw(
            "ICICI API Key is not configured (key 'icici_api_key' in site_config.json)",
            title="ICICI Integration Error",
        )
    
    return url, api_key, x_priority, service


def get_cert_path() -> str:
    """
    Returns absolute path to icici_cert.pem inside the app module.
    """
    app_root = frappe.get_app_path("icici_integration")
    return os.path.join(app_root, "icici_integration", "icici_cert.pem")


def load_icici_public_key():
    """Load ICICI public key from the PEM certificate."""
    cert_path = get_cert_path()
    if not os.path.exists(cert_path):
        frappe.throw(
            f"ICICI certificate not found at {cert_path}",
            title="ICICI Integration Error",
        )
    
    with open(cert_path, "rb") as f:
        data = f.read()
    cert = x509.load_pem_x509_certificate(data, backend=default_backend())
    return cert.public_key()


def encrypt_inner_payload(inner_body: dict, request_id: str) -> dict:
    """
    Encrypt the inner JSON payload using:
    - AES-256-CBC (PKCS7 padding)
    - AES key encrypted with ICICI RSA public key (OAEP)
    Returns the envelope dict to send to ICICI.
    """
    # 1) Convert inner JSON to bytes (compact)
    plaintext = json.dumps(inner_body, separators=(",", ":")).encode("utf-8")

    # 2) Generate random AES key and IV
    aes_key = secrets.token_bytes(32)  # 256-bit key
    iv = secrets.token_bytes(16)       # 128-bit IV

    # 3) PKCS7 pad the plaintext
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # 4) AES-CBC encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 5) Encrypt AES key with ICICI public key (RSA-OAEP)
    pubkey = load_icici_public_key()
    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 6) Build envelope
    envelope = {
        "requestId": request_id,
        "service": ICICI_SERVICE,
        "encryptedKey": base64.b64encode(encrypted_key).decode("ascii"),
        "encryptedData": base64.b64encode(ciphertext).decode("ascii"),
        "oaepHashingAlgorithm": "NONE",  # as per ICICI doc/sample
        "iv": base64.b64encode(iv).decode("ascii"),
        "clientInfo": "",
        "optionalParam": "",
    }
    return envelope


def call_icici_name_inquiry(inner_body: dict) -> dict:
    """
    Builds the envelope, calls ICICI, and returns a dict with request + response.
    """
    url, api_key, x_priority, service = get_icici_config()
    
    request_id = inner_body["TranRefNo"]
    envelope = encrypt_inner_payload(inner_body, request_id)

    headers = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "apikey": api_key,
        "x-priority": x_priority,
    }

    try:
        resp = requests.post(url, json=envelope, headers=headers, timeout=60)
    except Exception as e:
        frappe.throw(
            f"Error calling ICICI API: {str(e)}",
            title="ICICI Integration Error",
        )

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"raw": resp.text}

    return {
        "success": resp.ok,
        "http_status": resp.status_code,
        "request_sent_to_icici": envelope,
        "icici_response_encrypted": resp_json,
    }

