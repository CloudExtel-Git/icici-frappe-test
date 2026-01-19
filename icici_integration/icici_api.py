from __future__ import annotations

import os
import json
import base64
import datetime
from typing import Tuple, Any, Dict, Optional

import requests
import frappe
from frappe import _

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# CONFIG HELPERS
# ---------------------------------------------------------------------------

DEFAULT_ICICI_URL = "https://apibankingonesandbox.icicibank.in/api/v1/composite-validation"
DEFAULT_X_PRIORITY = "0010"
DEFAULT_SERVICE = "IMPS_NAME_INQUIRY"


def get_icici_config() -> Tuple[str, str, str, str]:
    """
    Read ICICI config from site_config.json (frappe.conf),
    falling back to sandbox defaults.

    Add these keys in site_config.json on your real site for prod:

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
            _("ICICI API Key is not configured (key 'icici_api_key' in site_config.json)"),
            title=_("ICICI Integration Error"),
        )

    return url, api_key, x_priority, service


# ---------------------------------------------------------------------------
# CERTIFICATE LOADING
# ---------------------------------------------------------------------------

def get_cert_path() -> str:
    """
    Returns absolute path to icici_cert.pem inside the app module:
        apps/icici_integration/icici_integration/icici_cert.pem
    """
    app_root = frappe.get_app_path("icici_integration")  # /home/.../apps/icici_integration
    return os.path.join(app_root, "icici_integration", "icici_cert.pem")



def load_icici_public_key():
    """
    Load ICICI's public key from icici_cert.pem (X.509 certificate).
    """
    cert_path = get_cert_path()
    if not os.path.exists(cert_path):
        frappe.throw(
            _("ICICI certificate not found at {0}").format(cert_path),
            title=_("ICICI Integration Error"),
        )

    with open(cert_path, "rb") as f:
        data = f.read()

    cert = x509.load_pem_x509_certificate(data, backend=default_backend())
    return cert.public_key()


# ---------------------------------------------------------------------------
# ENCRYPTION HELPERS
# ---------------------------------------------------------------------------

def encrypt_inner_payload(inner_body: Dict[str, Any], request_id: str, service: str) -> Dict[str, Any]:
    """
    Encrypt the inner JSON payload using:
    - AES-256-CBC with PKCS7 padding
    - AES key encrypted using ICICI RSA public key (OAEP SHA-256)
    """

    # 1) Convert JSON to compact bytes
    plaintext = json.dumps(inner_body, separators=(",", ":")).encode("utf-8")

    # 2) Random AES key + IV
    aes_key = os.urandom(32)  # 256-bit
    iv = os.urandom(16)       # 128-bit

    # 3) PKCS7 padding to block size 128 bits
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # 4) AES-CBC encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 5) Encrypt AES key with ICICI public key
    pubkey = load_icici_public_key()
    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 6) Build envelope in ICICI format
    envelope = {
        "requestId": request_id,
        "service": service,
        "encryptedKey": base64.b64encode(encrypted_key).decode("ascii"),
        "encryptedData": base64.b64encode(ciphertext).decode("ascii"),
        # Docs often show "NONE" here, we keep that unless ICICI tells otherwise
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(iv).decode("ascii"),
        "clientInfo": "",
        "optionalParam": "",
    }

    return envelope


# ---------------------------------------------------------------------------
# CORE CALL TO ICICI
# ---------------------------------------------------------------------------

def call_icici_name_inquiry(
    bene_acc: str,
    bene_ifsc: str,
    rem_name: str,
    rem_mobile: str,
    tran_ref: Optional[str] = None,
) -> Tuple[bool, int, Any]:
    """
    Low-level helper: builds inner JSON, encrypts, hits ICICI API,
    returns (success_flag, http_status, parsed_response_or_text).
    """
    url, api_key, x_priority, service = get_icici_config()

    if not tran_ref:
        tran_ref = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

    inner = {
        "BeneAccNo": bene_acc,
        "BeneIFSC": bene_ifsc,
        "TranRefNo": tran_ref,
        "PaymentRef": "IMPSTransfer",
        "RemName": rem_name,
        "RemMobile": rem_mobile,
        "RetailerCode": "rcode",
        "PassCode": "447c4524c9074b8c97e3a3c40ca7458d",
        "TransactionDate": tran_ref,
        "Channel": "APICORPBC",
        "BcID": "IBCKer00055",
    }

    logger = frappe.logger("icici_integration")
    logger.info("ICICI INNER PAYLOAD: {0}".format(inner))

    try:
        envelope = encrypt_inner_payload(inner, tran_ref, service)
    except Exception as e:
        frappe.throw(
            _("Failed to encrypt payload for ICICI: {0}").format(e),
            title=_("ICICI Integration Error"),
        )

    logger.info("ICICI ENVELOPE: {0}".format(envelope))

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
            _("Error calling ICICI API: {0}").format(e),
            title=_("ICICI Integration Error"),
        )

    status = resp.status_code

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = resp.text

    logger.info("ICICI RESPONSE [{0}]: {1}".format(status, resp_json))

    return bool(resp.ok), status, resp_json


# ---------------------------------------------------------------------------
# PUBLIC API ENDPOINT – FOR POSTMAN / OTHER SYSTEMS
# ---------------------------------------------------------------------------

@frappe.whitelist(allow_guest=True)
def icici_name_inquiry(
    BeneAccNo: str,
    BeneIFSC: str,
    RemName: str,
    RemMobile: str,
    TranRefNo: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Public, whitelisted method to call from Postman:

    POST /api/method/icici_integration.icici_api.icici_name_inquiry

    JSON body:
    {
      "BeneAccNo": "1234567890",
      "BeneIFSC": "ICIC0000011",
      "RemName": "Excel Telesonic",
      "RemMobile": "9999988888",
      "TranRefNo": "20251205123000"   // optional
    }
    """

    bene_acc = (BeneAccNo or "").strip()
    bene_ifsc = (BeneIFSC or "").strip()
    rem_name = (RemName or "").strip()
    rem_mobile = (RemMobile or "").strip()

    if not bene_acc or not bene_ifsc or not rem_name or not rem_mobile:
        frappe.throw(
            _("BeneAccNo, BeneIFSC, RemName and RemMobile are required."),
            title=_("ICICI Integration Error"),
        )

    ok, http_status, resp_json = call_icici_name_inquiry(
        bene_acc=bene_acc,
        bene_ifsc=bene_ifsc,
        rem_name=rem_name,
        rem_mobile=rem_mobile,
        tran_ref=TranRefNo,
    )

    return {
        "success": ok,
        "http_status": http_status,
        "icici_response_encrypted": resp_json,
    }


# ---------------------------------------------------------------------------
# SUPPLIER HELPER – VERIFY BANK FROM SUPPLIER FIELDS
# ---------------------------------------------------------------------------

@frappe.whitelist()
def verify_supplier_bank(supplier):
    """
    Verify the bank account of a Supplier using ICICI IMPS Name Inquiry.

    Uses Supplier fields:
      - custom_bank_account_number
      - custom_bank_ifsc_code

    Optionally writes back status fields if they exist on Supplier:
      - custom_bank_verified (Check)
      - custom_icici_account_name (Data)
      - custom_icici_verified_on (Datetime)
      - custom_icici_raw_response (Long Text)
      - custom_icici_status (Data)
    """

    doc = frappe.get_doc("Supplier", supplier)

    # --------- Read account details from Supplier ----------
    bene_acc = (doc.get("custom_bank_account_number") or "").strip()
    bene_ifsc = (doc.get("custom_bank_ifsc_code") or "").strip()

    if not bene_acc or not bene_ifsc:
        frappe.throw(
            "Bank Account Number (custom_bank_account_number) and "
            "IFSC (custom_bank_ifsc_code) are required on Supplier before verification."
        )

    rem_name = (doc.supplier_name or supplier).strip()
    rem_mobile = (
        doc.get("mobile_no")
        or doc.get("phone")
        or "9999999999"  # fallback
    )
    rem_mobile = str(rem_mobile).strip()

    tran_ref = frappe.utils.now_datetime().strftime("%Y%m%d%H%M%S")

    # --------- Call the common ICICI helper ----------
    ok, http_status, resp_json = call_icici_name_inquiry(
        bene_acc=bene_acc,
        bene_ifsc=bene_ifsc,
        rem_name=rem_name,
        rem_mobile=rem_mobile,
        tran_ref=tran_ref,
    )

    # --------- Try to interpret ICICI response (we'll refine once we see real JSON) ----------
    match_flag = None
    bene_name = None
    data_block = None

    if isinstance(resp_json, dict):
        # ICICI might wrap data; adjust once you see real structure in custom_icici_raw_response
        data_block = resp_json.get("data") or resp_json.get("response") or resp_json

        if isinstance(data_block, dict):
            bene_name = (
                data_block.get("BeneName")
                or data_block.get("beneName")
                or data_block.get("accountName")
            )
            match_flag = (
                data_block.get("matchFlag")
                or data_block.get("status")
                or resp_json.get("status")
            )

    meta = doc.meta

    # Save raw ICICI response (for debugging / audit)
    if meta.has_field("custom_icici_raw_response"):
        doc.db_set("custom_icici_raw_response", frappe.as_json(resp_json), commit=False)

    # Save verification timestamp
    if meta.has_field("custom_icici_verified_on"):
        doc.db_set("custom_icici_verified_on", frappe.utils.now_datetime(), commit=False)

    # Save returned beneficiary name
    if meta.has_field("custom_icici_account_name"):
        doc.db_set("custom_icici_account_name", bene_name or "", commit=False)

    # Mark verified flag
    if meta.has_field("custom_bank_verified"):
        doc.db_set("custom_bank_verified", 1 if ok else 0, commit=False)

    # Optional status text
    if meta.has_field("custom_icici_status"):
        status_text = f"HTTP {http_status}"
        if match_flag:
            status_text += f" | Match: {match_flag}"
        doc.db_set("custom_icici_status", status_text, commit=False)

    frappe.db.commit()

    # Message shown to user
    if ok:
        msg = f"✅ ICICI verification call succeeded (HTTP {http_status})."
        if bene_name:
            msg += f"<br><b>Beneficiary Name (from bank):</b> {bene_name}"
    else:
        msg = f"❌ ICICI verification failed (HTTP {http_status}).<br>Check ICICI raw response."

    return {
        "success": ok,
        "http_status": http_status,
        "message": msg,
        "icici_response": resp_json,
    }

