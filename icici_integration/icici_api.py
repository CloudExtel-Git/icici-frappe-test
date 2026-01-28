from __future__ import annotations

import os
import json
import base64
import datetime
import secrets
import string
from typing import Tuple, Any, Dict, Optional

import requests
import frappe
from frappe import _

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# CONFIG HELPERS
# ---------------------------------------------------------------------------

DEFAULT_ICICI_URL = "https://apibankingonesandbox.icici.bank.in/api/v1/composite-validation"
DEFAULT_X_PRIORITY = "0010"
DEFAULT_SERVICE = "IMPS_NAME_INQUIRY"


def get_icici_config() -> Tuple[str, str, str, str]:
    """
    Read ICICI config from site_config.json (frappe.conf),
    falling back to sandbox defaults.
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
    Returns absolute path to icici_cert.pem inside the app module.
    """
    app_root = frappe.get_app_path("icici_integration")
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
# ENCRYPTION HELPERS - NEW IMPLEMENTATION PER CLIENT SPECS
# ---------------------------------------------------------------------------

def generate_16_digit_random() -> str:
    """
    Generate a 16-digit random number as string.
    """
    # Using secrets module for cryptographically secure random numbers
    digits = string.digits
    return ''.join(secrets.choice(digits) for _ in range(16))


def encrypt_inner_payload_icici(inner_body: Dict[str, Any], request_id: str, service: str) -> Dict[str, Any]:
    """
    Encrypt the inner JSON payload using ICICI's specified encryption steps.
    
    Steps:
    1. Generate 16-digit random number (RANDOMNO1) - AES key
    2. Encrypt RANDOMNO1 using RSA/ECB/PKCS1Padding with ICICI public key
    3. Base64 encode the encrypted key (ENCR_KEY)
    4. Generate another 16-digit random number (RANDOMNO2) - IV
    5. Concatenate RANDOMNO2 + JSON data = DATA
    6. AES/CBC/PKCS5Padding encryption on DATA using RANDOMNO1 as key and RANDOMNO2 as IV
    7. Base64 encode the encrypted data (ENCR_DATA)
    """
    
    # Step 1: Generate 16-digit random number RANDOMNO1 (AES key)
    randomno1 = generate_16_digit_random()
    frappe.log_error(message=f"RANDOMNO1: {randomno1}", title="ICICI Encryption Step 1")
    
    # Step 2: Encrypt RANDOMNO1 using RSA/ECB/PKCS1Padding
    pubkey = load_icici_public_key()
    randomno1_bytes = randomno1.encode('utf-8')
    
    # RSA encryption with PKCS1 v1.5 padding
    encrypted_key = pubkey.encrypt(
        randomno1_bytes,
        asym_padding.PKCS1v15()  # Using PKCS1v15 as per client specs
    )
    frappe.log_error(message=f"Encrypted Key Length: {len(encrypted_key)}", title="ICICI Encryption Step 2")
    
    # Step 3: Base64 encode the encrypted key
    encr_key = base64.b64encode(encrypted_key).decode('ascii')
    frappe.log_error(message=f"ENCR_KEY (first 50 chars): {encr_key[:50]}", title="ICICI Encryption Step 3")
    
    # Step 4: Generate another 16-digit random number RANDOMNO2 (IV)
    randomno2 = generate_16_digit_random()
    frappe.log_error(message=f"RANDOMNO2: {randomno2}", title="ICICI Encryption Step 4")
    
    # Step 5: Concatenate RANDOMNO2 and JSON data
    # Convert JSON to compact format (no spaces)
    json_data = json.dumps(inner_body, separators=(",", ":"))
    data = randomno2 + json_data
    data_bytes = data.encode('utf-8')
    
    frappe.log_error(message=f"Data length (RANDOMNO2 + JSON): {len(data_bytes)}", title="ICICI Encryption Step 5")
    frappe.log_error(message=f"Data (first 100 chars): {data[:100]}", title="ICICI Encryption Step 5")
    
    # Step 6: AES/CBC/PKCS5Padding encryption
    # Convert RANDOMNO1 to 16-byte key (AES-128)
    aes_key = randomno1.encode('utf-8')
    # Ensure exactly 16 bytes for AES-128
    if len(aes_key) != 16:
        if len(aes_key) > 16:
            aes_key = aes_key[:16]
        else:
            aes_key = aes_key.ljust(16, b'0')
    
    # Convert RANDOMNO2 to 16-byte IV
    iv = randomno2.encode('utf-8')
    if len(iv) != 16:
        if len(iv) > 16:
            iv = iv[:16]
        else:
            iv = iv.ljust(16, b'0')
    
    frappe.log_error(message=f"AES Key (hex): {aes_key.hex()}", title="ICICI Encryption Step 6")
    frappe.log_error(message=f"IV (hex): {iv.hex()}", title="ICICI Encryption Step 6")
    
    # PKCS5 padding (same as PKCS7 for 8-byte block size, but we'll use PKCS7 for AES)
    padder = sym_padding.PKCS7(128).padder()  # 128-bit = 16 bytes
    padded_data = padder.update(data_bytes) + padder.finalize()
    
    # AES-CBC encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    frappe.log_error(message=f"Ciphertext length: {len(ciphertext)}", title="ICICI Encryption Step 6")
    
    # Step 7: Base64 encode the encrypted data
    encr_data = base64.b64encode(ciphertext).decode('ascii')
    frappe.log_error(message=f"ENCR_DATA (first 50 chars): {encr_data[:50]}", title="ICICI Encryption Step 7")
    
    # Build the envelope as per client specs
    envelope = {
        "requestId": request_id,
        "service": service,
        "encryptedKey": encr_key,
        "oaepHashingAlgorithm": "NONE",  # Using NONE because we're using PKCS1v15, not OAEP
        "iv": "",  # IV is included in the encrypted data (RANDOMNO2 concatenated)
        "encryptedData": encr_data,
        "clientInfo": "",
        "optionalParam": "",
    }
    
    frappe.log_error(message=f"Final Envelope: {json.dumps(envelope, indent=2)}", title="ICICI Final Envelope")
    
    return envelope


# ---------------------------------------------------------------------------
# CORE CALL TO ICICI - UPDATED WITH NEW ENCRYPTION
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
    logger.info("ICICI INNER PAYLOAD: %s", inner)

    try:
        envelope = encrypt_inner_payload_icici(inner, tran_ref, service)
    except Exception as e:
        frappe.log_error(
            message=f"Encryption failed: {str(e)}\nInner: {inner}",
            title="ICICI Encryption Error"
        )
        frappe.throw(
            _("Failed to encrypt payload for ICICI: {0}").format(e),
            title=_("ICICI Integration Error"),
        )

    logger.info("ICICI ENVELOPE: %s", envelope)

    headers = {
        "Content-Type": "application/json",
        "accept": "application/json",
        "apikey": api_key,
        "x-priority": x_priority,
    }

    try:
        # Log the complete request for debugging
        frappe.log_error(
            message=f"Request URL: {url}\nHeaders: {headers}\nEnvelope: {json.dumps(envelope, indent=2)}",
            title="ICICI API Request"
        )
        
        resp = requests.post(url, json=envelope, headers=headers, timeout=60)
        
        # Log response details
        frappe.log_error(
            message=f"Response Status: {resp.status_code}\nResponse Headers: {dict(resp.headers)}\nResponse Body: {resp.text}",
            title="ICICI API Response"
        )
        frappe.log_error(
            message=resp.json(),
            title="ICICI Complete Response"
        )
        
    except requests.exceptions.Timeout:
        frappe.throw(
            _("ICICI API request timed out after 60 seconds"),
            title=_("ICICI Integration Error"),
        )
    except requests.exceptions.ConnectionError:
        frappe.throw(
            _("Failed to connect to ICICI API"),
            title=_("ICICI Integration Error"),
        )
    except Exception as e:
        frappe.log_error(
            message=f"API call failed: {str(e)}\nURL: {url}\nHeaders: {headers}",
            title="ICICI API Call Error"
        )
        frappe.throw(
            _("Error calling ICICI API: {0}").format(e),
            title=_("ICICI Integration Error"),
        )

    status = resp.status_code

    try:
        resp_json = resp.json()
        logger.info("ICICI RESPONSE JSON [%s]: %s", status, resp_json)
    except ValueError:
        resp_json = resp.text
        logger.info("ICICI RESPONSE TEXT [%s]: %s", status, resp_json[:500])

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
    Public, whitelisted method to call from Postman.
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
        "icici_response": resp_json,
    }


# ---------------------------------------------------------------------------
# SUPPLIER HELPER – VERIFY BANK FROM SUPPLIER FIELDS
# ---------------------------------------------------------------------------

@frappe.whitelist()
def verify_supplier_bank(supplier: str) -> Dict[str, Any]:
    """
    Verify the bank account of a Supplier using ICICI IMPS Name Inquiry.

    Uses Supplier fields:
      - custom_bank_account_number
      - custom_bank_ifsc_code
      - custom_bank_account_details (optional Link to Bank Account)
    """
    doc = frappe.get_doc("Supplier", supplier)

    # Get account + IFSC from Supplier
    bene_acc = (doc.get("custom_bank_account_number") or "").strip()
    bene_ifsc = (doc.get("custom_bank_ifsc_code") or "").strip()

    # Optional: Bank Account link as backup
    bank_link = (doc.get("custom_bank_account_details") or "").strip()
    if bank_link and (not bene_acc or not bene_ifsc):
        try:
            bank_doc = frappe.get_doc("Bank Account", bank_link)
            if not bene_acc:
                bene_acc = (bank_doc.get("bank_account_no") or "").strip()
            if not bene_ifsc:
                bene_ifsc = (
                    (bank_doc.get("custom_ifsc") or "").strip()
                    or (bank_doc.get("ifsc_code") or "").strip()
                )
        except Exception:
            pass

    if not bene_acc or not bene_ifsc:
        frappe.throw(
            _(
                "Bank Account Number or IFSC is missing. "
                "Please fill <b>Bank Account Number</b> and <b>Bank IFSC Code</b> on Supplier."
            )
        )

    rem_name = (doc.supplier_name or supplier).strip()
    rem_mobile = (
        str(doc.get("mobile_no") or doc.get("phone") or "9999999999")
    ).strip()

    ok, http_status, resp_json = call_icici_name_inquiry(
        bene_acc=bene_acc,
        bene_ifsc=bene_ifsc,
        rem_name=rem_name,
        rem_mobile=rem_mobile,
    )

    # Interpret response
    match_flag = None
    bene_name = None
    status_text = f"HTTP {http_status}"

    try:
        if isinstance(resp_json, dict):
            # Try to extract relevant information from response
            match_flag = resp_json.get("response", {}).get("matchFlag") or resp_json.get("matchFlag")
            bene_name = resp_json.get("response", {}).get("BeneName") or resp_json.get("BeneName")
            
            if match_flag:
                status_text += f" | Match: {match_flag}"
            if bene_name:
                status_text += f" | Name: {bene_name}"
    except Exception:
        pass

    # Write status back to Supplier if fields exist
    meta = doc.meta

    if meta.has_field("custom_icici_status"):
        doc.db_set("custom_icici_status", status_text, commit=False)

    if meta.has_field("custom_icici_verified_on"):
        doc.db_set("custom_icici_verified_on", frappe.utils.now(), commit=False)

    # if meta.has_field("custom_icici_raw_response"):
    #     doc.db_set("custom_icici_raw_response", frappe.as_json(resp_json), commit=False)

    if meta.has_field("custom_icici_account_name") and bene_name:
        doc.db_set("custom_icici_account_name", bene_name, commit=False)

    frappe.db.commit()

    return {
        "success": ok,
        "http_status": http_status,
        "match_flag": match_flag,
        "bene_name": bene_name,
        "status_text": status_text,
        "icici_response": resp_json,
    }