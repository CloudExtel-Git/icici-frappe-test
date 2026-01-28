from __future__ import annotations

import os
import json
import base64
import datetime
from typing import Dict, Any, Tuple, Optional

import requests
import frappe
from frappe import _

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

DEFAULT_ICICI_URL = "https://apibankingonesandbox.icici.bank.in/api/v1/composite-validation"
DEFAULT_SERVICE = "IMPS_NAME_INQUIRY"
DEFAULT_X_PRIORITY = "0010"


def get_icici_config():
    conf = getattr(frappe, "conf", {}) or {}

    url = conf.get("icici_url") or DEFAULT_ICICI_URL
    api_key = conf.get("icici_api_key")
    service = conf.get("icici_service") or DEFAULT_SERVICE
    x_priority = conf.get("icici_x_priority") or DEFAULT_X_PRIORITY

    if not api_key:
        frappe.throw("ICICI API key not configured")

    return url, api_key, service, x_priority


# ---------------------------------------------------------------------------
# CERTIFICATE
# ---------------------------------------------------------------------------

def load_icici_public_key():
    cert_path = os.path.join(
        frappe.get_app_path("icici_integration"),
        "icici_integration",
        "icici_cert.pem",
    )

    if not os.path.exists(cert_path):
        frappe.throw("ICICI public certificate not found")

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    return cert.public_key()


# ---------------------------------------------------------------------------
# ENCRYPTION (ICICI SPEC COMPLIANT)
# ---------------------------------------------------------------------------

def encrypt_inner_payload(inner_body: Dict[str, Any], request_id: str, service: str) -> Dict[str, Any]:
    # STEP 1: RANDOMNO1 (AES key – 16 bytes)
    randomno1 = os.urandom(16)

    # STEP 4: RANDOMNO2 (IV – 16 bytes)
    randomno2 = os.urandom(16)

    # STEP 5: DATA = RANDOMNO2 + JSON
    json_data = json.dumps(inner_body, separators=(",", ":")).encode("utf-8")
    data = randomno2 + json_data

    # STEP 6: AES/CBC/PKCS5Padding
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(randomno1),
        modes.CBC(randomno2),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # STEP 2: RSA/ECB/PKCS1Padding
    pubkey = load_icici_public_key()
    encrypted_key = pubkey.encrypt(
        randomno1,
        asym_padding.PKCS1v15()
    )

    # STEP 3 & 7: Base64 encode
    return {
        "requestId": request_id,
        "service": service,
        "encryptedKey": base64.b64encode(encrypted_key).decode(),
        "oaepHashingAlgorithm": "NONE",
        "iv": base64.b64encode(randomno2).decode(),
        "encryptedData": base64.b64encode(encrypted_data).decode(),
        "clientInfo": "",
        "optionalParam": "",
    }


# ---------------------------------------------------------------------------
# ICICI API CALL
# ---------------------------------------------------------------------------

def call_icici_name_inquiry(
    bene_acc: str,
    bene_ifsc: str,
    rem_name: str,
    rem_mobile: str,
    tran_ref: Optional[str] = None,
) -> Tuple[bool, int, Any]:

    url, api_key, service, x_priority = get_icici_config()

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

    envelope = encrypt_inner_payload(inner, tran_ref, service)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "apikey": api_key,
        "x-priority": x_priority,
        "x-forwarded-for": frappe.local.request_ip or "127.0.0.1",
    }

    resp = requests.post(url, json=envelope, headers=headers, timeout=60)

    frappe.log_error(
        message=f"HTTP {resp.status_code}\n{resp.text}",
        title="ICICI_RAW_RESPONSE"
    )

    try:
        return resp.ok, resp.status_code, resp.json()
    except Exception:
        return False, resp.status_code, resp.text


# ---------------------------------------------------------------------------
# PUBLIC METHOD – VERIFY SUPPLIER BANK
# ---------------------------------------------------------------------------

@frappe.whitelist()
def verify_supplier_bank(supplier: str) -> Dict[str, Any]:

    doc = frappe.get_doc("Supplier", supplier)

    bene_acc = (doc.get("custom_bank_account_number") or "").strip()
    bene_ifsc = (doc.get("custom_bank_ifsc_code") or "").strip()

    if not bene_acc or not bene_ifsc:
        frappe.throw("Bank Account Number or IFSC missing")

    rem_name = doc.supplier_name or supplier
    rem_mobile = (
        doc.get("mobile_no")
        or doc.get("phone")
        or "9999999999"
    )

    ok, http_status, resp = call_icici_name_inquiry(
        bene_acc=bene_acc,
        bene_ifsc=bene_ifsc,
        rem_name=rem_name,
        rem_mobile=str(rem_mobile),
    )

    return {
        "success": ok,
        "http_status": http_status,
        "icici_response": resp,
    }
