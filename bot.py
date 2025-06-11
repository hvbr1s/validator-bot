import os
import json
import requests
import base64
import hashlib
import ecdsa
import time
import subprocess
from dotenv import load_dotenv
from ecdsa.util import sigdecode_der
from http import HTTPStatus
from fastapi import FastAPI, Request, HTTPException
from typing import Dict, Optional

ORIGIN_VAULT = "0x8BFCF9e2764BC84DE4BBd0a0f5AAF19F47027A73" # Change to your Vault's address
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

app = FastAPI()

load_dotenv()
FORDEFI_API_USER_TOKEN = os.getenv("FORDEFI_API_USER_TOKEN")
public_key_path = os.getenv("FORDEFI_PUBLIC_KEY_PATH")

with open(public_key_path, "r") as f:
    FORDEFI_PUBLIC_KEY = f.read()

signature_pub_key = ecdsa.VerifyingKey.from_pem(FORDEFI_PUBLIC_KEY)


class TransactionAbortError(Exception):
    """Raised when a transaction should be aborted"""
    pass


def verify_signature(signature: str, body: bytes) -> bool:
    """Verify webhook signature using ECDSA"""
    try:
        return signature_pub_key.verify(
            signature=base64.b64decode(signature),
            data=body,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_der,
        )
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False


def get_transaction_data(transaction_id: str) -> Dict:
    """Fetch transaction data from Fordefi API"""
    url = f"https://api.fordefi.com/api/v1/transactions/{transaction_id}"
    headers = {"Authorization": f"Bearer {FORDEFI_API_USER_TOKEN}"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching transaction data: {e}")
        return {}


def wait_for_transaction_creation(transaction_id: str, max_wait_time: int = 300) -> Dict:
    """Poll until transaction is created and ready for validation"""
    target_states = ["waiting_for_approval"]
    start_time = time.time()
    poll_interval = 5
    
    print(f"🕐 Waiting for transaction {transaction_id} to be created...")
    
    while time.time() - start_time < max_wait_time:
        transaction_data = get_transaction_data(transaction_id)
        
        if not transaction_data:
            print("Failed to fetch transaction data, retrying...")
            time.sleep(poll_interval)
            continue
            
        current_state = transaction_data.get("state")
        print(f"Current transaction state: {current_state}")
        
        # Check for aborted state FIRST, before the generic check
        if current_state == "aborted":
            print("ℹ️ Transaction already aborted - running validation for audit purposes")
            return transaction_data
        
        if current_state not in target_states:
            print(f"✅ Transaction is now in created state: {current_state}")
            return transaction_data
            
        print(f"Transaction not yet created, waiting {poll_interval}s...")
        time.sleep(poll_interval)
    
    print(f"⏰ Timeout: Transaction did not reach created state within {max_wait_time} seconds")
    return {}


def abort_transaction(transaction_id: str, reason: str) -> None:
    """Abort a transaction with the given reason"""
    url = f"https://api.fordefi.com/api/v1/transactions/{transaction_id}/abort"
    headers = {"Authorization": f"Bearer {FORDEFI_API_USER_TOKEN}"}

    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        print(f"✅ Transaction aborted: {reason}")
    except requests.exceptions.RequestException as e:
        # Get more details about the error response
        response_details = ""
        request_id = ""
        
        if hasattr(e, 'response') and e.response is not None:
            response_details = f"Status: {e.response.status_code}"
            
            # Try to get request ID from headers
            if 'x-request-id' in e.response.headers:
                request_id = e.response.headers['x-request-id']
                response_details += f", Request ID: {request_id}"
            
            # Try to get response body for more context
            try:
                response_body = e.response.text
                if response_body:
                    response_details += f", Response: {response_body}"
            except:
                pass
        
        error_message = f"❌ Error aborting transaction: {e}"
        if response_details:
            error_message += f" ({response_details})"
        print(error_message)
        
        # Check if this is a 400 error - might be expected (already aborted)
        if hasattr(e, 'response') and e.response is not None and e.response.status_code == 400:
            print("⚠️ Got 400 error - transaction might already be aborted or in invalid state")
            # Don't raise HTTP 500 for 400 errors - just log and continue
            return
        
        # For other errors, still raise 500
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to abort transaction: {reason}. {response_details}"
        )


def validate_eip_712_order(transaction_data: Dict) -> None:
    """Validate EIP-712 orders"""
    raw_data = transaction_data.get("raw_data")
    if not raw_data:
        return
        
    try:
        if isinstance(raw_data, str):
            parsed_data = json.loads(raw_data)
            message = parsed_data.get("message", {})
            receiver = message.get("receiver", "").lower()
            
            if not receiver:
                return
                
            print(f"🔍 Order receiver: {receiver}")
            
            # Allow zero address (valid) or ORIGIN_VAULT
            if receiver == ZERO_ADDRESS:
                print("✅ Receiver is zero address - considered valid")
            elif receiver == ORIGIN_VAULT.lower():
                print(f"✅ Receiver matches ORIGIN_VAULT")
            else:
                raise TransactionAbortError(f"Unauthorized receiver: {receiver}")
                
    except json.JSONDecodeError:
        print("⚠️ raw_data is not valid JSON")
    except TransactionAbortError:
        raise
    except Exception as e:
        print(f"⚠️ Error parsing raw_data: {e}")


def validate_hex_data(transaction_data: Dict) -> None:
    """Validate hex data contains ORIGIN_VAULT"""
    hex_data = transaction_data.get("hex_data")
    if not hex_data:
        return
        
    # Skip validation for approval transactions
    contract_method = transaction_data.get("parsed_data", {}).get("method")
    if contract_method == "approve":
        print("This is an approval, skipping hex data validation")
        return
        
    try:
        # Decode using cast
        result = subprocess.run(
            ["cast", "4byte-decode", hex_data], 
            capture_output=True, 
            text=True
        )
        decoded_output = result.stdout or ""
        print(f"🔎 Decoded function signature: {decoded_output}")
        
        if ORIGIN_VAULT.lower() not in decoded_output.lower():
            raise TransactionAbortError("ORIGIN_VAULT not found in decoded data")
        else:
            print(f"✅ ORIGIN_VAULT found in decoded data")
            
    except subprocess.SubprocessError as e:
        raise TransactionAbortError(f"Unable to decode hex data: {e}")


def validate_transaction(transaction_data: Dict) -> None:
    """Run all transaction validations"""
    print("🔍 Validating transaction...")
    
    # Validate EIP-712 orders (CoWSwap, 1inch)
    validate_eip_712_order(transaction_data)
    
    # Validate hex data
    validate_hex_data(transaction_data)
    
    print("✅ Transaction validation passed")


@app.post("/")
async def fordefi_webhook(request: Request):
    """
    Fordefi webhook endpoint for monitoring transactions.
    
    Validates transactions to prevent unauthorized fund movements
    by checking receivers and ensuring ORIGIN_VAULT is present.
    """
    # Authenticate webhook is from Fordefi
    signature = request.headers.get("X-Signature")
    if not signature:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Missing signature")

    raw_body = await request.body()
    if not verify_signature(signature, raw_body):
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail="Invalid signature")

    # Parse webhook data
    try:
        data = json.loads(raw_body)
        print("📝 Received webhook event")
    except json.JSONDecodeError:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid JSON")

    # Extract transaction ID from webhook
    transaction_id = data.get("event", {}).get("transaction_id")
    if not transaction_id:
        return {"message": "No transaction ID found"}

    print(f"🔍 Processing transaction: {transaction_id}")

    # Wait for transaction to be created
    transaction_data = wait_for_transaction_creation(transaction_id)
    if not transaction_data:
        return {"message": "Timeout: Transaction did not reach created state"}

    # Validate transaction
    try:
        validate_transaction(transaction_data)
        return {"message": "Transaction validated successfully"}
        
    except TransactionAbortError as e:
        abort_transaction(transaction_id, str(e))
        return {"message": f"Transaction aborted: {e}"}

# uvicorn bot:app --host 0.0.0.0 --port 8080 --reload