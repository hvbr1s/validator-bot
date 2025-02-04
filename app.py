import os
import json
import requests
import base64
import hashlib
import ecdsa
from dotenv import load_dotenv
from ecdsa.util import sigdecode_der
from http import HTTPStatus
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

load_dotenv()
FORDEFI_API_USER_TOKEN = os.getenv("FORDEFI_API_USER_TOKEN")
public_key_path = os.getenv("FORDEFI_PUBLIC_KEY_PATH")
with open(public_key_path, "r") as f:
    FORDEFI_PUBLIC_KEY = f.read()
signature_pub_key = ecdsa.VerifyingKey.from_pem(FORDEFI_PUBLIC_KEY)

def verify_signature(signature: str, body: bytes) -> bool:
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

@app.post("/fordefi_webhook")
async def fordefi_webhook(request: Request):
    # 1. Get the signature from headers
    signature = request.headers.get("X-Signature")
    if not signature:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED, 
            detail="Missing signature"
        )

    # 2. Read the raw body once
    raw_body = await request.body()

    # 3. Verify the signature
    if not verify_signature(signature, raw_body):
        print("Invalid signature")
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Invalid signature"
        )

    print(f"Received event: {raw_body.decode()}")

    # 4. Parse the JSON body into a dictionary
    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid JSON in request body"
        )

    # 5. Extract the transaction_id from the data (if present)
    transaction_id = data.get("event", {}).get("transaction_id")
    transaction_data = None

    if transaction_id:
        print("Transaction ID:", transaction_id)
        fordefi_url = f"https://api.fordefi.com/api/v1/transactions/{transaction_id}"
        headers = {"Authorization": f"Bearer {FORDEFI_API_USER_TOKEN}"}

        try:
            response = requests.get(fordefi_url, headers=headers)
            response.raise_for_status()
            transaction_data = response.json()
            print("Transaction data:", transaction_data)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching transaction data: {e}")
    else:
        print("transaction_id field not found in the event data.")

    if not transaction_data:
        # If we don't get any transaction data, there's nothing more to do
        return {"message": "Webhook processed; no transaction data found."}

    # 6. Retrieve the vault_address from transaction_data
    vault_address = None
    transfers = transaction_data.get("mined_result", {}).get("effects", {}).get("transfers", [])
    if transfers and len(transfers) > 0:
        vault_info = transfers[0].get("from", {}).get("vault", {})
        vault_address = vault_info.get("address")
    
    if not vault_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Vault address not found in the transaction data."
        )
    # 7. Extract the receiver address
    receiver_address = transaction_data["mined_result"]["effects"]["balance_changes"][1]["address"]["vault"]["address"]
    if not receiver_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Receiver address not found in raw_data."
        )

    # 8. Compare addresses (case-insensitive)
    if vault_address.lower() == receiver_address.lower():
        print("Vault address and receiver address are similar.")
    else:
        print("Vault address and receiver address are not similar.")

    return {"message": "Webhook received successfully"}

# uvicorn app:app --host 0.0.0.0 --port 8000 --reload