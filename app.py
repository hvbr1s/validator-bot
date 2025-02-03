import os
import json
import base64
import hashlib
import ecdsa
from web3.auto import w3
from dotenv import load_dotenv
from ecdsa.util import sigdecode_der
from http import HTTPStatus
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

load_dotenv()
public_key_path = os.getenv("FORDEFI_PUBLIC_KEY_PATH")
with open(public_key_path, "r") as f:
    FORDEFI_PUBLIC_KEY = f.read()
signature_pub_key = ecdsa.VerifyingKey.from_pem(FORDEFI_PUBLIC_KEY)

async def verify_sig(request: Request):
    # Retrieve the signature from the request headers
    signature = request.headers.get("X-Signature")
    if signature is None:
        return "Missing signature", HTTPStatus.UNAUTHORIZED

    # Read the request body asynchronously
    body = await request.body()

    try:
        # Verify the signature using the provided public key and body data
        valid = signature_pub_key.verify(
            signature=base64.b64decode(signature),
            data=body,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_der,
        )
    except Exception as e:
        print(e)
        valid = False

    if not valid:
        return "Invalid signature", HTTPStatus.UNAUTHORIZED

    print(f"Received event: {body.decode()}")
    return "OK", HTTPStatus.OK

@app.post("/fordefi_webhook")
async def fordefi_webhook(request: Request):
    # 1) First, verify the signature:
    status_message, status_code = await verify_sig(request)
    if status_message != "OK":
        # Return error or raise an exception if signature is invalid
        raise HTTPException(status_code=status_code, detail="Invalid signature")

    # 2) Parse the JSON body
    body = await request.body()
    data = json.loads(body)

    # 3) Grab the raw tx from the JSON
    raw_tx_hex = data["event"]["raw_transaction"]  # e.g. "0x02f9025c81891..."

    # 4) Decode the transaction
    #    In newer web3.py versions, you can do:
    #    w3.eth.account.signing.decode_transaction(...) or
    #    w3.eth.account._parse_raw_transaction(...)
    #
    #    The exact method name depends on your Web3.py version.
    #
    #    If you get an error about "no attribute decode_raw_transaction", 
    #    try using `_parse_raw_transaction` or see the official docs.
    
    try:
        decoded_tx = w3.eth.account.signing.decode_transaction(raw_tx_hex)
        # decoded_tx is typically a tuple like:
        #   (intrinsic_tx, tx_hash, sender, r, s, v)
        # 
        # The first item, `intrinsic_tx`, will have the typed fields.
        intrinsic_tx, tx_hash, sender, r, s, v = decoded_tx

        print("Decoded TX:", intrinsic_tx)
        print("Transaction Hash:", tx_hash.hex())
        print("Sender Address:", sender)
        print("Signature r, s, v:", r, s, v)

    except Exception as e:
        print(f"Error decoding transaction: {e}")

    return {"message": "Webhook received"}

# uvicorn app:app --host 0.0.0.0 --port 8000