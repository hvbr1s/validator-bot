import os
import base64
import hashlib
import ecdsa
from dotenv import load_dotenv
from ecdsa.util import sigdecode_der
from http import HTTPStatus
from fastapi import FastAPI, Request

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
        valid = False

    if not valid:
        return "Invalid signature", HTTPStatus.UNAUTHORIZED

    print(f"Received event: {body.decode()}")
    return "OK", HTTPStatus.OK

@app.post("/fordefi_webhook")
async def fordefi_webhook(request: Request):
    # Await the asynchronous verify_sig function
    status_message, status_code = await verify_sig(request)
    
    if status_message == "OK":
        print("Valid request")
        print(request)
    else:
        # You might want to handle the error (e.g., return an error response)
        print(status_message)

    return {"message": "Webhook received"}

# uvicorn app:app --host 0.0.0.0 --port 8000