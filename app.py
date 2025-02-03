import os
import base64
import requests
import hashlib
import ecdsa
from dotenv import load_dotenv
from ecdsa.util import sigdecode_der
from http import HTTPStatus
from fastapi import FastAPI, Request

app = FastAPI()

load_dotenv()
FORDEFI_PUBLIC_KEY = os.getenv("FORDEFI_PUBLIC_KEY")
signature_pub_key = ecdsa.VerifyingKey.from_pem(FORDEFI_PUBLIC_KEY)

def verify_sig(request):

    signature = request.headers.get("X-Signature")

    if signature is None:
        return "Missing signature", HTTPStatus.UNAUTHORIZED

    if not signature_pub_key.verify(
        signature=base64.b64decode(signature),
        data=request.get_data(),
        hashfunc=hashlib.sha256,
        sigdecode=sigdecode_der,
    ):
        return "Invalid signature", HTTPStatus.UNAUTHORIZED

    print(f"Received event: {request.get_data().decode()}")
    return "OK", HTTPStatus.OK

#### APP ####

@app.post("/fordefi_webhook")
async def fordefi_webhook(request: Request):

    verify = verify_sig(request)
    if verify == "OK":
        print("Valid request")
        print(request)

    return {"message": "Webhook received"}

# start command -> uvicorn app:app --host 0.0.0.0 --port 8000