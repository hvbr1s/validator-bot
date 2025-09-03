# Fordefi Transaction Validation Bot

A FastAPI webhook server that automatically validates and approves Fordefi transactions based on predefined security rules.

## Overview

This bot monitors incoming Fordefi webhook events and validates transactions to prevent unauthorized fund movements by:
- Validating EIP-712 order receivers (CoWSwap, 1inch, etc.)
- Checking hex data for the presence of authorized vault addresses
- Automatically approving valid transactions or aborting suspicious ones

## Features

- **Webhook Signature Verification**: Validates incoming webhooks using Fordefi public key
- **EIP-712 Order Validation**: Ensures swap receivers match authorized addresses
- **Hex Data Validation**: Decodes transaction data to verify vault addresses
- **Health Check Bot**: Tests bot connectivity before processing transactions
- **State Management**: Only processes transactions in "waiting_for_approval" state

## Setup

### Prerequisites
- Python 3.8+
- [Foundry](https://getfoundry.sh/) (for `cast` command)
- Fordefi API access tokens

### Environment Variables
Create a `.env` file with:
```bash
FORDEFI_API_USER_TOKEN=your_main_bot_token
HEALTH_CHECK_BOT_TOKEN=your_health_check_bot_token
FORDEFI_PUBLIC_KEY_PATH=path_to_fordefi_public_key.pem
```

### Installation
```bash
pip install fastapi uvicorn python-dotenv requests ecdsa
```

### Configuration
Update the `ORIGIN_VAULT` address in `bot.py`:
```python
ORIGIN_VAULT = "0xYourVaultAddress"  # Change to your vault's address
```

## Usage

### Start the Server
```bash
uvicorn bot:app --host 0.0.0.0 --port 8080 --reload
```

### Expose with ngrok (for testing)
```bash
ngrok http 8080
```

### Configure Fordefi Webhook
Set your webhook URL in Fordefi to point to your server endpoint (e.g., `https://your-domain.com/` or ngrok URL).

## API Endpoints

- `POST /` - Main webhook endpoint for Fordefi events
- `GET /health` - Health check endpoint

## Security Rules

The bot validates transactions based on:

1. **EIP-712 Orders**: Receivers must be either:
   - Zero address (`0x0000...`)
   - The configured `ORIGIN_VAULT` address

2. **Hex Data**: Must contain the `ORIGIN_VAULT` address when decoded

3. **Transaction State**: Only processes transactions in "waiting_for_approval" state

## Logging

The bot provides detailed logging including:
- Webhook event details
- Transaction data inspection
- Validation step progress
- Error details and exception handling
- API call results

## Error Handling

- Invalid transactions are automatically aborted with detailed reasons
- Network errors are logged with full context
- Unexpected errors trigger transaction abortion as a safety measure

## Documentation Links

- [Fordefi Developer Quickstart](https://docs.fordefi.com/developers/program-overview)
- [Transaction Management API](https://docs.fordefi.com/api/openapi/transactions)
- [Webhooks Documentation](https://docs.fordefi.com/developers/webhooks)