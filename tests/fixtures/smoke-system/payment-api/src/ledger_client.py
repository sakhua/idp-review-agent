import requests

LEDGER_URL = "http://ledger-api:8080"


def post_entry(payload: dict) -> dict:
    return requests.post(f"{LEDGER_URL}/entries", json=payload).json()
