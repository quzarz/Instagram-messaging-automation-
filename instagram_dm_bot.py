import os
import hmac
import hashlib
import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

ACCESS_TOKEN = os.environ["META_ACCESS_TOKEN"]
VERIFY_TOKEN = os.environ["META_VERIFY_TOKEN"]
APP_SECRET = os.environ["META_APP_SECRET"]
KEYWORD = os.environ.get("TRIGGER_KEYWORD", "info")
DM_MESSAGE = os.environ.get("DM_MESSAGE", "Thanks for your interest! Here's more info...")
GRAPH_API_URL = "https://graph.facebook.com/v19.0"


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        APP_SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def send_dm(recipient_id: str, message: str) -> requests.Response:
    return requests.post(
        f"{GRAPH_API_URL}/me/messages",
        params={"access_token": ACCESS_TOKEN},
        json={
            "recipient": {"id": recipient_id},
            "message": {"text": message},
        },
    )


@app.get("/webhook")
def webhook_verify():
    if (
        request.args.get("hub.mode") == "subscribe"
        and request.args.get("hub.verify_token") == VERIFY_TOKEN
    ):
        return request.args.get("hub.challenge"), 200
    abort(403)


@app.post("/webhook")
def webhook_receive():
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(request.get_data(), signature):
        abort(401)

    body = request.get_json(silent=True) or {}

    for entry in body.get("entry", []):
        for change in entry.get("changes", []):
            if change.get("field") != "comments":
                continue
            value = change.get("value", {})
            comment_text = value.get("text", "").lower()
            commenter_id = value.get("from", {}).get("id")
            if commenter_id and KEYWORD.lower() in comment_text:
                send_dm(commenter_id, DM_MESSAGE)

    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)))
