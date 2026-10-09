
from flask import Flask, render_template, request

app = Flask(__name__)


def analyze_message(message):
    text = message.lower()

    indicators = []

    # Check for urgent language
    urgent_words = [
        "urgent", "immediately", "act now",
        "account blocked", "expires today"
    ]

    if any(word in text for word in urgent_words):
        indicators.append("Urgent or pressure-based language detected.")

    # Check for unexpected prizes or offers
    offer_words = [
        "you won", "winner", "prize",
        "claim your reward", "free gift"
    ]

    if any(word in text for word in offer_words):
        indicators.append("Unexpected prize or offer detected.")

    # Check for sensitive information requests
    sensitive_words = [
        "otp", "password", "bank details",
        "card number", "pin number"
    ]

    if any(word in text for word in sensitive_words):
        indicators.append("Reference to sensitive information detected.")

    # Check for links
    if "http://" in text or "https://" in text or "www." in text:
        indicators.append("A web link was found and should be checked.")

    # Assign a preliminary risk level
    if len(indicators) >= 3:
        risk = "High"
    elif len(indicators) >= 1:
        risk = "Medium"
    else:
        risk = "Low"

    if risk == "High":
        guidance = (
            "Avoid clicking links or sharing sensitive information. "
            "Verify the sender through an official channel."
        )
    elif risk == "Medium":
        guidance = (
            "Be cautious. Check the sender and verify any claims "
            "before clicking links or sharing information."
        )
    else:
        guidance = (
            "No configured warning indicators were detected. "
            "This does not guarantee that the message is safe."
        )

    return {
        "risk": risk,
        "indicators": indicators,
        "guidance": guidance,
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result = analyze_message(message)

    return render_template(
        "index.html",
        result=result,
        message=message
    )


if __name__ == "__main__":
    app.run(debug=True)
