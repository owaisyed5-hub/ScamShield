
from transformers import pipeline

MODEL_NAME = "Horizon-Labs/phishing-scam-detector-base"

print("Loading scam detection model...")
classifier = pipeline(
    "text-classification",
    model=MODEL_NAME,
    top_k=None
)

messages = [
    (
        "ALERT: We detected an unauthorized transaction of "
        "$489.22 on your card. If you did not make this purchase, "
        "click here to freeze your account: "
        "https://git-scm.com/installll"
    ),
    (
        "USPS/FedEx: Your package could not be delivered due "
        "to an incomplete address. Update your shipping details "
        "immediately to avoid return."
    ),
    "Hey, are we meeting for class tomorrow?",
    "Congratulations! You won a free prize. Claim now!"
]

for message in messages:
    results = classifier(message)[0]
    results = sorted(
        results,
        key=lambda item: item["score"],
        reverse=True
    )

    print("\nMessage:", message)
    for item in results:
        print(
            f'{item["label"]}: '
            f'{item["score"] * 100:.1f}%'
        )
