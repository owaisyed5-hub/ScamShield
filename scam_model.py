
from transformers import pipeline

MODEL_NAME = "Horizon-Labs/phishing-scam-detector-base"

print("Loading ScamShield fraud detection model...")

classifier = pipeline(
    "text-classification",
    model=MODEL_NAME,
    top_k=None
)


def predict_message(message):
    results = classifier(message)[0]

    scores = {
        item["label"].lower(): float(item["score"])
        for item in results
    }

    prediction = max(scores, key=scores.get)

    label_names = {
        "fraud": "Scam",
        "spam": "Spam",
        "legitimate": "Legitimate"
    }

    return {
        "label": label_names.get(prediction, "Unknown"),
        "confidence": round(scores[prediction] * 100, 1),
        "scores": {
            label_names.get(label, label): round(score * 100, 1)
            for label, score in scores.items()
        }
    }
