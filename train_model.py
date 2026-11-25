
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# 1. Load the dataset
df = pd.read_csv(
    "SMSSpamCollection",
    sep="\t",
    header=None,
    names=["label", "message"]
)

# 2. Convert labels into numbers
df["label"] = df["label"].map({
    "ham": 0,
    "spam": 1
})

# Remove any rows with missing data
df = df.dropna(subset=["label", "message"])

# 3. Separate messages and their correct labels
X = df["message"]
y = df["label"]

# 4. Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# 5. Build the ML pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))
])

# 6. Train the model
model.fit(X_train, y_train)

# 7. Test on messages the model did not train on
predictions = model.predict(X_test)

print("Training messages:", len(X_train))
print("Testing messages:", len(X_test))

print("\nAccuracy:", round(
    accuracy_score(y_test, predictions), 4
))

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Spam"],
    zero_division=0
))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

# 8. Try new messages
test_messages = [
    "Congratulations! You won a free prize. Claim now!",
    "Your bank account is blocked. Click this link to unblock it.",
    "Hey, are we meeting for class tomorrow?"
]

print("\nSample Predictions:")

for message in test_messages:
    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]

    label = "SPAM" if prediction == 1 else "LEGITIMATE"
    confidence = probabilities[prediction] * 100

    print(f"\nMessage: {message}")
    print(f"Prediction: {label}")
    print(f"Model confidence: {confidence:.1f}%")

# 9. Save the trained model
import joblib

joblib.dump(model, "scamshield_model.joblib")

print("\nModel saved as scamshield_model.joblib")
