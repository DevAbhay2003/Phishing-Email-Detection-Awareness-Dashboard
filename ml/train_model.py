"""
Machine Learning Training Pipeline
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Trains and evaluates multiple classifiers (Logistic Regression, Multinomial Naive Bayes, Random Forest)
on synthetic cybersecurity email dataset using TF-IDF text vectorization.
Saves the best-performing model to disk along with metrics and vectorizer artifacts.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report


def train_models():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "phishing_email_dataset.csv")
    models_dir = os.path.join(base_dir, "models")
    reports_dir = os.path.join(base_dir, "reports")
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    print(f"[*] Loading dataset from: {data_path}")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run data/generate_dataset.py first.")

    df = pd.read_csv(data_path)
    df.fillna("", inplace=True)
    print(f"[+] Loaded {len(df)} records. Class counts:\n{df['label'].value_counts()}")

    # Prepare input text: combine Subject and Body to capture semantic context
    df["combined_text"] = df["subject"] + " " + df["body"]
    
    # Binary target: 1 for PHISHING, 0 for LEGITIMATE
    df["target"] = (df["label"] == "PHISHING").astype(int)

    X = df["combined_text"]
    y = df["target"]

    # Stratified Train/Test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Training samples: {len(X_train)} | Test samples: {len(X_test)}")

    # Vectorize text using TF-IDF (unigrams + bigrams, sublinear tf)
    print("[*] Vectorizing text with TF-IDF...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
        stop_words="english"
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Candidate models to evaluate
    classifiers = {
        "Logistic Regression": LogisticRegression(random_state=42, max_iter=1000),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.5),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model = None

    print("\n" + "=" * 60)
    print("MODEL EVALUATION & BENCHMARKING")
    print("=" * 60)

    for name, clf in classifiers.items():
        print(f"\n[*] Training {name}...")
        clf.fit(X_train_vec, y_train)
        y_pred = clf.predict(X_test_vec)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm,
            "classification_report": classification_report(y_test, y_pred, output_dict=True)
        }

        print(f"    Accuracy:  {acc:.4f}")
        print(f"    Precision: {prec:.4f}  (Reduces false alarms / alert fatigue)")
        print(f"    Recall:    {rec:.4f}  (Reduces missed attacks / breaches)")
        print(f"    F1 Score:  {f1:.4f}  (Harmonic mean balancing both)")
        print(f"    Confusion Matrix [ [TN, FP], [FN, TP] ]:")
        print(f"    {cm}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = clf

    print("\n" + "=" * 60)
    print(f"[+] Top-Performing Model: {best_model_name} (F1 Score: {best_f1:.4f})")
    print("=" * 60)

    # Save artifacts
    model_save_path = os.path.join(models_dir, "phishing_model.joblib")
    vectorizer_save_path = os.path.join(models_dir, "tfidf_vectorizer.joblib")
    metadata_path = os.path.join(models_dir, "model_metadata.json")

    joblib.dump(best_model, model_save_path)
    joblib.dump(vectorizer, vectorizer_save_path)

    metadata = {
        "best_model": best_model_name,
        "f1_score": best_f1,
        "metrics": results[best_model_name],
        "all_models_compared": results,
        "training_dataset_size": len(df),
        "test_split_size": len(X_test),
        "vocabulary_size": len(vectorizer.vocabulary_)
    }

    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=4)

    # Generate human-readable evaluation report
    report_text_path = os.path.join(reports_dir, "model_evaluation_report.txt")
    with open(report_text_path, "w") as rf:
        rf.write("=" * 70 + "\n")
        rf.write("CYBERSECURITY ML MODEL EVALUATION REPORT\n")
        rf.write("Project: Phishing Email Detection & Awareness Dashboard\n")
        rf.write("=" * 70 + "\n\n")
        rf.write(f"Total Dataset Records: {len(df)} (Balanced 50/50 Legitimate & Phishing)\n")
        rf.write(f"Training Samples: {len(X_train)} | Testing Samples: {len(X_test)}\n\n")
        rf.write("MODEL COMPARISON TABLE:\n")
        rf.write(f"{'Model':<26} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8}\n")
        rf.write("-" * 70 + "\n")
        for mname, mres in results.items():
            rf.write(f"{mname:<26} | {mres['accuracy']:<8.4f} | {mres['precision']:<9.4f} | {mres['recall']:<8.4f} | {mres['f1_score']:<8.4f}\n")
        rf.write("-" * 70 + "\n\n")
        rf.write(f"SELECTED PRODUCTION MODEL: {best_model_name}\n")
        cm = results[best_model_name]["confusion_matrix"]
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        rf.write(f"Confusion Matrix Breakdown:\n")
        rf.write(f"  * True Negatives  (TN - Benign correctly marked safe):     {tn}\n")
        rf.write(f"  * False Positives (FP - Benign flagged as phishing):       {fp}\n")
        rf.write(f"  * False Negatives (FN - Phishing slipped past detector):   {fn}\n")
        rf.write(f"  * True Positives  (TP - Phishing correctly intercepted):   {tp}\n\n")
        rf.write("DEFENSIVE SECURITY ANALYSIS:\n")
        rf.write("- Precision indicates SOC efficiency: a high precision minimizes alert fatigue.\n")
        rf.write("- Recall indicates defensive posture: a high recall ensures critical intrusions do not breach perimeters.\n")
        rf.write("- Combined with the Rule-Based engine, hybrid detection guarantees zero single-point-of-failure.\n")

    print(f"\n[+] Saved model: {model_save_path}")
    print(f"[+] Saved vectorizer: {vectorizer_save_path}")
    print(f"[+] Saved metadata: {metadata_path}")
    print(f"[+] Saved evaluation report: {report_text_path}")

    return metadata


if __name__ == "__main__":
    train_models()
