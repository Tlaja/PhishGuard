import re
import string
import time
import base64

import requests
import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib
matplotlib.use("Agg")  # non-interactive backend — no Tkinter/display required
import matplotlib.pyplot as plt

# CONST
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # https://www.virustotal.com/gui/my-apikey
VT_HEADERS = {"x-apikey": VT_API_KEY}
VT_RATE_LIMIT_DELAY = 15  # seconds between submissions (free tier: 4 req/min)


TFIDF_PARAMS = dict(
    max_features=30_000,
    ngram_range=(1, 2),
    sublinear_tf=True,
    strip_accents="unicode",
    analyzer="word",
    token_pattern=r"\b[a-zA-Z][a-zA-Z0-9]{1,}\b",
)

# TEKST EMAIL

_URL_RE   = re.compile(r"https?://[^\s]+|www\.[^\s]+")
_EMAIL_RE = re.compile(r"\S+@\S+")
_PUNCT    = str.maketrans("", "", string.punctuation)


def extract_urls(text: str) -> str:
    return _URL_RE.findall(text)


def clean_text(text: str) -> str:
    urls: list[str] = extract_urls(text)
    text = _URL_RE.sub(" URLTOKEN ", text)
    text = _EMAIL_RE.sub(" EMAILTOKEN ", text)
    text = text.lower()
    text = text.translate(_PUNCT)
    text = re.sub(r"\s+", " ", text).strip()

    if urls:
        text = text + " " + " ".join(urls).lower()

    return text

# KORPUS

def load_default_dataset() -> tuple[list[str], list[int]]:
    print("Loading dataset from HuggingFace …")
    ds = load_dataset("zefang-liu/phishing-email-dataset", split="train")
    df = ds.to_pandas()

    texts  = df["Email Text"].fillna("").apply(clean_text).tolist()
    labels = [1 if v == "Phishing Email" else 0 for v in df["Email Type"]]

    _print_class_balance(labels)
    return texts, labels


def _print_class_balance(labels: list[int]) -> None:
    n_pos = sum(labels)
    n     = len(labels)
    print(f"   Total: {n:,}  |  "
          f"positive: {n_pos:,} ({n_pos/n:.1%})  |  "
          f"negative: {n-n_pos:,} ({(n-n_pos)/n:.1%})")

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(**TFIDF_PARAMS)),
        ("clf",   MultinomialNB(alpha=0.1)),
    ])

# TRENING

def find_threshold(pipeline: Pipeline, X_val: list[str], y_val: list[int], min_recall: float = 0.99) -> float:
    from sklearn.metrics import precision_recall_curve

    probs = pipeline.predict_proba(X_val)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_val, probs)

    best_threshold = 0.5
    for precision, recall, threshold in zip(precisions, recalls, thresholds):
        if recall >= min_recall:
            best_threshold = threshold

    return best_threshold


def train_and_evaluate(texts: list[str], labels: list[int]) -> tuple[Pipeline, float]:
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
    X_fit, X_val, y_fit, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)

    print("\nTraining")
    pipeline = build_pipeline()
    pipeline.fit(X_fit, y_fit)

    cv = cross_val_score(pipeline, X_fit, y_fit, cv=5, scoring="f1", n_jobs=-1)
    print(f"   5-fold CV F1: {cv.mean():.4f} ± {cv.std():.4f}")

    # ── Threshold tuning ─────────────────────────────────────────────────────
    threshold = find_threshold(pipeline, X_val, y_val, min_recall=0.999)
    print(f"   Optimal threshold (≥99% recall): {threshold:.4f}  "
          f"(default was 0.5000)")

    # ── Evaluate with tuned threshold ────────────────────────────────────────
    probs  = pipeline.predict_proba(X_test)[:, 1]
    y_pred = (probs >= threshold).astype(int)

    print("\nClassification Report (tuned threshold):")
    print(classification_report(y_test, y_pred, target_names=["legit", "spam"]))

    _plot_confusion_matrix(y_test, y_pred)

    return pipeline, threshold

# CM

def _plot_confusion_matrix(y_test, y_pred) -> None:
    cm   = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=["legit", "spam"])
    disp.plot(cmap="Blues")
    plt.title("Phishing Guard CM")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=150)
    print("   Confusion matrix saved → confusion_matrix.png")
    plt.close()


# VIRUSTOTAL

def _vt_scan_url(url: str) -> dict | None:

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return None

    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=VT_HEADERS,
            data={"url": url},
            timeout=10,
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=VT_HEADERS,
            timeout=10,
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["stats"]
        return stats

    except requests.RequestException as e:
        print(f"    VirusTotal error for {url}: {e}")
        return None


def scan_urls_virustotal(urls: list[str]) -> list[dict]:

    results = []
    for i, url in enumerate(urls):
        if i > 0:
            time.sleep(VT_RATE_LIMIT_DELAY)

        stats = _vt_scan_url(url)
        if stats is None:
            results.append({"url": url, "error": True})
            continue

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = "MALICIOUS"
        elif suspicious > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        results.append({
            "url": url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "verdict": verdict,
            "error": False,
        })

    return results


def _print_vt_results(vt_results: list[dict]) -> None:

    if not vt_results:
        print("      No URLs found.")
        return

    for r in vt_results:
        if r.get("error"):
            print(f"      • {r['url']}")
            print(f"        VirusTotal: unavailable (check API key)")
        else:
            print(f"      • {r['url']}")
            print(f"        {r['verdict']}  —  "
                  f"{r['malicious']} malicious / "
                  f"{r['suspicious']} suspicious / "
                  f"{r['harmless']} clean  "
                  f"({r['total']} vendors total)")


# MAIN
def read_multiline(prompt: str) -> str:
    """
    Read a multiline paste from the user.
    The user signals they are done by entering a blank line.
    """
    print(prompt)
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)

DEMO_EMAILS = [
    """Congratulations! You've been selected for a $1,000 Amazon gift card.
    Click here immediately to claim: http://totally-not-a-scam.ru/claim?id=928374""",

    """Hi Sarah, just following up on yesterday's meeting. I've attached the
    Q3 budget spreadsheet we discussed. Let me know if you have questions. Best, Tom""",

    """URGENT: Your PayPal account has been limited. Verify your identity now
    or your account will be suspended. Login at: http://paypa1-secure-login.xyz/verify""",
]

def predict_one(pipeline: Pipeline, threshold: float, email: str) -> None:

    vt_enabled  = VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY"
    prob        = pipeline.predict_proba([clean_text(email)])[0, 1]
    pred        = int(prob >= threshold)
    model_label = "SPAM" if pred == 1 else "LEGIT"

    print(f"\n   Model : {model_label}  (confidence: {prob:.2%})")

    urls = extract_urls(email)
    if urls:
        print(f"URLs found ({len(urls)}):")
        if vt_enabled:
            vt_results = scan_urls_virustotal(urls)
            _print_vt_results(vt_results)
        else:
            for url in urls:
                print(f"      • {url}")
            print(" Set VT_API_KEY to enable VirusTotal scanning.")
    else:
        print(f"No URLs found.")

def main():
    texts, labels = load_default_dataset()
    pipeline, threshold = train_and_evaluate(texts, labels)

    print("\n" + "════════════════════════════════════════════════════════════════")
    print("  Welcome to PhishGuard powered by SentinelAI")
    print("  Type 'quit' and press Enter to exit.")
    print("════════════════════════════════════════════════════════════════")

    while True:
        email = read_multiline("\nPaste email (blank line when done, 'quit' to exit):")
        if email.strip().lower() == "quit":
            print("Goodbye.")
            break
        if not email.strip():
            print("No input received, try again.")
            continue
        predict_one(pipeline, threshold, email)


if __name__ == "__main__":
    main()
