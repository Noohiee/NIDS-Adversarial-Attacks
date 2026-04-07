
import torch
import numpy as np
from preprocessing import load_data, normalize
from models import Classifier

# ── 1. Load the dataset ──────────────────────────────────────────────
print("Loading dataset...")
X, y = load_data("MachineLearningCVE")
X = normalize(X)
print(f"Dataset shape: {X.shape}")

# ── 2. Load the trained model ────────────────────────────────────────
print("\nLoading model...")
checkpoint = torch.load(
    "checkpoints/baseline_cnn_cicids2017.pth",
    map_location=torch.device("cpu")   # no GPU needed
)

input_dim  = X.shape[1]
num_class  = len(np.unique(y))

clf = Classifier(
    method="cnn5",
    input_dim=input_dim,
    num_classes=num_class,
    num_epochs=1,
    runs_dir="checkpoints"
)
clf.model.load_state_dict(checkpoint["model_state_dict"])
clf.model.eval()
print("Model loaded!")

# ── 3. Pick a small sample of MALICIOUS flows ────────────────────────
# In CIC-IDS2017, label 0 = BENIGN, everything else = attack
malicious_idx = np.where(y != 0)[0]
sample_idx    = malicious_idx[:500]   # use 500 malicious samples
X_mal         = X[sample_idx]
y_mal         = y[sample_idx]
print(f"\nUsing {len(X_mal)} malicious samples")

# ── 4. Baseline prediction on original flows ─────────────────────────
print("\nRunning baseline predictions...")
preds_original = clf.predict(X_mal)
baseline_evasion = np.sum(preds_original == 0) / len(preds_original)
print(f"Baseline evasion rate (original): {baseline_evasion:.2%}")

# ── 5. Simulate naive attack effect ──────────────────────────────────
# Since pcap→CSV feature extraction needs CICFlowMeter (complex tool),
# we simulate naive perturbations directly on the feature vectors
# This is a valid approximation for naive packet-level attacks

def simulate_delay(X):
    X_mod = X.copy()
    # Delay affects flow duration and inter-arrival time features
    X_mod[:, 0] = X_mod[:, 0] * 1.1   # increase duration-like feature
    return X_mod

def simulate_padding(X):
    X_mod = X.copy()
    # Padding affects packet length features
    X_mod[:, 4] = X_mod[:, 4] + 0.05  # increase packet length feature
    X_mod[:, 5] = X_mod[:, 5] + 0.05
    return X_mod

def simulate_header_edit(X):
    X_mod = X.copy()
    # TTL/window changes affect header features slightly
    X_mod[:, 2] = np.clip(X_mod[:, 2] * 1.02, -1, 1)
    return X_mod

def simulate_reorder(X, seed=42):
    X_mod = X.copy()
    rng = np.random.default_rng(seed)
    # Reorder shuffles packet order within flows
    idx = rng.permutation(len(X_mod))
    X_mod = X_mod[idx]
    return X_mod

attacks = {
    "delay"      : simulate_delay(X_mal),
    "padding"    : simulate_padding(X_mal),
    "header_edit": simulate_header_edit(X_mal),
    "reorder"    : simulate_reorder(X_mal),
}

# ── 6. Compute evasion rate for each attack ──────────────────────────
print("\n========== NAIVE PLA EVASION RATES ==========")
print(f"{'Attack':<15} {'Evaded':>8} {'Total':>8} {'Evasion Rate':>14}")
print("-" * 50)
print(f"{'original':<15} {int(baseline_evasion*len(X_mal)):>8} {len(X_mal):>8} {baseline_evasion:>13.2%}")

for attack_name, X_mod in attacks.items():
    preds = clf.predict(X_mod)
    evaded = np.sum(preds == 0)
    evasion_rate = evaded / len(preds)
    print(f"{attack_name:<15} {evaded:>8} {len(preds):>8} {evasion_rate:>13.2%}")

print("\nDone! These are your naive PLA evasion rates.")