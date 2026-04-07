"""
Phase 5 - Integration & Comparison Analysis
Compares Naive Attack (Phase 3) vs Constrained Attack (Phase 4)
"""

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# ============================================================
# STEP 1: Load the results from Phase 3 and Phase 4
# ============================================================

# Phase 3 - Naive attack results (no constraints applied)
naive = pd.read_csv('phase3_attack_results.csv')
naive['is_success'] = naive['orig_pred'] != naive['adv_pred']  # success = prediction changed

# Phase 4 - Constrained attack results (realistic constraints applied)
constrained = pd.read_csv('constrained_attack_results.csv')

print("=== Data Loaded ===")
print(f"Naive attack samples     : {len(naive)}")
print(f"Constrained attack samples: {len(constrained)}")

# ============================================================
# STEP 2: Calculate key metrics
# ============================================================

naive_success     = naive['is_success'].mean()
naive_semantic    = naive['semantic_ok'].mean()
naive_dur_delta   = naive['delta_duration'].abs().mean()
naive_iat_delta   = naive['delta_iat'].abs().mean()

const_success     = constrained['is_success'].mean()
const_semantic    = constrained['semantic_ok'].mean()
const_dur_delta   = constrained['delta_duration'].abs().mean()
const_iat_delta   = constrained['delta_iat'].abs().mean()

# Baseline values added
baseline_success  = 0.0
baseline_semantic = 1.0

print("\n=== Key Metrics ===")
print(f"{'Metric':<30} {'Baseline':>10} {'Naive':>10} {'Constrained':>15}")
print("-" * 65)
print(f"{'Attack Success Rate':<30} {baseline_success:>10.1%} {naive_success:>10.1%} {const_success:>15.1%}")
print(f"{'Semantic Validity':<30} {baseline_semantic:>10.1%} {naive_semantic:>10.1%} {const_semantic:>15.1%}")
print(f"{'Avg Delta Duration':<30} {'-':>10} {naive_dur_delta:>10.4f} {const_dur_delta:>15.4f}")
print(f"{'Avg Delta IAT':<30} {'-':>10} {naive_iat_delta:>10.4f} {const_iat_delta:>15.4f}")

# ============================================================
# STEP 3: Generate Comparison Plots
# ============================================================

colors = ['#2196F3', '#FF5722']  # Blue = Naive, Orange = Constrained
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Phase 5 — Baseline vs Naive vs Constrained Attack Comparison',
             fontsize=16, fontweight='bold', y=1.03)

# --- Plot 1: Success Rate vs Semantic Validity ---
ax1 = axes[0, 0]
metrics = ['Attack Success Rate', 'Semantic Validity']
baseline_vals = [baseline_success, baseline_semantic]
naive_vals = [naive_success, naive_semantic]
const_vals = [const_success, const_semantic]

x = np.arange(len(metrics))
w = 0.25
bars0 = ax1.bar(x - w, baseline_vals, w, label='Baseline', color='gray', alpha=0.85)
bars1 = ax1.bar(x, naive_vals, w, label='Naive', color=colors[0], alpha=0.85)
bars2 = ax1.bar(x + w, const_vals, w, label='Constrained', color=colors[1], alpha=0.85)
ax1.set_ylim(0, 1.15)
ax1.set_title('Success Rate vs Semantic Validity', fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels(metrics)
ax1.set_ylabel('Rate')
ax1.legend()
for bar in bars0:
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f'{bar.get_height():.1%}', ha='center', fontsize=10)
for bar in bars1:
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f'{bar.get_height():.1%}', ha='center', fontsize=10)
for bar in bars2:
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
             f'{bar.get_height():.1%}', ha='center', fontsize=10)

# --- Plot 2: Perturbation Magnitude ---
ax2 = axes[0, 1]
naive_mag  = [naive_dur_delta, naive_iat_delta]
const_mag  = [const_dur_delta, const_iat_delta]

x2 = np.arange(2)
b1 = ax2.bar(x2 - w/2, naive_mag, w, label='Naive', color=colors[0], alpha=0.85)
b2 = ax2.bar(x2 + w/2, const_mag, w, label='Constrained', color=colors[1], alpha=0.85)
ax2.set_title('Average Perturbation Magnitude', fontweight='bold')
ax2.set_xticks(x2)
ax2.set_xticklabels(['Δ Duration', 'Δ Inter-Arrival Time'])
ax2.set_ylabel('Mean Absolute Change')
ax2.legend()
for bar in b1:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
             f'{bar.get_height():.3f}', ha='center', fontsize=10)
for bar in b2:
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
             f'{bar.get_height():.3f}', ha='center', fontsize=10)

# --- Plot 3: Per-class success rate (constrained) ---
ax3 = axes[1, 0]
class_success = constrained.groupby('orig_pred')['is_success'].agg(['mean', 'count'])
class_success = class_success[class_success['count'] > 100]  # only classes with enough data
ax3.bar(class_success.index.astype(str), class_success['mean'],
        color=colors[1], alpha=0.85)
ax3.set_title('Constrained Attack — Success Rate per Class', fontweight='bold')
ax3.set_xlabel('Traffic Class')
ax3.set_ylabel('Success Rate')
ax3.set_ylim(0, 1.15)
ax3.axhline(y=const_success, color='black', linestyle='--', linewidth=1.2,
            label=f'Overall avg ({const_success:.1%})')
ax3.legend()

# --- Plot 4: Realism vs Evasion Trade-off ---
ax4 = axes[1, 1]
class_stats = constrained.groupby('orig_pred').agg(
    success=('is_success', 'mean'),
    semantic=('semantic_ok', 'mean'),
    count=('is_success', 'count')
).reset_index()
class_stats = class_stats[class_stats['count'] > 100]

ax4.scatter(class_stats['semantic'], class_stats['success'],
            s=class_stats['count'] / 500, alpha=0.7,
            color=colors[1], edgecolors='black', linewidth=0.5)
for _, row in class_stats.iterrows():
    ax4.annotate(f"C{int(row['orig_pred'])}",
                 (row['semantic'], row['success']),
                 textcoords='offset points', xytext=(5, 3), fontsize=8)
ax4.set_title('Realism vs Evasion Trade-off (per class)', fontweight='bold')
ax4.set_xlabel('Semantic Validity Rate (Realism)')
ax4.set_ylabel('Attack Success Rate (Evasion)')
ax4.set_xlim(0, 1.1)
ax4.set_ylim(-0.1, 1.1)

# ============================================================
# STEP 4: Save the plot
# ============================================================

plt.tight_layout()
plt.savefig('phase5_comparison_plots.png', dpi=150, bbox_inches='tight')
plt.show()
print("\nPlot saved as: phase5_comparison_plots.png")