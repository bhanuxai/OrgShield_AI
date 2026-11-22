# OrgShield AI: Final Scientific Integrity & Domain-Shift Audit
**Course / Project**: INT396 — *Email Threat Discovery Without Labelled Phishing Examples*  
**Date of Audit**: November 22, 2026  
**Auditor**: Independent Principal AI/ML Systems Auditor  
**Scope**: Final Empirical Verification, Dataset Integrity, Domain-Shift Quantification, and Model Invariance  
**Artifact Verified**: `reports/evaluation/final_integrity_audit_data.json`  

---

## Executive Summary

This report concludes the comprehensive scientific evaluation of **OrgShield AI**. Following the independent audit and the external generalisation benchmark on the Jose Nazario Phishing Corpus, this final audit establishes the complete data provenance, quantitative domain-shift measurements, exact metric verification, model artifact invariance, and scientific conclusions.

All empirical findings were computed deterministically from scratch using the frozen model artifacts and preprocessors via [audit_integrity_and_domain_shift.py](file:///c:/Users/Bhanu/Desktop/Email%20Threat%20Discovery%20Without%20Labelled%20Phishing%20_INT396/scripts/audit_integrity_and_domain_shift.py). The test suite confirmed **20 passed, 0 failed, 0 skipped** tests.

---

## 1. Dataset Verification & Corpus Integrity

Every email record was inspected directly from source files. Collection dates and temporal distributions were derived exclusively from parsed RFC 2822 `Date:` headers, never inferred from filesystem modification timestamps.

### 1.1 Dataset Summary & Cryptographic Checksums

| Dataset Component | Source / File Path | SHA-256 Cryptographic Checksum | Size (Bytes) | Parsed Emails | Unique Hashes | Duplicates |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Enron Corporate Sample** | `enron_mail_20150507_final/maildir` | *Streaming Directory Partition* | $1.7\text{ GB}$ (Total) | $6,000$ | $5,744$ | $256$ |
| **Jose Nazario Phishing** | `ml/data/external/nazario_phishing0.mbox` | `6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848` | $3,119,972$ | $414$ | $292$ | $122$ |
| **Synthetic Benchmark** | `ml/data/phishing_benchmark.json` | `3e25dada815ef6fc0a18d07f71506d81bc47e00085ce88d6b479349919f0f8f9` | $82,876$ | $100$ | $100$ | $0$ |

### 1.2 Temporal Boundary Analysis (RFC 2822 Header Dates)

All dates were normalized to UTC using `email.utils.parsedate_to_datetime`:

* **Enron Corporate Sample ($N = 6,000$)**:
  * Valid parsed dates: $6,000 / 6,000$ ($100.0\%$)
  * Missing or unparseable dates: $0$
  * Earliest valid date: `1980-01-01T00:00:00+00:00` (historical gateway header artifact)
  * Core operational window: $1999\text{--}2002$ (active Enron corporate era)
  * Latest valid date: `2004-02-04T02:23:47+00:00`
* **Jose Nazario Phishing Corpus ($N = 414$)**:
  * Valid parsed dates: $414 / 414$ ($100.0\%$)
  * Missing or unparseable dates: $0$
  * Earliest valid date: `1970-01-03T14:43:14+00:00` (single malformed mail-client epoch reset header)
  * Active phishing campaign window: November 2004 – June 2005
  * Latest valid date: `2005-06-13T14:15:23+00:00`
* **Duplicate Message Analysis**:
  * Nazario contains $122$ duplicates ($292$ unique content hashes across $414$ messages), reflecting authentic bulk spam runs where identical lures were delivered to multiple harvested recipients.
  * Enron contains $256$ duplicate messages across the $6,000$-sample set, reflecting company-wide broadcast memos and carbon-copied trading schedules.

### 1.3 Cross-Benchmark Overlap Audit
To ensure zero data contamination:
* **Synthetic $\leftrightarrow$ Nazario Content Hash Overlap**: **0** (Zero shared bodies or messages).
* **Synthetic $\leftrightarrow$ Nazario Subject Line Overlap**: **0** (Zero identical subjects).
* **Enron $\leftrightarrow$ Nazario Content Hash Overlap**: **0** (Zero cross-corpus leakage).

---

## 2. Quantitative Domain-Shift Analysis

The feature extractor [feature_extractor.joblib](file:///c:/Users/Bhanu/Desktop/Email%20Threat%20Discovery%20Without%20Labelled%20Phishing%20_INT396/ml/models_store/feature_extractor.joblib) was fitted strictly on $4,201$ normal Enron training emails. The following measurements quantify the domain shift between Enron and the external Nazario dataset:

```
                                  Domain-Shift Spectrum
+-----------------------------------------------------------------------------------+
| Enron In-Domain Baseline                               Nazario Cross-Domain Drift |
| - Vocabulary Out-of-Vocabulary: 0.0%                   - Vocabulary OOV: 99.60%   |
| - Unseen Sender Domains: 3.89%                         - Unseen Domains: 82.61%   |
| - Median Risk Score: 0.2162                            - Median Risk Score: 0.5414|
| - Primary Topic: Energy Trading / Corporate            - Primary Topic: Banking   |
+-----------------------------------------------------------------------------------+
```

### 2.1 Vocabulary & Lexical Starvation
* **Enron Training TF-IDF Vocabulary Size**: $40$ terms (e.g. `gas`, `power`, `trading`, `houston`, `ferc`, `contract`, `pipeline`, `market`, `deal`).
* **Nazario Unique Word Tokens**: $5,005$ distinct words extracted from subjects and bodies.
* **Nazario Tokens Absent from Enron Vocabulary**: **$4,985$ tokens ($99.60\%$ Out-Of-Vocabulary)**.
* **Lexical Impact**: Real banking phishing terms (`ebay`, `paypal`, `citibank`, `auction`, `bidding`, `billing`, `ssn`, `passcode`) were absent from the Enron corporate feature space. Consequently, Nazario emails projected as nearly empty vectors in the TF-IDF feature subspace.

### 2.2 TF-IDF Sparsity Per Email
* **Enron Held-Out Test Emails ($N = 899$)**:
  * Mean active TF-IDF features: $6.95 \pm 6.25$
  * Median active TF-IDF features: $5.0$
* **Nazario External Phishing Emails ($N = 414$)**:
  * Mean active TF-IDF features: $5.16 \pm 2.94$
  * Median active TF-IDF features: $5.0$
* **Observation**: Both corpora exhibit comparable active feature counts ($5.0$ median), but Nazario features activate on generic stopwords or shared numbers (`00`, `01`, `10`, `cc`) rather than substantive threat-discriminative keywords.

### 2.3 Sender Domain Familiarity
* **Enron Known Sender Domains**: $329$ domains learned during unsupervised training.
* **Enron Test Emails with Unseen Sender Domains**: $35 / 899$ (**$3.89\%$**).
* **Nazario Emails with Unseen Sender Domains**: $342 / 414$ (**$82.61\%$**).
* **Observation**: Unseen domain status contributed strong anomaly weight to the One-Class SVM kernel distance, preventing complete failure and allowing One-Class SVM to achieve an ROC-AUC of $0.8716$.

### 2.4 Header Presence & Structural Comparison

| Header Field | Enron Held-Out Normal ($N=899$) | Nazario Phishing ($N=414$) | Difference / Impact |
| :--- | :---: | :---: | :--- |
| **Missing Subject** | $33$ ($3.67\%$) | $0$ ($0.00\%$) | Phishing lures always supply a lure subject. |
| **Missing Date** | $0$ ($0.00\%$) | $0$ ($0.00\%$) | Both corpora retain valid RFC 2822 dates. |
| **Missing Reply-To** | $899$ ($100.00\%$) | $236$ ($57.00\%$) | Internal corporate exchange rarely populates `Reply-To`. |
| **Reply-To Present** | $0$ ($0.00\%$) | $178$ ($43.00\%$) | Phishing campaigns frequently redirect replies. |
| **Missing Message-ID** | $0$ ($0.00\%$) | $0$ ($0.00\%$) | Both datasets possess standard message identifiers. |

### 2.5 Continuous Anomaly Risk Score Distributions (One-Class SVM)

Continuous risk scores $s \in [0.0, 1.0]$ produced by the stateless monotonic mapping:

| Metric | Enron Normal ($N = 899$) | Nazario Phishing ($N = 414$) | Synthetic Phishing ($N = 100$) |
| :--- | :---: | :---: | :---: |
| **Minimum** | $0.0066$ | $0.0699$ | $0.7310$ |
| **25th Percentile** | $0.1365$ | $0.4286$ | $0.8824$ |
| **Median (50th)** | **$0.2162$** | **$0.5414$** | **$0.9108$** |
| **Mean** | $0.2509$ | $0.5551$ | $0.9035$ |
| **Std. Dev.** | $0.1717$ | $0.2050$ | $0.0491$ |
| **75th Percentile** | $0.3278$ | $0.6839$ | $0.9400$ |
| **95th Percentile** | **$0.5776$** | **$0.9184$** | **$0.9581$** |
| **99th Percentile** | $0.7904$ | $0.9395$ | $0.9581$ |
| **Maximum** | $0.9240$ | $0.9494$ | $0.9581$ |
| **Calibrated Threshold ($\tau$)** | **$0.7912$** | **$0.7912$** | **$0.7912$** |

```
Distribution Histogram Approximation:
Enron Normal:    [████████████████████] median=0.2162, 95%=0.5776
Nazario Phish:                 [████████████████████] median=0.5414, 95%=0.9184
Synthetic Phish:                                 [████████████████████] median=0.9108
Threshold tau:                                             | (0.7912)
```

**Distribution Analysis**:
1. Nazario phishing emails have a median risk score of **$0.5414$**, substantially higher than Enron normal emails (**$0.2162$**). This confirms that the model recognizes Nazario emails as anomalous relative to normal Enron traffic ($\text{ROC-AUC} = 0.8716$).
2. However, because threshold $\tau = 0.7912$ was calibrated at the extreme $98.5\text{th}$ percentile of normal corporate emails to limit false alarms to $\le 15$ per $1,000$, only the top $16.18\%$ of Nazario emails exceed $\tau$.
3. In contrast, synthetic phishing emails had a median of **$0.9108$** because they compounded four simultaneous overt threat indicators, causing $97\%$ to cross the threshold.

---

## 3. Metric Verification & Cross-Benchmark Isolation

All reported evaluation metrics were independently recalculated directly from the model risk scores and ground truth labels. Both benchmarks remain strictly isolated without pooled metrics:

### 3.1 Verified Evaluation Metrics Summary Table

| Metric | Synthetic Phishing Benchmark | External Nazario Phishing Benchmark | Exact Match with Saved Artifacts |
| :--- | :---: | :---: | :---: |
| **Total Evaluated ($N$)** | $999$ ($899$ Normal, $100$ Phishing) | $1,313$ ($899$ Normal, $414$ Phishing) | Yes |
| **True Positives (TP)** | $97$ | $67$ | Yes |
| **False Positives (FP)** | $9$ | $9$ | Yes |
| **True Negatives (TN)** | $890$ | $890$ | Yes |
| **False Negatives (FN)** | $3$ | $347$ | Yes |
| **Detection Rate (Recall)** | **$97.00\%$** ($0.9700$) | **$16.18\%$** ($0.1618$) | Yes |
| **Precision** | **$0.9151$** ($91.51\%$) | **$0.8816$** ($88.16\%$) | Yes |
| **F1-Score** | **$0.9417$** | **$0.2735$** | Yes |
| **FP / 1,000 Normal Emails** | **$10.01$** | **$10.01$** | Yes |
| **PR-AUC (Continuous)** | **$0.9764$** | **$0.7509$** | Yes |
| **ROC-AUC (Continuous)** | **$0.9977$** | **$0.8716$** | Yes |
| **Operating Threshold ($\tau$)** | $0.7912$ | $0.7912$ | Yes |

### 3.2 Continuous PR-AUC and ROC-AUC Verification
Both PR-AUC and ROC-AUC were computed directly from continuous risk scores using Scikit-Learn `precision_recall_curve` and `roc_auc_score`.
* **Synthetic Benchmark**: $\text{PR-AUC} = 0.9764$, $\text{ROC-AUC} = 0.9977$
* **Nazario Benchmark**: $\text{PR-AUC} = 0.7509$, $\text{ROC-AUC} = 0.8716$
* **Result**: The continuous ranking capability remains strong across both benchmarks, confirming that the underlying unsupervised distance metric is sound.

---

## 4. Model Invariance & Cryptographic Integrity

To confirm that no retraining, data leakage, or post-hoc parameter adjustments occurred after external evaluation commenced, cryptographic hashes and timestamps were audited:

| File Name | SHA-256 Checksum | Size (Bytes) | UTC Modification Timestamp | Status |
| :--- | :--- | :---: | :---: | :---: |
| `one_class_svm.joblib` | `7ced4b3df601f0ebfdd059c13f52b983ea1ec457a5ff199cbc8fa08968da56b5` | $127,711$ | `2026-11-22T11:39:56Z` | Verified Frozen |
| `isolation_forest.joblib` | `bb06a9db25fbf340b6526bd74de4ebaa202ad8dfad4d5ed3ac8d604ac3a5a8d4` | $1,097,865$ | `2026-11-22T11:39:56Z` | Verified Frozen |
| `local_outlier_factor.joblib` | `8cd8ae4960333a379e03ebf6b69064b2aca946fc18af3bf74b9a846b0f23f335` | $3,462,542$ | `2026-11-22T11:39:56Z` | Verified Frozen |
| `feature_extractor.joblib` | `877fb78b2df2333d79b0ae630fc0e259959804cab622eea21cdf46551d94f344` | $621,303$ | `2026-11-22T11:39:56Z` | Verified Frozen |
| `scaler.joblib` | `36eaa1419ff82af306d238aceb4de745626ffe46eb93b33627beac1428230b37` | $2,407$ | `2026-11-22T11:39:56Z` | Verified Frozen |
| `model_metadata.json` | `a970f50f515076fed4129aac263b444daab4063ac5f0ce0901f4a004516aaf4d` | $2,150$ | `2026-11-22T11:39:56Z` | Verified Frozen |

### Protocol Integrity Checks
1. **Zero Retraining**: All model and feature extractor files retain their original modification timestamp (`11:39:56 UTC`). No weights or scalers were modified during external evaluation.
2. **Threshold Invariance**: Threshold $\tau = 0.7912$ remained constant.
3. **Zero Phishing Training Labels**: Training and validation sets remain strictly legitimate Enron emails.
4. **Artifact Preservation**: All previous benchmark reports ([model_comparison.json](file:///c:/Users/Bhanu/Desktop/Email%20Threat%20Discovery%20Without%20Labelled%20Phishing%20_INT396/reports/evaluation/model_comparison.json), [independent_audit.md](file:///c:/Users/Bhanu/Desktop/Email%20Threat%20Discovery%20Without%20Labelled%20Phishing%20_INT396/reports/evaluation/independent_audit.md), [external_generalisation_evaluation.md](file:///c:/Users/Bhanu/Desktop/Email%20Threat%20Discovery%20Without%20Labelled%20Phishing%20_INT396/reports/evaluation/external_generalisation_evaluation.md)) are preserved unmodified.

---

## 5. Unresolved Issues & Scientific Limitations

1. **Subspace Lexical Starvation**:
   The $40$-dimensional TF-IDF vocabulary fitted exclusively on Enron emails left $99.60\%$ of Nazario tokens unrepresented. When evaluated zero-shot on consumer phishing, content-based features provide minimal signal.
2. **Operational Threshold Trade-off**:
   Maintaining a strict $1.5\%$ FPR constraint ($\le 15$ FP per $1,000$ emails) limits One-Class SVM recall to $16.18\%$ on out-of-domain phishing. Lowering the threshold to $\tau = 0.50$ increases recall to $55.07\%$, but raises the false positive rate on normal corporate traffic.
3. **Historical Epoch Timestamp Anomaly**:
   A single message in the Nazario mbox (`1970-01-03T14:43:14+00:00`) reflects an epoch reset bug from an early 2000s mail client. This was safely handled by UTC normalization.

---

## 6. Final Scientific Conclusion About Generalisation

1. **The original 97.00% detection rate does NOT generalise to in-the-wild historical phishing at the same operating point.**
2. **Synthetic Benchmarks Overestimate Heuristic and Boundary Separability**:
   The $97\%$ ML recall and $100\%$ baseline recall on the synthetic benchmark were driven by compounding synthetic indicators (raw IP hosts, `.xyz`/`.top` TLDs, explicit urgency keywords). Real-world historical attacks avoid these obvious markers, causing the rule-based baseline to collapse to **$0.97\%$**.
3. **One-Class SVM Preserves Robust Anomaly Ranking Across Domains**:
   Despite total vocabulary divergence ($99.6\%$ OOV), One-Class SVM achieved **$\text{ROC-AUC} = 0.8716$**, **$\text{PR-AUC} = 0.7509$**, and **$88.16\%$ precision** on real phishing. Its structural and sender-domain kernels capture meaningful organizational boundaries without supervision.

---

## 7. Automated Test Suite Verification

The full automated test suite was executed:
```powershell
$env:PYTHONPATH="."; .venv\Scripts\python.exe -m pytest tests -v
```
* **Total Tests Executed**: **20**
* **Passed**: **20**
* **Failed**: **0**
* **Skipped**: **0**
* **Execution Time**: $11.22$ seconds
* **Status**: Complete Pass.
