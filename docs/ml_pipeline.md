# OrgShield AI - Machine Learning & Anomaly Detection Pipeline

## 1. Problem Formulation

Under the **INT396** problem formulation:
$$D_{train} = \{x_i\}_{i=1}^{N_{train}}, \quad y_i \equiv 0 \quad (\text{Legitimate Organizational Communications})$$

No phishing samples ($y=1$) are available during training or feature engineering. The goal is to construct an anomaly scoring function $S(x) \in [0, 1]$ and an operational threshold $\tau$ such that:
$$\hat{y} = \begin{cases} 1 & \text{if } S(x) \ge \tau \quad (\text{Threat Flagged}) \\ 0 & \text{if } S(x) < \tau \quad (\text{Normal Communication}) \end{cases}$$

---

## 2. Feature Engineering Taxonomy (76 Dimensions)

Features are extracted across six distinct cyber behavioral domains:

### A. Sender & Domain Features
1. `sender_freq_log`: $\ln(1 + \text{freq}_{train}(\text{sender}))$
2. `domain_freq_log`: $\ln(1 + \text{freq}_{train}(\text{domain}))$
3. `is_first_time_sender`: Binary indicator (1 if sender was never observed in training history, else 0).
4. `is_external_sender`: Binary indicator (1 if sender domain $\ne$ target organization domain `enron.com`).
5. `max_sender_recip_pair_freq`: Historical communication frequency between sender and recipient.

### B. Communication Behaviour Features
6. `recipient_count`: Total direct recipients (`To:`).
7. `cc_count`: Carbon-copy recipient count.
8. `bcc_count`: Blind carbon-copy recipient count.
9. `external_recipient_count`: Count of non-organizational recipients.
10. `external_recipient_ratio`: Ratio of external recipients to total recipients.
11. `is_mass_email`: Flag for high recipient fan-out (> 10 recipients).

### C. Content & Lexical Features
12. `subject_length`: Character length of subject.
13. `subject_word_count`: Word count of subject.
14. `body_length`: Character length of body.
15. `body_word_count`: Word count of body.
16. `subject_caps_ratio`: Uppercase character fraction in subject.
17. `body_caps_ratio`: Uppercase character fraction in body.
18. `urgent_keyword_count`: Frequency of urgency tokens (*urgent, immediately, action required, account suspended, verify*).
19. `financial_keyword_count`: Frequency of financial tokens (*wire, invoice, bank, payroll, w-2, gift card, credit card*).
20. `suspicious_greeting_flag`: Flag for generic impersonation greetings (*Dear Customer, Dear User, Attention Valued Member*).
21–60. `tfidf_00` to `tfidf_www`: 40-dimensional TF-IDF unigram and bigram representation learned strictly from training corpus text.

### D. URL & Threat Heuristics
61. `url_count`: Total URLs extracted from email text.
62. `has_ip_url`: Flag indicating a raw IPv4 address used as URL host (e.g., `http://192.168.1.1/login`).
63. `has_suspicious_tld`: Flag indicating high-risk TLDs (`.xyz`, `.top`, `.buzz`, `.club`, `.tk`, `.loan`).
64. `suspicious_url_count`: Count of URLs matching heuristic threat indicators (hex encoding, embedded `@` credential signs).
65. `shortened_url_count`: Count of URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`).
66. `has_multiple_urls`: Flag for emails containing 3 or more hyperlinks.

### E. Temporal Profiles
67. `sending_hour`: Time of transmission (0–23).
68. `day_of_week`: Day of transmission (0=Monday, 6=Sunday).
69. `is_weekend`: Flag for Saturday or Sunday dispatch.
70. `is_off_hours`: Flag for dispatch outside normal corporate hours (before 07:00 or after 19:00).

### F. Header & Routing Inconsistencies
71. `reply_to_mismatch`: Flag indicating `Reply-To` domain differs from `From` domain.
72. `has_reply_to`: Flag indicating explicit `Reply-To` header.
73. `routing_hop_count`: Number of `Received:` relay hops recorded in message headers.
74. `has_public_ip`: Flag indicating presence of a routable public IPv4 address in relay headers.
75. `missing_message_id`: Flag indicating missing standard RFC Message-ID.
76. `missing_date`: Flag indicating missing or non-RFC compliant date header.

---

## 3. Unsupervised Anomaly Algorithms

### 3.1 Isolation Forest (Primary Model)
- **Concept**: Tree-based ensemble that recursively partitions feature space. Anomalies require fewer random splits to isolate than normal points, yielding shorter average path lengths $h(x)$.
- **Anomaly Score**:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
  where $c(n) = 2\ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in a Binary Search Tree.

### 3.2 One-Class SVM (Support Vector Boundary)
- **Concept**: Maps vectors into an infinite-dimensional feature space via Radial Basis Function (RBF) kernel:
  $$K(x, x') = \exp(-\gamma \|x - x'\|^2)$$
  Constructs a maximum-margin hyperplane separating normal vectors from the origin with margin parameter $\nu$.

### 3.3 Local Outlier Factor (LOF Novelty Mode)
- **Concept**: Computes the local reachability density of an observation relative to its $k$-nearest neighbors:
  $$\text{LOF}_k(p) = \frac{\sum_{o \in N_k(p)} \frac{\text{lrd}(o)}{\text{lrd}(p)}}{|N_k(p)|}$$
  Points with significantly lower density than their neighbors receive high outlier scores.

---

## 4. Leakage-Aware Validation Threshold Calibration

To maintain academic rigor and satisfy INT396 requirements:
1. **Zero Phishing Exposure**: No phishing examples are present during training or threshold selection.
2. **Operational Constraint**: In real-world enterprise deployments, security operations centers cannot tolerate unbounded false alarm rates. We specify an allowable false alarm constraint on normal communications:
   $$\text{FPR}_{\text{target}} \le 1.5\% \quad (\le 15 \text{ False Positives per 1,000 Normal Emails})$$
3. **Percentile Calibration**: The decision threshold $\tau$ is chosen as the $(1 - \text{FPR}_{\text{target}})$ percentile of validation scores on legitimate Enron emails:
   $$\tau = \text{Percentile}(S(X_{val}), 100 \times (1 - \text{FPR}_{\text{target}}))$$

---

## 5. Experimental Results Summary

Evaluated on the held-out test partition consisting of **759 legitimate Enron test emails** and **100 curated phishing benchmark attacks**:

| Model | Detection Rate | FP / 1,000 Normal | Precision | Recall | F1-Score | PR-AUC | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | **83.00%** | **25.03** | **0.8137** | **0.8300** | **0.8218** | **0.8944** | **0.9572** |
| **One-Class SVM** | 66.00% | 1.32 | 0.9851 | 0.6600 | 0.7904 | 0.9685 | 0.9698 |
| **Local Outlier Factor** | 10.00% | 5.27 | 0.7143 | 0.1000 | 0.1754 | 0.1492 | 0.6874 |
| **Rule-Based Baseline** | 100.00% | 3.95 | 0.9709 | 1.0000 | 0.9852 | 0.9914 | 0.9980 |

### Key Experimental Insights:
- **Isolation Forest** achieved the highest unsupervised ML detection rate (83.00%) and highest F1-score (0.8218).
- **One-Class SVM** demonstrated remarkable precision (0.9851) and exceptionally low false positives (only 1.32 per 1,000 legitimate emails), making it ideal for low-noise environments.
- **Local Outlier Factor** suffered from the curse of dimensionality across the 76-feature vector space, resulting in lower recall.
- **The Rule-Based Baseline** effectively caught signature attacks but lacks adaptability against zero-day evasion or nuanced linguistic attacks.
