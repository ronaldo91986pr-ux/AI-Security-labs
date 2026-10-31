# Threat Model: Adversarial ML Attacks (MITRE ATLAS)

**Author:** Jose Alvarez Ramirez
**Framework:** MITRE ATLAS (Adversarial Threat Landscape for AI Systems), with NIST AI RMF and OWASP ML/LLM Top 10 cross-references
**Methodology:** STRIDE-style decomposition of an ML pipeline, mapped to ATLAS tactics/techniques, scored by likelihood x impact
**Status:** Living document. Technique IDs reflect the ATLAS matrix at time of writing; verify against https://atlas.mitre.org before citing, since IDs and sub-techniques are renumbered between releases.

---

## 1. Scope and System Under Analysis

Reference architecture: a cloud-hosted ML platform (Azure ML / AWS SageMaker pattern) serving a fraud/anomaly classifier and an LLM-backed internal assistant.

| Stage | Components | Trust boundary |
|---|---|---|
| Data ingestion | Blob/S3 landing zones, ETL, third-party feeds, user-labeled data | External data -> internal storage |
| Training | Notebooks, compute clusters, experiment tracking, feature store | Dev/data-science -> prod registry |
| Model registry | Versioned artifacts (pickle/ONNX/safetensors), container images | Registry -> deployment |
| Inference | REST endpoint behind API gateway, batch scoring | Internet/internal clients -> model |
| Monitoring | Logging, drift detection, feedback loop | Prod telemetry -> retraining data |

**Crown jewels:** training data (PII, proprietary labels), model weights (IP), inference integrity (business decisions depend on outputs), feedback loop (feeds retraining).

**Adversary profiles**

| Profile | Access | Goal |
|---|---|---|
| External, black-box | Public/partner inference API only | Extraction, evasion, cost abuse |
| Malicious data contributor | Can submit labeled data or feedback | Poisoning, backdoor |
| Supply-chain attacker | Public model hubs, packages, datasets | Code execution, trojaned weights |
| Insider / compromised identity | Storage, registry, or pipeline permissions | Tamper, exfiltrate weights/data |

---

## 2. Threat Summary

| # | Threat | ATLAS technique(s) | Likelihood | Impact | Risk |
|---|---|---|---|---|---|
| T1 | Training data poisoning / backdoor | AML.T0020 Poison Training Data; AML.T0018 Manipulate AI Model (Backdoor) | Medium | High | **High** |
| T2 | Model extraction (theft via API) | AML.T0040 Inference API Access; AML.T0024.002 Extract ML Model; AML.T0005 Create Proxy ML Model | High | Medium-High | **High** |
| T3 | Adversarial perturbation / evasion | AML.T0043 Craft Adversarial Data; AML.T0015 Evade ML Model | High | High | **High** |
| T4 | Membership inference / model inversion | AML.T0024.000 Infer Training Data Membership; AML.T0024.001 Invert ML Model | Medium | High (PII) | **High** |
| T5 | ML supply chain compromise | AML.T0010 ML Supply Chain Compromise; AML.T0018.002 Embed Malware | Medium | Critical | **Critical** |
| T6 | LLM prompt injection / jailbreak | AML.T0051 LLM Prompt Injection; AML.T0054 LLM Jailbreak | High | Medium-High | **High** |
| T7 | Denial of ML service / cost harvesting | AML.T0029 Denial of ML Service; AML.T0034 Cost Harvesting | Medium | Medium | Medium |

Scoring: Likelihood and Impact on Low/Medium/High; Risk = combined judgment, weighted up where the failure is silent (wrong predictions look like normal predictions).

---

## 3. Detailed Threat Analysis

### T1: Training Data Poisoning and Backdoors

**ATLAS:** AML.T0020 Poison Training Data, AML.T0018 Manipulate AI Model (Backdoor ML Model)

**How it works**
- *Availability/integrity poisoning:* attacker injects mislabeled or skewed samples so overall accuracy or a target class degrades.
- *Backdoor (targeted) poisoning:* attacker inserts samples carrying a trigger (pixel patch, rare token, specific field value) paired with an attacker-chosen label. Clean-data accuracy stays normal; trigger input flips the output. Standard validation does not catch this because the test set has no trigger.
- *Feedback-loop poisoning:* if production predictions or user feedback feed retraining, the attacker poisons through the front door with no storage access.

**Preconditions:** write access to a data source, a scraped/public dataset, a labeling vendor, or a user feedback channel.

**Impact:** silent misclassification of attacker-chosen inputs (e.g., fraud that always scores "legit"), compliance failure, loss of model trust.

**Detection**
- Data lineage diffs: unexpected volume, source, or label-distribution shift between dataset versions.
- Per-slice accuracy tracking, not just global accuracy.
- Spectral signature / activation clustering analysis on suspect training subsets.
- Neural Cleanse-style trigger reverse engineering for high-value models.

**Mitigations (enterprise)**
| Control | Implementation |
|---|---|
| Data provenance and integrity | Hash and version every dataset (DVC / Azure ML data assets / S3 Object Lock + versioning); signed manifests |
| Least privilege on data | Entra ID RBAC / AWS IAM scoped write access to landing zones; separate ingest vs. training roles; no standing write access for data scientists |
| Input validation gates | Schema, range, and duplicate checks in the pipeline; quarantine zone before promotion to training set |
| Label assurance | Multi-annotator agreement, golden-set audits on vendor labels |
| Feedback-loop hardening | Rate-limit and reputation-score contributors; human review before feedback enters retraining |
| Robust training | Outlier filtering, differential-privacy training, ensemble/bagging to dilute poisoned subsets |
| Release gate | Backdoor scan + per-slice regression tests required before registry promotion |

---

### T2: Model Extraction

**ATLAS:** AML.T0040 ML Model Inference API Access, AML.T0024.002 Extract ML Model, AML.T0005 Create Proxy ML Model

**How it works:** attacker issues large numbers of queries (often crafted to cover decision boundaries), records outputs (labels, and especially confidence scores/logits), and trains a surrogate that approximates the victim. The surrogate then serves three purposes: IP theft, offline development of white-box adversarial examples that transfer to the real model (feeds T3), and a cheaper competing service.

**Preconditions:** query access. Risk scales with output richness: full probability vectors are far easier to extract from than top-1 labels.

**Impact:** loss of IP and training investment, enabling of precise evasion attacks, potential disclosure of proprietary logic.

**Detection**
- Per-identity query volume, velocity, and input diversity anomalies (systematic grid-like or boundary-probing sweeps).
- High ratio of near-duplicate or synthetic-looking inputs from one principal.
- Sudden consumption spikes from newly created keys.

Example KQL (Azure API Management gateway logs in Log Analytics; adapt table and column names to your diagnostic settings):

```kql
ApiManagementGatewayLogs
| where TimeGenerated > ago(24h)
| where ApiId == "fraud-scoring"
| summarize Requests = count(),
            DistinctPayloads = dcount(hash_md5(RequestBody)),
            Clients = dcount(CallerIpAddress)
          by SubscriptionId, bin(TimeGenerated, 1h)
| where Requests > 5000 and DistinctPayloads > 0.9 * Requests
| order by Requests desc
```

**Mitigations (enterprise)**
| Control | Implementation |
|---|---|
| Output minimization | Return label or coarse score bands, not raw logits/full probability vectors, unless a consumer needs them |
| Authentication and quotas | API gateway with per-key rate limits, daily quotas, and anomaly-triggered throttling |
| Identity hygiene | Short-lived tokens, no shared keys, KYC for external consumers, key-per-consumer for attribution |
| Query-pattern monitoring | Alert on extraction heuristics above; feed to SIEM (Sentinel/Splunk) |
| Output perturbation | Calibrated noise or rounding on confidence values (accept the utility trade-off) |
| Watermarking | Embed model watermarks / canary behaviors to prove theft after the fact |
| Legal | ToS prohibiting model replication, contractual audit rights for partners |

---

### T3: Adversarial Perturbation (Evasion)

**ATLAS:** AML.T0043 Craft Adversarial Data, AML.T0015 Evade ML Model

**How it works:** attacker applies small, targeted input changes that cross the model's decision boundary while staying valid to a human or downstream system.
- *White-box:* gradient-based (FGSM, PGD, C&W) using stolen or open weights.
- *Black-box:* query-based (score-based, decision-based like HopSkipJump) or transfer attacks via a proxy model from T2.
- *Domain-specific:* malware byte padding to evade ML AV, transaction feature manipulation to evade fraud models, patch/sticker attacks on vision systems.

**Impact:** direct bypass of ML-based security controls; this is the most operationally relevant threat for ML-driven detection (EDR, fraud, phishing classifiers).

**Detection**
- Input anomaly detection (feature-space outliers, out-of-distribution scores).
- Prediction instability: small input jitter producing large confidence swings.
- Repeated near-identical queries with incremental changes from one principal (query-based attack signature).

**Mitigations (enterprise)**
| Control | Implementation |
|---|---|
| Adversarial training | Include PGD-generated examples in training; re-run per model release |
| Input preprocessing | Canonicalization, feature squeezing, bounded feature ranges; reject out-of-spec inputs |
| Ensembles and diversity | Heterogeneous models or feature views so one perturbation does not flip all |
| Defense in depth | Never let a single ML verdict be the sole control; layer with rules, reputation, and human review for high-risk decisions |
| Query throttling | Slows black-box search attacks (shared control with T2) |
| Certified robustness | Randomized smoothing where provable bounds justify the accuracy cost |
| Red-team cadence | Scheduled evaluation with ART (Adversarial Robustness Toolbox), CleverHans, or Counterfit before each release |

---

### T4: Membership Inference and Model Inversion

**ATLAS:** AML.T0024.000 Infer Training Data Membership, AML.T0024.001 Invert ML Model

**How it works:** overfit models behave differently on training records (higher confidence, lower loss). Attacker uses that gap to decide whether a record was in training data, or to reconstruct representative features of training samples. For LLMs, the analogue is training data extraction via crafted prompts.

**Impact:** privacy breach and regulatory exposure (GDPR/LFPDPPP-class obligations), disclosure that a specific individual is in a sensitive dataset.

**Mitigations:** differential privacy (DP-SGD), regularization and early stopping to limit overfitting, output minimization (shared with T2), de-duplication and PII scrubbing of training data, DLP controls (e.g., Microsoft Purview) on datasets and LLM outputs, memorization audits before release.

---

### T5: ML Supply Chain Compromise

**ATLAS:** AML.T0010 ML Supply Chain Compromise, AML.T0018.002 Embed Malware

**How it works:** attacker publishes or tampers with a pretrained model, dataset, or ML package. Pickle-based formats execute arbitrary code on load; trojaned weights carry backdoors that survive fine-tuning; typosquatted packages target ML engineers.

**Impact:** code execution inside the training/inference environment, which means credential theft, lateral movement into the cloud tenant, and persistent backdoors.

**Mitigations (enterprise)**
| Control | Implementation |
|---|---|
| Safe serialization | Ban pickle for untrusted artifacts; use safetensors/ONNX; scan with ModelScan or equivalent |
| Artifact trust | Internal mirror/registry only; pin versions and hashes; verify publisher signatures |
| Sandboxed evaluation | Load and test third-party models in isolated, no-egress compute with no cloud credentials |
| Dependency hygiene | SCA scanning, lockfiles, private package index, SBOM (extend to an ML-BOM covering models and datasets) |
| Workload identity | Managed identities with minimal scope; no long-lived keys in notebooks |
| Defender coverage | Defender for Cloud / container scanning on training and serving images |

---

### T6: LLM Prompt Injection and Jailbreak

**ATLAS:** AML.T0051 LLM Prompt Injection (direct and indirect), AML.T0054 LLM Jailbreak

**How it works:** attacker-controlled text (user prompt, retrieved document, email, web page) overrides system instructions or triggers tool calls. Indirect injection through RAG content is the dangerous variant because the victim never types the payload.

**Impact:** data exfiltration through tool/connector abuse, unauthorized actions by agents, policy bypass, reputational damage.

**Mitigations:** treat all retrieved content as untrusted data; least-privilege tool permissions with human approval for state-changing actions; output filtering and egress controls (block markdown-image/URL exfil channels); separate system and data channels; prompt-injection classifiers as one layer only (they are bypassable); log full prompt/tool-call traces to SIEM; adversarial testing with Garak/PyRIT.

---

### T7: Denial of ML Service and Cost Harvesting

**ATLAS:** AML.T0029 Denial of ML Service, AML.T0034 Cost Harvesting

**How it works:** resource-exhausting inputs (sponge examples, maximum-length prompts) or sheer volume drive latency and cloud spend.

**Mitigations:** input size and token caps, per-principal budgets, autoscaling ceilings with spend alerts, timeout enforcement, request queue isolation between tenants and workloads.

---

## 4. Cross-Cutting Control Matrix

| Control | T1 | T2 | T3 | T4 | T5 | T6 | T7 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Least-privilege IAM / RBAC | X | X | | | X | X | |
| API gateway auth, rate limits, quotas | | X | X | X | | X | X |
| Output minimization | | X | X | X | | | |
| Data/model provenance and signing | X | | | | X | | |
| Adversarial training and red teaming | X | | X | | | X | |
| Differential privacy | X | | | X | | | |
| SIEM telemetry and anomaly alerts | X | X | X | X | X | X | X |
| Sandboxed model loading | | | | | X | | |
| Human-in-the-loop for high-risk actions | | | X | | | X | |

---

## 5. Monitoring and Response Hooks

- **Telemetry to collect:** per-principal query counts and payload diversity, confidence distributions, drift metrics, dataset version diffs, registry promotion events, model load events, LLM prompt/tool-call traces.
- **Detection owners:** SOC owns query-abuse and identity alerts; ML platform team owns drift, data lineage, and release gates.
- **Playbook triggers:** suspected poisoning means freeze retraining, roll back to last signed model and dataset version, diff datasets, re-run backdoor scans. Suspected extraction means revoke keys, tighten output, review logs for the full query set, assess downstream adversarial-example risk.

---

## 6. Framework Alignment

| Framework | Relevance |
|---|---|
| MITRE ATLAS | Primary threat taxonomy used above |
| NIST AI RMF 1.0 | Map, Measure, Manage functions for risk governance |
| NIST AI 100-2 | Adversarial ML taxonomy and terminology |
| OWASP ML Top 10 / LLM Top 10 | Developer-facing risk lists (poisoning, supply chain, prompt injection) |
| ISO/IEC 27001 / 42001 | Control environment and AI management system |
| MITRE ATT&CK | Detection engineering for the surrounding infrastructure |

---

## 7. Residual Risk and Open Items

- Backdoor detection is probabilistic. No scan gives a clean bill of health, so provenance controls matter more than detection.
- Output minimization trades off against consumer utility; each exposure of scores needs a documented business justification.
- Adversarial robustness and clean accuracy trade off; acceptable thresholds must be set per model by risk owner.
- Indirect prompt injection has no complete technical fix today; architecture (least privilege, human approval) is the control.
- Next iteration: map each threat to concrete detections in Sentinel and add test evidence (ART runs, ModelScan output) to this folder.
