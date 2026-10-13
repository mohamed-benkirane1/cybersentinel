# CyberSentinel Limitations

## 1. Scope

CyberSentinel is an academic Blue Team prototype for authentication anomaly analysis. It demonstrates a complete local pipeline from validated events to explainable assessments, but its scope is intentionally narrow and its output requires human interpretation.

## 2. Synthetic Data

All bundled traffic is synthetic. The normal generator, failure bursts, and multi-account scenarios are deterministic simplifications designed for reproducible software testing and controlled experiments.

Synthetic distributions do not capture the diversity, seasonality, organizational context, identity lifecycle, network topology, or data-quality problems found in real authentication telemetry. No real personal authentication data is included.

## 3. Detection Coverage

Only two deterministic patterns are implemented:

- R001: five or more failed attempts for one user within five minutes;
- R002: four or more distinct users from one source IP within five minutes.

These heuristics do not cover the broader set of behaviors investigated by a SOC. A rule match indicates that its explicit threshold was reached, not why it was reached and not whether the activity is malicious.

## 4. Feature Coverage

The model and rules use only four temporal count features:

- `attempts_5m`;
- `failed_attempts_5m`;
- `unique_users_per_ip_5m`;
- `unique_ips_per_user_30m`.

The MVP does not model device identity, geography, user baselines, service sensitivity, session context, threat intelligence, business schedules, or longer-term behavioral history.

## 5. Machine Learning Limitations

Isolation Forest is an unsupervised baseline trained on synthetic normal authentication behavior. Its output indicates relative statistical atypicality under that fitted model.

The anomaly score is `-decision_function`. It is not calibrated, is not a probability, and is not an estimate of attack likelihood. Model behavior depends on the training distribution and selected features. Distribution shift and unseen legitimate behavior may increase false positives or false negatives.

## 6. Evaluation Limitations

The audited synthetic experiment contains 110 samples: 100 synthetic normal samples and 10 samples from injected suspicious scenarios. It produced:

- 45 predicted anomalies;
- TP = 10;
- FP = 35;
- TN = 65;
- FN = 0;
- precision = 0.2222;
- recall = 1.0;
- F1 = 0.3636.

The false-positive count is high. Perfect recall in this controlled experiment must not be generalized: the scenarios and training data come from known synthetic generators and do not represent production traffic or real incident prevalence.

## 7. Risk Score Limitations

The risk score is a bounded heuristic priority score:

- R001 contributes 40;
- R002 contributes 40;
- an ML anomaly contributes 20;
- the maximum is 100.

The score helps order review attention. It is not derived from incident probability, expected loss, calibrated severity, or empirical attack likelihood. The magnitude of the Isolation Forest score does not change the risk contribution.

## 8. Confidence Limitations

Confidence represents agreement between signal families:

- no signal: low;
- rules only: medium;
- ML only: medium;
- rules and ML: high.

It is not statistical confidence, a confidence interval, or a calibrated probability. High confidence means deterministic and statistical signals agree, not that malicious activity has been proven.

## 9. Operational Limitations

- The default runtime is oriented toward localhost demonstrations.
- The fitted model exists only in process memory.
- Events and assessments are not persisted.
- There is no distributed processing, queue, scheduler, or high-availability design.
- There is no built-in model registry, retraining schedule, drift monitoring, or production observability stack.
- The launcher manages one local API process and one local dashboard process.

## 10. Security Limitations

The MVP does not provide authentication, authorization, TLS termination, rate limiting, tenant isolation, audit-log persistence, or hardened deployment configuration. It should not be exposed directly to an untrusted network.

The repository contains no offensive capability, exploitation functionality, credential collection, or real personal authentication data.

## 11. What CyberSentinel Does Not Claim

CyberSentinel does **not** claim to:

- confirm cyberattacks;
- identify malicious users with certainty;
- estimate attack probability;
- provide calibrated statistical confidence;
- replace SOC analysts;
- provide production-grade detection.

Its purpose is academic learning and transparent exploration of defensive anomaly detection and analyst prioritization using synthetic data.
