#!/usr/bin/env python3
"""
ML-based threat scoring.
Loads trained ONNX or Pickle model from models/ directory.
Falls back to rule-based heuristic scoring if no model is found.
"""
import json
from pathlib import Path
from typing import List, Dict, Any

MODEL_DIR = Path(__file__).parent

# Severity thresholds for rule-based fallback
RULE_SCORES = {
    "SSH_BRUTE_FORCE":    {"severity": "CRITICAL", "score": 0.95},
    "MALICIOUS_PROCESS":  {"severity": "CRITICAL", "score": 0.92},
    "OPEN_PORT":          {"severity": "HIGH",     "score": 0.75},
    "WORLD_WRITABLE_FILE":{"severity": "HIGH",     "score": 0.70},
    "SUID_BINARY":        {"severity": "HIGH",     "score": 0.68},
    "UNPATCHED_CVE":      {"severity": "HIGH",     "score": 0.80},
    "CIS_DRIFT":          {"severity": "MEDIUM",   "score": 0.55},
    "ANOMALOUS_TRAFFIC":  {"severity": "MEDIUM",   "score": 0.60},
}

def _load_onnx_model():
    try:
        import onnxruntime as rt
        candidates = list(MODEL_DIR.glob("*.onnx"))
        if candidates:
            return rt.InferenceSession(str(candidates[0]))
    except ImportError:
        pass
    return None

def _load_pickle_model():
    try:
        import pickle
        candidates = list(MODEL_DIR.glob("*.pkl"))
        if candidates:
            with open(candidates[0], "rb") as f:
                return pickle.load(f)
    except Exception:
        pass
    return None

def score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Score a list of raw findings dicts.
    Adds 'severity' and 'ml_score' keys to each finding.
    """
    # Try ML model first
    onnx_model   = _load_onnx_model()
    pickle_model = _load_pickle_model()

    scored = []
    for f in findings:
        ftype = f.get("type", "UNKNOWN")

        # ML scoring (if model available and finding has numeric features)
        if onnx_model and "features" in f:
            import numpy as np
            features = np.array([f["features"]], dtype=np.float32)
            iname = onnx_model.get_inputs()[0].name
            result = onnx_model.run(None, {iname: features})
            ml_score = float(result[0][0])
            severity = _score_to_severity(ml_score)
        elif pickle_model and "features" in f:
            import numpy as np
            ml_score = float(pickle_model.predict_proba([f["features"]])[0][1])
            severity = _score_to_severity(ml_score)
        else:
            # Fallback: rule-based
            rule = RULE_SCORES.get(ftype, {"severity": "LOW", "score": 0.20})
            ml_score = rule["score"]
            severity = rule["severity"]

        scored.append({**f, "ml_score": ml_score, "severity": severity})

    return scored

def _score_to_severity(score: float) -> str:
    if score >= 0.90: return "CRITICAL"
    if score >= 0.70: return "HIGH"
    if score >= 0.45: return "MEDIUM"
    return "LOW"
