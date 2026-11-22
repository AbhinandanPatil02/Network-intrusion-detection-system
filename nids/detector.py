"""Hybrid detection engine.

* **Signature-style classification** — a Random Forest trained on CIC-IDS2017
  flow features predicts one of eight classes (Benign + 7 attack families).
* **Anomaly detection** — a dense autoencoder trained on benign traffic. The
  reconstruction error of each flow is compared with an *adaptive baseline*
  learned online from flows the classifier considers benign, so the threshold
  self-calibrates to the network it is deployed on.
* **Explainability** — a LIME-style local surrogate (weighted ridge regression
  over perturbed samples) shows which features drove a verdict.

The autoencoder is evaluated in pure NumPy straight from the Keras HDF5 file,
so TensorFlow is not required at runtime.
"""
from __future__ import annotations

import json
import logging
import pickle
import threading
import warnings
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .features import FEATURE_KEYS, FEATURE_LABELS, N_FEATURES

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def risk_to_severity(risk: float) -> str:
    if risk >= 85:
        return "critical"
    if risk >= 65:
        return "high"
    if risk >= 40:
        return "medium"
    if risk >= 20:
        return "low"
    return "info"


class NumpyAutoencoder:
    """Minimal forward pass for a Keras Sequential stack of Dense layers."""

    _ACT = {
        "elu": lambda x: np.where(x > 0, x, np.expm1(np.minimum(x, 0))),
        "relu": lambda x: np.maximum(x, 0),
        "sigmoid": lambda x: 1.0 / (1.0 + np.exp(-x)),
        "tanh": np.tanh,
        "linear": lambda x: x,
        None: lambda x: x,
    }

    def __init__(self, path: Path):
        import h5py

        self.layers: list[tuple[np.ndarray, np.ndarray, str]] = []
        with h5py.File(path, "r") as f:
            cfg = json.loads(f.attrs["model_config"])
            weights = f["model_weights"]
            for layer in cfg["config"]["layers"]:
                if layer["class_name"] != "Dense":
                    continue
                name = layer["config"]["name"]
                grp = weights[name][name]
                kernel = np.asarray(grp["kernel:0"], dtype=np.float64)
                bias = np.asarray(grp["bias:0"], dtype=np.float64)
                act = layer["config"].get("activation", "linear")
                if act not in self._ACT:
                    raise ValueError(f"Unsupported activation {act!r}")
                self.layers.append((kernel, bias, act))
        if not self.layers:
            raise ValueError("No Dense layers found in autoencoder file")

    def predict(self, x: np.ndarray) -> np.ndarray:
        out = np.asarray(x, dtype=np.float64)
        for kernel, bias, act in self.layers:
            out = self._ACT[act](out @ kernel + bias)
        return out


@dataclass
class Verdict:
    label: str
    confidence: float
    attack_prob: float
    probs: dict
    anomaly_error: float
    anomaly_score: float  # error / adaptive threshold (>1 == anomalous)
    is_anomaly: bool
    risk: float           # 0..100
    severity: str
    verdict: str          # benign | suspicious | malicious


class Detector:
    def __init__(self, models_dir: Path, cfg):
        self.cfg = cfg
        self._lock = threading.Lock()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import joblib

            with open(models_dir / "model.pkl", "rb") as f:
                self.classifier = pickle.load(f)
            self.ae_pipeline = joblib.load(models_dir / "preprocess_pipeline_AE_39ft.save")
            try:
                with open(models_dir / "scaler.pkl", "rb") as f:
                    self.range_scaler = pickle.load(f)
            except Exception:  # optional
                self.range_scaler = None

        self.autoencoder = NumpyAutoencoder(models_dir / "autoencoder_39ft.hdf5")
        self.classes = [str(c) for c in self.classifier.classes_]
        self.benign_idx = self.classes.index("Benign") if "Benign" in self.classes else 0
        n_in = getattr(self.classifier, "n_features_in_", N_FEATURES)
        if n_in != N_FEATURES:
            raise ValueError(f"Classifier expects {n_in} features, extractor produces {N_FEATURES}")

        importances = getattr(self.classifier, "feature_importances_", None)
        self.global_importance = (
            sorted(
                ({"feature": FEATURE_LABELS[i], "key": FEATURE_KEYS[i], "importance": float(v)}
                 for i, v in enumerate(importances)),
                key=lambda d: -d["importance"],
            ) if importances is not None else []
        )

        # Online state for adaptive anomaly baseline + explanation background.
        self._benign_errors: deque[float] = deque(maxlen=5000)
        self._background: deque[np.ndarray] = deque(maxlen=2000)
        self._threshold_cache: tuple[int, float] | None = None
        log.info("Detector ready: %d classes %s, AE with %d layers",
                 len(self.classes), self.classes, len(self.autoencoder.layers))

    # ------------------------------------------------------------------ utils
    @staticmethod
    def sanitize(features) -> np.ndarray:
        x = np.asarray(features[:N_FEATURES], dtype=np.float64)
        x[~np.isfinite(x)] = 0.0
        return x

    def _predict_proba(self, X: np.ndarray) -> np.ndarray:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return self.classifier.predict_proba(X).astype(float)

    def reconstruction(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            xt = self.ae_pipeline.transform(x.reshape(1, -1))
        # The shipped MinMax step was fit on a very narrow range, so raw outputs can reach
        # ~1e9. Clip to the autoencoder's training domain [0, 1] so errors stay bounded and
        # comparable; the adaptive baseline then calibrates the threshold on live traffic.
        xt = np.clip(xt, 0.0, 1.0)
        return xt[0], self.autoencoder.predict(xt)[0]

    def anomaly_threshold(self) -> float | None:
        n = len(self._benign_errors)
        if n < self.cfg.anomaly_warmup:
            return None
        if self._threshold_cache and abs(self._threshold_cache[0] - n) < 25 and n < 5000:
            return self._threshold_cache[1]
        thr = float(np.percentile(np.fromiter(self._benign_errors, float), self.cfg.anomaly_percentile))
        thr = max(thr, 1e-6)
        self._threshold_cache = (n, thr)
        return thr

    def baseline_status(self) -> dict:
        thr = self.anomaly_threshold()
        return {
            "samples": len(self._benign_errors),
            "warmup": self.cfg.anomaly_warmup,
            "calibrated": thr is not None,
            "threshold": thr,
        }

    # -------------------------------------------------------------- inference
    def analyze(self, features, learn: bool = True) -> tuple[np.ndarray, Verdict]:
        """Classify a flow. ``learn`` controls whether it may update the adaptive baseline."""
        x = self.sanitize(features)
        proba = self._predict_proba(x.reshape(1, -1))[0]
        idx = int(np.argmax(proba))
        label = self.classes[idx]
        confidence = float(proba[idx])
        attack_prob = float(1.0 - proba[self.benign_idx])

        xt, rec = self.reconstruction(x)
        err = float(np.mean((rec - xt) ** 2))

        with self._lock:
            thr = self.anomaly_threshold()
            if learn and label == "Benign" and confidence >= 0.9:
                self._benign_errors.append(err)
            if learn:
                self._background.append(x)

        anomaly_score = err / thr if thr else 0.0
        is_anomaly = bool(thr and anomaly_score > 1.0)

        # Risk 0..100: classifier attack probability is the primary signal; the
        # anomaly score can raise (never lower) risk for flows the RF thinks benign.
        risk = attack_prob * 100.0
        if is_anomaly:
            risk = max(risk, min(70.0, 30.0 + 10.0 * np.log2(anomaly_score)))
        risk = float(round(min(100.0, risk), 1))

        if label != "Benign" and confidence >= self.cfg.alert_min_confidence:
            verdict = "malicious"
        elif label != "Benign" or is_anomaly or attack_prob >= 0.3:
            verdict = "suspicious"
        else:
            verdict = "benign"

        return x, Verdict(
            label=label,
            confidence=round(confidence, 4),
            attack_prob=round(attack_prob, 4),
            probs={c: round(float(p), 4) for c, p in zip(self.classes, proba)},
            anomaly_error=err,
            anomaly_score=round(float(anomaly_score), 3),
            is_anomaly=is_anomaly,
            risk=risk,
            severity=risk_to_severity(risk),
            verdict=verdict,
        )

    # ---------------------------------------------------------- explanations
    def _feature_scale(self) -> np.ndarray:
        with self._lock:
            bg = np.array(self._background) if len(self._background) >= 50 else None
        if bg is not None:
            std = bg.std(axis=0)
        elif self.range_scaler is not None:
            std = (self.range_scaler.data_max_ - self.range_scaler.data_min_) / 50.0
        else:
            std = np.ones(N_FEATURES)
        return np.where(std > 1e-9, std, 1.0)

    def explain(self, features, num_samples: int = 600, top_k: int = 10, seed: int = 7) -> dict:
        """LIME-style local surrogate explanation for the predicted class."""
        x = self.sanitize(features)
        proba = self._predict_proba(x.reshape(1, -1))[0]
        target = int(np.argmax(proba))
        scale = self._feature_scale()

        rng = np.random.default_rng(seed)
        Z = rng.normal(0.0, 1.0, size=(num_samples, N_FEATURES))
        Z[0] = 0.0
        samples = np.maximum(x + Z * scale, 0.0)  # all flow features are non-negative (bar 2)
        y = self._predict_proba(samples)[:, target]

        # Exponential kernel on standardized Euclidean distance (LIME default width).
        Xs = (samples - x) / scale
        dist = np.linalg.norm(Xs, axis=1)
        width = 0.75 * np.sqrt(N_FEATURES)
        w = np.sqrt(np.exp(-(dist ** 2) / width ** 2))

        Xd = np.hstack([np.ones((num_samples, 1)), Xs])
        W = w[:, None]
        lam = 1.0
        A = (Xd * W).T @ (Xd * W) + lam * np.eye(N_FEATURES + 1)
        A[0, 0] -= lam  # don't regularise intercept
        b = (Xd * W).T @ (y * w)
        coef = np.linalg.solve(A, b)[1:]

        order = np.argsort(-np.abs(coef))[:top_k]
        return {
            "target_class": self.classes[target],
            "target_probability": round(float(proba[target]), 4),
            "contributions": [
                {
                    "feature": FEATURE_LABELS[i],
                    "key": FEATURE_KEYS[i],
                    "value": float(x[i]),
                    "weight": round(float(coef[i]), 5),
                }
                for i in order
            ],
            "method": "Local surrogate (LIME-style weighted ridge, %d perturbations)" % num_samples,
        }

    def reconstruction_report(self, features, top_k: int = 10) -> dict:
        x = self.sanitize(features)
        xt, rec = self.reconstruction(x)
        err = np.abs(rec - xt)
        order = np.argsort(-err)[:top_k]
        thr = self.anomaly_threshold()
        mse = float(np.mean((rec - xt) ** 2))
        return {
            "mse": mse,
            "threshold": thr,
            "score": (mse / thr) if thr else None,
            "top": [{"feature": FEATURE_LABELS[i], "error": round(float(err[i]), 5)} for i in order],
        }
