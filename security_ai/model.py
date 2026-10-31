import os
import json
import numpy as np
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest

from .config import (
    MODEL_DIR,
    ISOLATION_FOREST_N_ESTIMATORS,
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_RANDOM_STATE,
)
from .features import FEATURE_NAMES

MODEL_FILENAME = "isolation_forest.joblib"
METADATA_FILENAME = "model_metadata.json"


class IsolationForestManager:
    _instance = None
    _model = None
    _metadata = None
    _last_load_mtime = 0

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def model_path(self):
        return os.path.join(MODEL_DIR, MODEL_FILENAME)

    @property
    def metadata_path(self):
        return os.path.join(MODEL_DIR, METADATA_FILENAME)

    def load_model(self, force_reload=False):
        """
        Loads the persisted Isolation Forest model and its metadata.
        Caches in memory and reloads if file modification time changes.
        """
        if not os.path.exists(self.model_path):
            self._model = None
            self._metadata = None
            return None, None

        mtime = os.path.getmtime(self.model_path)
        if not force_reload and self._model is not None and mtime == self._last_load_mtime:
            return self._model, self._metadata

        try:
            self._model = joblib.load(self.model_path)
            self._last_load_mtime = mtime
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = {"version": "1.0", "trained_at": "unknown"}
            return self._model, self._metadata
        except Exception as e:
            print(f"[SecurityAI] Error loading Isolation Forest model: {e}")
            self._model = None
            self._metadata = None
            return None, None

    def predict_anomaly(self, feature_vector):
        """
        Computes anomaly score for a given feature vector using Isolation Forest.
        
        Returns:
            dict: {
                "anomaly_score": float (0.0 to 1.0, higher = more anomalous),
                "is_outlier": bool,
                "model_available": bool,
                "version": str
            }
        """
        model, metadata = self.load_model()
        if model is None:
            return {
                "anomaly_score": 0.0,
                "is_outlier": False,
                "model_available": False,
                "version": "none",
            }

        X = np.array([feature_vector], dtype=float)

        try:
            # decision_function: < 0 is anomaly, > 0 is inlier
            dec = float(model.decision_function(X)[0])
            pred = int(model.predict(X)[0])  # -1 = anomaly, +1 = normal

            # Map decision function (-0.5 to +0.5 typical) to calibrated 0.0 - 1.0 anomaly scale
            # dec <= -0.2 -> ~0.8 to 1.0 (very anomalous)
            # dec == 0.0  -> 0.5 (boundary)
            # dec >= +0.2 -> 0.0 to 0.2 (very normal)
            calibrated_score = 0.5 - (dec * 1.5)
            calibrated_score = max(0.0, min(1.0, calibrated_score))

            is_outlier = (pred == -1)

            return {
                "anomaly_score": round(float(calibrated_score), 4),
                "is_outlier": is_outlier,
                "model_available": True,
                "version": metadata.get("version", "1.0") if metadata else "1.0",
                "raw_decision": round(dec, 4),
            }
        except Exception as e:
            print(f"[SecurityAI] Error predicting anomaly: {e}")
            return {
                "anomaly_score": 0.0,
                "is_outlier": False,
                "model_available": False,
                "version": "error",
            }

    
def train(self, X_train, contamination=None, version="1.0"):
    """
    Train Isolation Forest after validating the feature matrix.
    Saves the model and its metadata to disk.
    """
    if contamination is None:
        contamination = ISOLATION_FOREST_CONTAMINATION

    if not 0.0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and at most 0.5.")

    X = np.asarray(X_train, dtype=float)

    if X.ndim != 2:
        raise ValueError("Training data must be a 2D feature matrix.")

    if X.shape[0] < 2:
        raise ValueError("At least 2 training samples are required.")

    if X.shape[1] != len(FEATURE_NAMES):
        raise ValueError(
            f"Expected {len(FEATURE_NAMES)} features per sample; "
            f"received {X.shape[1]}."
        )

    if not np.isfinite(X).all():
        raise ValueError("Training data contains NaN or infinite values.")

    os.makedirs(MODEL_DIR, exist_ok=True)

    model = IsolationForest(
        n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
        contamination=contamination,
        random_state=ISOLATION_FOREST_RANDOM_STATE,
    )

    model.fit(X)

    train_preds = model.predict(X)
    anomaly_count = int(np.sum(train_preds == -1))

    metadata = {
        "version": version,
        "trained_at": datetime.now().isoformat(),
        "sample_count": int(X.shape[0]),
        "feature_count": int(X.shape[1]),
        "feature_names": FEATURE_NAMES,
        "contamination": float(contamination),
        "n_estimators": int(ISOLATION_FOREST_N_ESTIMATORS),
        "random_state": int(ISOLATION_FOREST_RANDOM_STATE),
        "train_anomalies_detected": anomaly_count,
    }

    # Persist the model and metadata only after fitting succeeds.
    joblib.dump(model, self.model_path)

    with open(self.metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    self.load_model(force_reload=True)
    return metadata


model_manager = IsolationForestManager.get_instance()
