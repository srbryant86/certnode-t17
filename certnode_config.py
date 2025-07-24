"""
CertNode Configuration and Core Constants
Production-grade configuration management for the CertNode certification system.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib

class CertNodeConfig:
    """Core configuration for CertNode certification system."""

    # System Versions (Genesis Locked)
    FRAME_VERSION = "v3.0.1"
    STRIDE_VERSION = "L1↑.3"
    CDP_VERSION = "v1.0.3"
    SECL_VERSION = "v1.0"
    LCL_VERSION = "v1.1"
    CERTNODE_VERSION = "T17+ v2.0.0"

    # Operator Information
    OPERATOR = "SRB Creative Holdings LLC"
    SYSTEM_NAME = "CertNode T17+ Logic Governance Infrastructure"
    PROTOCOL_NAME = "CDP"

    # Certification Classes
    CERT_TYPES = {
        "CORE_AUTHORSHIP": "Core Authorship Cert",
        "LOGIC_FRAGMENT": "Logic Fragment Cert", 
        "DERIVATIVE": "Derivative Cert"
    }

    # Slope Classifications (Internal)
    SLOPE_TYPES = {
        "INSTRUCTIONAL": "instructional",
        "RECURSIVE": "recursive",
        "DIAGNOSTIC": "diagnostic", 
        "COMPARATIVE": "comparative",
        "THEORETICAL": "theoretical",
        "PERSUASIVE": "persuasive"
    }

    # Anchor Classifications (Internal)
    ANCHOR_TYPES = {
        "PRIMARY_SOURCE": "primary_source",
        "SYNTHETIC_RATIONALE": "synthetic_rationale", 
        "CROSS_SOURCED_LOGIC": "cross_sourced_logic",
        "CONTEXTUAL_RECALL": "contextual_recall"
    }

    # Convergence Patterns (Internal)
    CONVERGENCE_PATTERNS = {
        "TAPERED_LINEARITY": "tapered_linearity",
        "NESTED_GLIDE": "nested_glide",
        "SPIRAL_DESCENT": "spiral_descent",
        "ANCHOR_LOCK_CHAIN": "anchor_lock_chain"
    }

    # File Paths
    BASE_DIR = Path.cwd()
    VAULT_DIR = BASE_DIR / "vault"
    CERTS_DIR = BASE_DIR / "certified_outputs"
    LOGS_DIR = BASE_DIR / "logs"
    BADGES_DIR = BASE_DIR / "trust_badges"

    # Validation Thresholds
    MIN_PARAGRAPH_MASS = 50  # Minimum words per paragraph
    MAX_DRIFT_THRESHOLD = 0.15  # Maximum structural drift allowed
    OVERLAP_SIMILARITY_THRESHOLD = 0.85  # CCOD threshold
    CERTIFICATION_THRESHOLD = 0.7  # Minimum score for certification

    # API Settings
    DEFAULT_MAX_TOKENS = 1000
    HASH_ALGORITHM = "sha256"

    @classmethod
    def ensure_directories(cls) -> None:
        """Ensure all required directories exist."""
        for directory in [cls.VAULT_DIR, cls.CERTS_DIR, cls.LOGS_DIR, cls.BADGES_DIR]:
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_genesis_hash(cls) -> str:
        """Generate genesis hash for system state."""
        system_state = {
            "versions": {
                "frame": cls.FRAME_VERSION,
                "stride": cls.STRIDE_VERSION, 
                "cdp": cls.CDP_VERSION,
                "secl": cls.SECL_VERSION,
                "lcl": cls.LCL_VERSION,
                "certnode": cls.CERTNODE_VERSION
            },
            "operator": cls.OPERATOR,
            "timestamp": datetime.utcnow().isoformat(),
            "slope_types": list(cls.SLOPE_TYPES.keys()),
            "anchor_types": list(cls.ANCHOR_TYPES.keys())
        }
        
        state_json = json.dumps(system_state, sort_keys=True)
        return hashlib.sha256(state_json.encode()).hexdigest()

    @classmethod
    def load_config(cls, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file if exists."""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}

    @classmethod 
    def save_config(cls, config: Dict[str, Any], config_path: str) -> None:
        """Save configuration to file."""
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

class CertNodeLogger:
    """Production-grade logging for CertNode operations."""

    def __init__(self, component: str):
        self.component = component
        self.log_file = CertNodeConfig.LOGS_DIR / f"{component}.log"
        CertNodeConfig.ensure_directories()

    def log(self, level: str, message: str, metadata: Optional[Dict] = None) -> None:
        """Log message with timestamp and metadata."""
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "component": self.component,
            "level": level,
            "message": message,
            "metadata": metadata or {}
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

    def info(self, message: str, metadata: Optional[Dict] = None) -> None:
        self.log("INFO", message, metadata)

    def warning(self, message: str, metadata: Optional[Dict] = None) -> None:
        self.log("WARNING", message, metadata)

    def error(self, message: str, metadata: Optional[Dict] = None) -> None:
        self.log("ERROR", message, metadata)

    def debug(self, message: str, metadata: Optional[Dict] = None) -> None:
        self.log("DEBUG", message, metadata)

