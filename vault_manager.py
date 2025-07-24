"""
Vault Manager - Immutable storage and retrieval system
Handles vault operations, immutable registration, and drift surveillance.
"""

import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import threading

from certnode_config import CertNodeConfig, CertNodeLogger
from ics_generator import ICSSignature

@dataclass
class VaultEntry:
    """Single vault entry record."""
    vault_anchor: str
    cert_id: str
    ics_hash: str
    content_hash: str
    timestamp: str
    cert_type: str
    author_signature: Optional[str]
    metadata: Dict[str, Any]

class VaultManager:
    """
    Immutable vault storage and drift surveillance system.
    Provides permanent storage and verification for all certifications.
    """

    def __init__(self):
        self.logger = CertNodeLogger("Vault")
        self.config = CertNodeConfig()
        self.db_path = self.config.VAULT_DIR / "certnode_vault.db"
        self.lock = threading.RLock()
        
        # Initialize database
        self._initialize_database()
        
        self.logger.info("Vault manager initialized", {
            "vault_path": str(self.config.VAULT_DIR),
            "db_path": str(self.db_path)
        })

    def _initialize_database(self) -> None:
        """Initialize SQLite database for vault storage."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vault_entries (
                    vault_anchor TEXT PRIMARY KEY,
                    cert_id TEXT UNIQUE NOT NULL,
                    ics_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    cert_type TEXT NOT NULL,
                    author_signature TEXT,
                    metadata TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS drift_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_id TEXT NOT NULL,
                    original_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    drift_detected REAL NOT NULL,
                    drift_severity REAL NOT NULL,
                    alert_type TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT FALSE
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vault_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            ''')
            
            # Initialize metadata
            self._set_vault_metadata("genesis_hash", self.config.get_genesis_hash())
            self._set_vault_metadata("vault_version", "1.0.0")
            self._set_vault_metadata("operator", self.config.OPERATOR)
            
            conn.commit()

    def store_certification(self, signature: ICSSignature) -> bool:
        """Store certification in immutable vault."""
        with self.lock:
            try:
                entry = VaultEntry(
                    vault_anchor=signature.fingerprint.combined_hash,
                    cert_id=signature.cert_id,
                    ics_hash=signature.fingerprint.combined_hash,
                    content_hash=signature.fingerprint.content_hash,
                    timestamp=signature.timestamp,
                    cert_type=signature.cert_type,
                    author_signature=signature.author_signature,
                    metadata=signature.metadata
                )
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO vault_entries 
                        (vault_anchor, cert_id, ics_hash, content_hash, timestamp, 
                         cert_type, author_signature, metadata, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        entry.vault_anchor,
                        entry.cert_id,
                        entry.ics_hash,
                        entry.content_hash,
                        entry.timestamp,
                        entry.cert_type,
                        entry.author_signature,
                        json.dumps(entry.metadata),
                        datetime.now(timezone.utc).timestamp()
                    ))
                    conn.commit()
                
                self.logger.info("Certification stored in vault", {
                    "cert_id": entry.cert_id,
                    "vault_anchor": entry.vault_anchor
                })
                
                return True
                
            except sqlite3.IntegrityError as e:
                self.logger.warning("Duplicate certification attempt", {
                    "cert_id": signature.cert_id,
                    "error": str(e)
                })
                return False
            except Exception as e:
                self.logger.error("Vault storage failed", {
                    "cert_id": signature.cert_id,
                    "error": str(e)
                })
                return False

    def retrieve_certification(self, cert_id: str) -> Optional[VaultEntry]:
        """Retrieve certification from vault."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute('''
                        SELECT vault_anchor, cert_id, ics_hash, content_hash, 
                               timestamp, cert_type, author_signature, metadata
                        FROM vault_entries 
                        WHERE cert_id = ?
                    ''', (cert_id,))
                    
                    row = cursor.fetchone()
                    if row:
                        return VaultEntry(
                            vault_anchor=row[0],
                            cert_id=row[1],
                            ics_hash=row[2],
                            content_hash=row[3],
                            timestamp=row[4],
                            cert_type=row[5],
                            author_signature=row[6],
                            metadata=json.loads(row[7])
                        )
                    
                    return None
                    
            except Exception as e:
                self.logger.error("Vault retrieval failed", {
                    "cert_id": cert_id,
                    "error": str(e)
                })
                return None

    def verify_certification(self, cert_id: str, content_hash: str) -> bool:
        """Verify certification against vault."""
        entry = self.retrieve_certification(cert_id)
        if not entry:
            return False
        
        return entry.content_hash == content_hash

    def detect_drift(self, cert_id: str, current_content: str) -> Dict[str, Any]:
        """Detect content drift from original certification."""
        entry = self.retrieve_certification(cert_id)
        if not entry:
            return {"error": "Certification not found"}
        
        # Calculate current content hash
        current_hash = hashlib.sha256(current_content.encode('utf-8')).hexdigest()
        
        # Check for drift
        drift_detected = current_hash != entry.content_hash
        
        if drift_detected:
            # Calculate drift severity (simplified)
            drift_severity = self._calculate_drift_severity(entry.content_hash, current_hash)
            
            # Store drift alert
            self._store_drift_alert(cert_id, entry.content_hash, current_hash, drift_severity)
            
            return {
                "drift_detected": True,
                "original_hash": entry.content_hash,
                "current_hash": current_hash,
                "drift_severity": drift_severity,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        return {"drift_detected": False}

    def list_certifications(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List certifications in vault."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute('''
                        SELECT cert_id, timestamp, cert_type, created_at
                        FROM vault_entries 
                        ORDER BY created_at DESC
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                    
                    return [
                        {
                            "cert_id": row[0],
                            "timestamp": row[1],
                            "cert_type": row[2],
                            "created_at": row[3]
                        }
                        for row in cursor.fetchall()
                    ]
                    
            except Exception as e:
                self.logger.error("Failed to list certifications", {"error": str(e)})
                return []

    def get_certification_count(self) -> int:
        """Get total number of certifications in vault."""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute('SELECT COUNT(*) FROM vault_entries')
                    return cursor.fetchone()[0]
            except Exception:
                return 0

    def is_available(self) -> bool:
        """Check if vault is available."""
        try:
            return self.db_path.exists()
        except Exception:
            return False

    def _calculate_drift_severity(self, original_hash: str, current_hash: str) -> float:
        """Calculate drift severity (0.0 to 1.0)."""
        # Simple Hamming distance calculation
        if len(original_hash) != len(current_hash):
            return 1.0
        
        differences = sum(c1 != c2 for c1, c2 in zip(original_hash, current_hash))
        return min(differences / len(original_hash), 1.0)

    def _store_drift_alert(self, cert_id: str, original_hash: str, current_hash: str, severity: float):
        """Store drift alert in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO drift_alerts 
                    (cert_id, original_hash, current_hash, drift_detected, drift_severity, alert_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    cert_id,
                    original_hash,
                    current_hash,
                    datetime.now(timezone.utc).timestamp(),
                    severity,
                    "CONTENT_DRIFT"
                ))
                conn.commit()
        except Exception as e:
            self.logger.error("Failed to store drift alert", {"error": str(e)})

    def _set_vault_metadata(self, key: str, value: str):
        """Set vault metadata."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO vault_metadata (key, value, updated_at)
                    VALUES (?, ?, ?)
                ''', (key, value, datetime.now(timezone.utc).timestamp()))
                conn.commit()
        except Exception as e:
            self.logger.error("Failed to set vault metadata", {"error": str(e)})

