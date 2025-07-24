"""
ICS (Immutable Content Signature) Generator
Creates cryptographic signatures and hashes for content certification.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from certnode_config import CertNodeConfig, CertNodeLogger

@dataclass
class ContentFingerprint:
    """Cryptographic fingerprint of content and analysis."""
    content_hash: str
    structure_hash: str
    logic_hash: str
    combined_hash: str
    fingerprint_algorithm: str

@dataclass
class CertificationMetadata:
    """Metadata for certification process."""
    cert_id: str
    timestamp: str
    operator: str
    system_version: str
    processing_versions: Dict[str, str]
    content_type: str
    author_signature: Optional[str]

@dataclass
class ICSSignature:
    """Complete ICS signature for certified content."""
    fingerprint: ContentFingerprint
    metadata: CertificationMetadata
    analysis_summary: Dict[str, Any]
    vault_anchor: str
    verification_data: Dict[str, Any]
    
    @property
    def cert_id(self) -> str:
        """Get certificate ID."""
        return self.metadata.cert_id
    
    @property
    def timestamp(self) -> str:
        """Get timestamp."""
        return self.metadata.timestamp
    
    @property
    def cert_type(self) -> str:
        """Get certificate type."""
        return self.metadata.content_type
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

class ICSGenerator:
    """
    ICS generator for creating immutable content signatures.
    Produces cryptographic signatures that prove content authenticity and processing.
    """

    def __init__(self):
        self.logger = CertNodeLogger("ICS")
        self.config = CertNodeConfig()

    def generate_signature(self, 
                          content: str,
                          cdp_result: Any,
                          frame_result: Any,
                          stride_result: Any,
                          cert_type: str = "LOGIC_FRAGMENT",
                          author_id: Optional[str] = None) -> ICSSignature:
        """
        Generate complete ICS signature for certified content.
        
        Args:
            content: Original content text
            cdp_result: CDP analysis result
            frame_result: FRAME analysis result  
            stride_result: STRIDE analysis result
            cert_type: Type of certification
            author_id: Optional author identifier
            
        Returns:
            Complete ICS signature
        """
        self.logger.info("Generating ICS signature", {
            "cert_type": cert_type,
            "author_id": author_id,
            "content_length": len(content)
        })
        
        try:
            # Generate content fingerprint
            fingerprint = self._generate_fingerprint(content, cdp_result, frame_result, stride_result)
            
            # Create certification metadata
            metadata = self._create_metadata(cert_type, author_id)
            
            # Create analysis summary
            analysis_summary = self._create_analysis_summary(cdp_result, frame_result, stride_result)
            
            # Generate vault anchor
            vault_anchor = self._generate_vault_anchor(fingerprint, metadata)
            
            # Create verification data
            verification_data = self._create_verification_data(
                content, fingerprint, metadata, analysis_summary
            )
            
            signature = ICSSignature(
                fingerprint=fingerprint,
                metadata=metadata,
                analysis_summary=analysis_summary,
                vault_anchor=vault_anchor,
                verification_data=verification_data
            )
            
            self.logger.info("ICS signature generated", {
                "cert_id": metadata.cert_id,
                "vault_anchor": vault_anchor,
                "combined_hash": fingerprint.combined_hash
            })
            
            return signature
            
        except Exception as e:
            self.logger.error(f"ICS signature generation failed: {str(e)}")
            raise

    def _generate_fingerprint(self, content: str, 
                            cdp_result: Any,
                            frame_result: Any, 
                            stride_result: Any) -> ContentFingerprint:
        """Generate cryptographic fingerprint of content and analysis."""
        
        # Content hash (raw content)
        content_hash = self._hash_content(content)
        
        # Structure hash (CDP structural analysis)
        structure_data = {
            "overall_slope": cdp_result.overall_slope,
            "structural_integrity": cdp_result.structural_integrity,
            "logic_continuity": cdp_result.logic_continuity,
            "convergence_achieved": cdp_result.convergence_achieved,
            "paragraph_count": len(cdp_result.paragraphs),
            "paragraph_slopes": [p.slope_type for p in cdp_result.paragraphs],
            "paragraph_anchors": [p.anchor_type for p in cdp_result.paragraphs]
        }
        structure_hash = self._hash_data(structure_data)
        
        # Logic hash (FRAME + STRIDE validation)
        logic_data = {
            "boundaries_satisfied": frame_result.boundaries_satisfied,
            "structural_score": frame_result.structural_score,
            "taper_achieved": frame_result.taper_analysis.taper_achieved,
            "slope_resolution": frame_result.slope_resolution,
            "suppression_score": stride_result.suppression_score,
            "tone_neutrality": stride_result.tone_analysis.tone_neutrality,
            "drift_severity": stride_result.drift_detection.drift_severity
        }
        logic_hash = self._hash_data(logic_data)
        
        # Combined hash (all elements)
        combined_data = {
            "content_hash": content_hash,
            "structure_hash": structure_hash,
            "logic_hash": logic_hash,
            "generator_version": self.config.CERTNODE_VERSION,
            "algorithm": self.config.HASH_ALGORITHM
        }
        combined_hash = self._hash_data(combined_data)
        
        return ContentFingerprint(
            content_hash=content_hash,
            structure_hash=structure_hash,
            logic_hash=logic_hash,
            combined_hash=combined_hash,
            fingerprint_algorithm=self.config.HASH_ALGORITHM
        )

    def _create_metadata(self, cert_type: str, author_id: Optional[str]) -> CertificationMetadata:
        """Create certification metadata."""
        cert_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Author signature (hash of author_id if provided)
        author_signature = None
        if author_id:
            author_signature = hashlib.sha256(author_id.encode()).hexdigest()[:16]
        
        return CertificationMetadata(
            cert_id=cert_id,
            timestamp=timestamp,
            operator=self.config.OPERATOR,
            system_version=self.config.CERTNODE_VERSION,
            processing_versions={
                "CDP": self.config.CDP_VERSION,
                "FRAME": self.config.FRAME_VERSION,
                "STRIDE": self.config.STRIDE_VERSION
            },
            content_type=cert_type,
            author_signature=author_signature
        )

    def _create_analysis_summary(self, cdp_result: Any,
                               frame_result: Any,
                               stride_result: Any) -> Dict[str, Any]:
        """Create summary of analysis results."""
        return {
            "cdp_analysis": {
                "overall_slope": cdp_result.overall_slope,
                "structural_integrity": round(cdp_result.structural_integrity, 3),
                "logic_continuity": round(cdp_result.logic_continuity, 3),
                "convergence_achieved": cdp_result.convergence_achieved,
                "total_paragraphs": len(cdp_result.paragraphs)
            },
            "frame_analysis": {
                "boundaries_satisfied": frame_result.boundaries_satisfied,
                "structural_score": round(frame_result.structural_score, 3),
                "taper_achieved": frame_result.taper_analysis.taper_achieved,
                "slope_resolution": frame_result.slope_resolution,
                "violation_count": len(frame_result.boundary_violations)
            },
            "stride_analysis": {
                "suppression_needed": stride_result.suppression_needed,
                "suppression_score": round(stride_result.suppression_score, 3),
                "tone_neutrality": round(stride_result.tone_analysis.tone_neutrality, 3),
                "drift_detected": stride_result.drift_detection.drift_severity > 0.4,
                "drift_severity": round(stride_result.drift_detection.drift_severity, 3)
            }
        }

    def _generate_vault_anchor(self, fingerprint: ContentFingerprint, 
                              metadata: CertificationMetadata) -> str:
        """Generate vault anchor for immutable registration."""
        vault_data = {
            "combined_hash": fingerprint.combined_hash,
            "cert_id": metadata.cert_id,
            "timestamp": metadata.timestamp,
            "operator": metadata.operator,
            "genesis_hash": self.config.get_genesis_hash()
        }
        
        return self._hash_data(vault_data)

    def _create_verification_data(self, content: str,
                                fingerprint: ContentFingerprint,
                                metadata: CertificationMetadata,
                                analysis_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Create data needed for signature verification."""
        return {
            "verification_algorithm": fingerprint.fingerprint_algorithm,
            "content_length": len(content),
            "word_count": len(content.split()),
            "paragraph_count": content.count('\n\n') + 1,
            "cert_type": metadata.content_type,
            "processing_timestamp": metadata.timestamp,
            "verification_url": f"https://certnode.io/verify?hash={fingerprint.combined_hash}",
            "badge_url": f"https://certnode.io/badge?cert={metadata.cert_id}",
            "vault_url": f"https://certnode.io/vault?anchor={self._generate_vault_anchor(fingerprint, metadata)}"
        }

    def _hash_content(self, content: str) -> str:
        """Hash raw content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _hash_data(self, data: Dict[str, Any]) -> str:
        """Hash structured data."""
        data_json = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(data_json.encode('utf-8')).hexdigest()

    def verify_signature(self, content: str, signature: ICSSignature) -> Tuple[bool, List[str]]:
        """
        Verify an ICS signature against content.
        
        Args:
            content: Content to verify
            signature: ICS signature to verify against
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        try:
            # Verify content hash
            content_hash = self._hash_content(content)
            if content_hash != signature.fingerprint.content_hash:
                errors.append("Content hash mismatch - content has been modified")
            
            # Verify combined hash structure
            expected_combined_data = {
                "content_hash": signature.fingerprint.content_hash,
                "structure_hash": signature.fingerprint.structure_hash,
                "logic_hash": signature.fingerprint.logic_hash,
                "generator_version": signature.metadata.system_version,
                "algorithm": signature.fingerprint.fingerprint_algorithm
            }
            expected_combined_hash = self._hash_data(expected_combined_data)
            
            if expected_combined_hash != signature.fingerprint.combined_hash:
                errors.append("Combined hash verification failed - signature integrity compromised")
            
            # Verify vault anchor
            expected_vault_anchor = self._generate_vault_anchor(
                signature.fingerprint, signature.metadata
            )
            if expected_vault_anchor != signature.vault_anchor:
                errors.append("Vault anchor verification failed")
            
            # Verify timestamp format and recency (not too old)
            try:
                cert_time = datetime.fromisoformat(signature.metadata.timestamp.replace('Z', '+00:00'))
                age_days = (datetime.now(timezone.utc) - cert_time).days
                if age_days > 365 * 5:  # 5 years max
                    errors.append("Certificate is too old (> 5 years)")
            except ValueError:
                errors.append("Invalid timestamp format in certificate")
            
            is_valid = len(errors) == 0
            
            self.logger.info("Signature verification completed", {
                "is_valid": is_valid,
                "error_count": len(errors),
                "cert_id": signature.metadata.cert_id
            })
            
            return is_valid, errors
            
        except Exception as e:
            self.logger.error(f"Signature verification failed: {str(e)}")
            errors.append(f"Verification error: {str(e)}")
            return False, errors

    def export_signature_json(self, signature: ICSSignature) -> str:
        """Export ICS signature as JSON string."""
        return json.dumps(asdict(signature), indent=2, ensure_ascii=False)

    def import_signature_json(self, signature_json: str) -> ICSSignature:
        """Import ICS signature from JSON string."""
        try:
            data = json.loads(signature_json)
            
            fingerprint = ContentFingerprint(**data['fingerprint'])
            metadata = CertificationMetadata(**data['metadata'])
            
            return ICSSignature(
                fingerprint=fingerprint,
                metadata=metadata,
                analysis_summary=data['analysis_summary'],
                vault_anchor=data['vault_anchor'],
                verification_data=data['verification_data']
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            self.logger.error(f"Failed to import signature JSON: {str(e)}")
            raise ValueError(f"Invalid signature JSON: {str(e)}")

