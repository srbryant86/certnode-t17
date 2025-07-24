"""
CertNode Main Processor
Coordinates all certification systems and provides the primary certification interface.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from certnode_config import CertNodeConfig, CertNodeLogger
from cdp_processor import CDPProcessor, CDPResult
from frame_processor import FRAMEProcessor, FRAMEResult
from stride_processor import STRIDEProcessor, STRIDEResult
from ics_generator import ICSGenerator, ICSSignature

@dataclass
class CertificationRequest:
    """Request for content certification."""
    content: str
    cert_type: str
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    title: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class CertificationResult:
    """Complete certification result."""
    success: bool
    cert_id: str
    ics_signature: Optional[ICSSignature]
    cdp_result: Optional[CDPResult]
    frame_result: Optional[FRAMEResult]
    stride_result: Optional[STRIDEResult]
    certification_score: float
    issues: List[str]
    recommendations: List[str]
    processing_time: float
    output_files: Dict[str, str]

class CertNodeProcessor:
    """
    Main CertNode processor that coordinates all certification systems.
    Provides the primary interface for content certification.
    """

    def __init__(self):
        self.logger = CertNodeLogger("CertNode")
        self.config = CertNodeConfig()
        
        # Initialize component processors
        self.cdp_processor = CDPProcessor()
        self.frame_processor = FRAMEProcessor()
        self.stride_processor = STRIDEProcessor()
        self.ics_generator = ICSGenerator()
        
        # Ensure output directories exist
        self.config.ensure_directories()
        
        self.logger.info("CertNode processor initialized", {
            "version": self.config.CERTNODE_VERSION,
            "operator": self.config.OPERATOR
        })

    def certify_content(self, request: CertificationRequest) -> CertificationResult:
        """
        Certify content through complete CertNode pipeline.
        
        Args:
            request: Certification request with content and parameters
            
        Returns:
            Complete certification result
        """
        start_time = datetime.now()
        
        self.logger.info("Starting content certification", {
            "content_length": len(request.content),
            "cert_type": request.cert_type,
            "author_id": request.author_id,
            "title": request.title
        })
        
        try:
            # Initialize result tracking
            issues = []
            recommendations = []
            
            # Step 1: CDP Processing (Core Logic Analysis)
            self.logger.info("Running CDP analysis")
            cdp_result = self.cdp_processor.process_content(
                request.content, request.author_id
            )
            
            if not cdp_result.convergence_achieved:
                issues.append("Content does not achieve logical convergence")
                recommendations.extend(["Strengthen logical flow between paragraphs",
                                      "Ensure final paragraph provides clear resolution"])
            
            # Step 2: FRAME Processing (Structural Boundaries)
            self.logger.info("Running FRAME analysis")
            frame_result = self.frame_processor.process_content(cdp_result)
            
            if not frame_result.boundaries_satisfied:
                issues.extend(frame_result.boundary_violations)
                recommendations.extend(frame_result.recommendations)
            
            # Step 3: STRIDE Processing (Drift Suppression)
            self.logger.info("Running STRIDE analysis")
            stride_result = self.stride_processor.process_content(cdp_result)
            
            if stride_result.suppression_needed:
                issues.append("Content contains rhetorical drift requiring suppression")
                recommendations.extend(stride_result.recommendations)
            
            # Step 4: Calculate Certification Score
            certification_score = self._calculate_certification_score(
                cdp_result, frame_result, stride_result
            )
            
            # Step 5: Determine Certification Success
            success = self._determine_certification_success(
                cdp_result, frame_result, stride_result, certification_score
            )
            
            # Step 6: Generate ICS Signature (if successful)
            ics_signature = None
            if success:
                self.logger.info("Generating ICS signature")
                ics_signature = self.ics_generator.generate_signature(
                    request.content, cdp_result, frame_result, stride_result,
                    request.cert_type, request.author_id
                )
            
            # Step 7: Generate Output Files
            output_files = self._generate_output_files(
                request, cdp_result, frame_result, stride_result, ics_signature
            )
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Create result
            result = CertificationResult(
                success=success,
                cert_id=ics_signature.metadata.cert_id if ics_signature else "FAILED",
                ics_signature=ics_signature,
                cdp_result=cdp_result,
                frame_result=frame_result,
                stride_result=stride_result,
                certification_score=certification_score,
                issues=issues,
                recommendations=recommendations,
                processing_time=processing_time,
                output_files=output_files
            )
            
            self.logger.info("Content certification completed", {
                "success": success,
                "cert_id": result.cert_id,
                "certification_score": certification_score,
                "processing_time": processing_time,
                "issues_count": len(issues)
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Content certification failed: {str(e)}")
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return CertificationResult(
                success=False,
                cert_id="ERROR",
                ics_signature=None,
                cdp_result=None,
                frame_result=None,
                stride_result=None,
                certification_score=0.0,
                issues=[f"Processing error: {str(e)}"],
                recommendations=["Review content format and retry certification"],
                processing_time=processing_time,
                output_files={}
            )

    def verify_certification(self, content: str, signature_data: str) -> Tuple[bool, List[str]]:
        """
        Verify a certification against content.
        
        Args:
            content: Content to verify
            signature_data: ICS signature as JSON string
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        try:
            signature = self.ics_generator.import_signature_json(signature_data)
            return self.ics_generator.verify_signature(content, signature)
        except Exception as e:
            self.logger.error(f"Verification failed: {str(e)}")
            return False, [f"Verification error: {str(e)}"]

    def _calculate_certification_score(self, cdp_result: CDPResult,
                                     frame_result: FRAMEResult,
                                     stride_result: STRIDEResult) -> float:
        """Calculate overall certification score."""
        # CDP Score (40% weight)
        cdp_score = 0.0
        if cdp_result.convergence_achieved:
            cdp_score += 0.4
        cdp_score += cdp_result.structural_integrity * 0.3
        cdp_score += cdp_result.logic_continuity * 0.3
        
        # FRAME Score (35% weight)
        frame_score = frame_result.structural_score
        
        # STRIDE Score (25% weight) - inverted suppression score
        stride_score = 1.0 - stride_result.suppression_score
        
        # Weighted total
        total_score = (cdp_score * 0.4) + (frame_score * 0.35) + (stride_score * 0.25)
        
        return min(max(total_score, 0.0), 1.0)  # Clamp to 0-1 range

    def _determine_certification_success(self, cdp_result: CDPResult,
                                       frame_result: FRAMEResult,
                                       stride_result: STRIDEResult,
                                       certification_score: float) -> bool:
        """Determine if content qualifies for certification."""
        # Minimum requirements
        min_score = self.config.CERTIFICATION_THRESHOLD
        if certification_score < min_score:
            return False
        
        # Must achieve convergence
        if not cdp_result.convergence_achieved:
            return False
        
        # Must satisfy structural boundaries
        if not frame_result.boundaries_satisfied:
            return False
        
        # Must not have severe drift
        if stride_result.drift_detection.drift_severity > 0.7:
            return False
        
        return True

    def _generate_output_files(self, request: CertificationRequest,
                             cdp_result: CDPResult,
                             frame_result: FRAMEResult,
                             stride_result: STRIDEResult,
                             ics_signature: Optional[ICSSignature]) -> Dict[str, str]:
        """Generate output files for certification."""
        output_files = {}
        
        try:
            # Create base filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            title_safe = self._safe_filename(request.title or "content")
            base_filename = f"{timestamp}_{title_safe}"
            
            # Generate certified content file
            if ics_signature:
                certified_content = self._create_certified_content(request, ics_signature)
                cert_file = self.config.CERTS_DIR / f"{base_filename}_certified.txt"
                with open(cert_file, 'w', encoding='utf-8') as f:
                    f.write(certified_content)
                output_files["certified_content"] = str(cert_file)
            
            # Generate ICS signature file
            if ics_signature:
                ics_file = self.config.CERTS_DIR / f"{base_filename}_signature.json"
                with open(ics_file, 'w', encoding='utf-8') as f:
                    f.write(self.ics_generator.export_signature_json(ics_signature))
                output_files["ics_signature"] = str(ics_file)
            
            # Generate analysis report
            report = self._create_analysis_report(request, cdp_result, frame_result, stride_result, ics_signature)
            report_file = self.config.CERTS_DIR / f"{base_filename}_analysis.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(json.dumps(report, indent=2))
            output_files["analysis_report"] = str(report_file)
            
            # Generate badge metadata
            if ics_signature:
                badge_data = self._create_badge_data(ics_signature)
                badge_file = self.config.BADGES_DIR / f"{base_filename}_badge.json"
                with open(badge_file, 'w', encoding='utf-8') as f:
                    f.write(json.dumps(badge_data, indent=2))
                output_files["badge_data"] = str(badge_file)
            
        except Exception as e:
            self.logger.error(f"Failed to generate output files: {str(e)}")
        
        return output_files

    def _create_certified_content(self, request: CertificationRequest, 
                                ics_signature: ICSSignature) -> str:
        """Create certified content with embedded metadata."""
        header = f"""# CERTIFIED BY CERTNODE

Certification ID: {ics_signature.metadata.cert_id}
Certified: {ics_signature.metadata.timestamp}
Operator: {ics_signature.metadata.operator}
ICS Hash: {ics_signature.fingerprint.combined_hash}
Verify at: {ics_signature.verification_data['verification_url']}

-----

"""
        
        footer = f"""

-----

## CERTIFICATION METADATA

- **Type**: {ics_signature.metadata.content_type}
- **Structural Integrity**: {ics_signature.analysis_summary['cdp_analysis']['structural_integrity']}
- **Logic Continuity**: {ics_signature.analysis_summary['cdp_analysis']['logic_continuity']}
- **Convergence Achieved**: {ics_signature.analysis_summary['cdp_analysis']['convergence_achieved']}
- **Boundaries Satisfied**: {ics_signature.analysis_summary['frame_analysis']['boundaries_satisfied']}
- **Suppression Score**: {ics_signature.analysis_summary['stride_analysis']['suppression_score']}

*This certification represents a structural logic validation issued by CertNode. It does not indicate copyright registration, originality guarantee, or legal authorship assignment.*
"""
        
        return header + request.content + footer

    def _create_analysis_report(self, request: CertificationRequest,
                              cdp_result: CDPResult,
                              frame_result: FRAMEResult,
                              stride_result: STRIDEResult,
                              ics_signature: Optional[ICSSignature]) -> Dict[str, Any]:
        """Create comprehensive analysis report."""
        return {
            "request": {
                "title": request.title,
                "cert_type": request.cert_type,
                "author_name": request.author_name,
                "content_length": len(request.content),
                "word_count": len(request.content.split())
            },
            "cdp_analysis": asdict(cdp_result) if cdp_result else None,
            "frame_analysis": asdict(frame_result) if frame_result else None,
            "stride_analysis": asdict(stride_result) if stride_result else None,
            "ics_signature": asdict(ics_signature) if ics_signature else None,
            "generated_timestamp": datetime.now().isoformat()
        }

    def _create_badge_data(self, ics_signature: ICSSignature) -> Dict[str, Any]:
        """Create badge display data."""
        return {
            "cert_id": ics_signature.metadata.cert_id,
            "badge_type": "CertNode Verified",
            "cert_type": ics_signature.metadata.content_type,
            "issued_date": ics_signature.metadata.timestamp,
            "operator": ics_signature.metadata.operator,
            "verification_url": ics_signature.verification_data["verification_url"],
            "badge_url": ics_signature.verification_data["badge_url"],
            "vault_anchor": ics_signature.vault_anchor,
            "structural_score": ics_signature.analysis_summary["frame_analysis"]["structural_score"],
            "convergence_achieved": ics_signature.analysis_summary["cdp_analysis"]["convergence_achieved"]
        }

    def _safe_filename(self, text: str) -> str:
        """Create safe filename from text."""
        import re
        # Remove or replace unsafe characters
        safe = re.sub(r'[<>:"/\\|?*]', '_', text)
        # Limit length
        return safe[:50] if len(safe) > 50 else safe

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and configuration."""
        return {
            "system_version": self.config.CERTNODE_VERSION,
            "operator": self.config.OPERATOR,
            "component_versions": {
                "CDP": self.config.CDP_VERSION,
                "FRAME": self.config.FRAME_VERSION,
                "STRIDE": self.config.STRIDE_VERSION
            },
            "directories": {
                "vault": str(self.config.VAULT_DIR),
                "certs": str(self.config.CERTS_DIR),
                "logs": str(self.config.LOGS_DIR),
                "badges": str(self.config.BADGES_DIR)
            },
            "genesis_hash": self.config.get_genesis_hash(),
            "supported_cert_types": list(self.config.CERT_TYPES.keys()),
            "status": "operational"
        }

# CLI Interface Functions

def certify_file(file_path: str, cert_type: str = "LOGIC_FRAGMENT",
                author_id: Optional[str] = None, title: Optional[str] = None) -> CertificationResult:
    """Certify content from file."""
    processor = CertNodeProcessor()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    request = CertificationRequest(
        content=content,
        cert_type=cert_type,
        author_id=author_id,
        title=title or Path(file_path).stem
    )

    return processor.certify_content(request)

def verify_file(content_file: str, signature_file: str) -> Tuple[bool, List[str]]:
    """Verify certification from files."""
    processor = CertNodeProcessor()
    
    with open(content_file, 'r', encoding='utf-8') as f:
        content = f.read()

    with open(signature_file, 'r', encoding='utf-8') as f:
        signature_data = f.read()

    return processor.verify_certification(content, signature_data)

