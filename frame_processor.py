"""
FRAME (Structural Boundaries) Processor
Enforces structural boundaries, taper, and slope resolution targets.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from certnode_config import CertNodeConfig, CertNodeLogger
from cdp_processor import CDPResult, ParagraphAnalysis

@dataclass
class StructuralBoundary:
    """Defines a structural boundary constraint."""
    boundary_type: str
    min_value: float
    max_value: float
    target_value: float
    weight: float

@dataclass
class TaperAnalysis:
    """Analysis of content taper (how content narrows to resolution)."""
    taper_achieved: bool
    taper_score: float
    taper_pattern: str
    resolution_strength: float

@dataclass
class FRAMEResult:
    """Complete FRAME analysis result."""
    boundaries_satisfied: bool
    boundary_violations: List[str]
    taper_analysis: TaperAnalysis
    slope_resolution: bool
    structural_score: float
    logical_consistency: float
    evidence_quality: float
    reasoning_clarity: float
    recommendations: List[str]
    metadata: Dict[str, Any]

class FRAMEProcessor:
    """
    FRAME processor for structural boundary enforcement.
    Sets and validates structural boundaries, taper, and slope resolution.
    """

    def __init__(self):
        self.logger = CertNodeLogger("FRAME")
        self.config = CertNodeConfig()
        self.boundaries = self._initialize_boundaries()

    def process_content(self, cdp_result: CDPResult) -> FRAMEResult:
        """
        Process CDP result through FRAME boundary analysis.
        
        Args:
            cdp_result: CDP analysis result
            
        Returns:
            FRAMEResult with boundary validation
        """
        self.logger.info("Starting FRAME processing", {
            "paragraph_count": len(cdp_result.paragraphs),
            "overall_slope": cdp_result.overall_slope
        })
        
        try:
            # Check boundary satisfaction
            boundaries_satisfied, violations = self._check_boundaries(cdp_result)
            
            # Analyze taper
            taper_analysis = self._analyze_taper(cdp_result.paragraphs)
            
            # Check slope resolution
            slope_resolution = self._check_slope_resolution(cdp_result)
            
            # Calculate structural score
            structural_score = self._calculate_structural_score(
                boundaries_satisfied, taper_analysis, slope_resolution
            )
            
            # Calculate additional metrics
            logical_consistency = self._calculate_logical_consistency(cdp_result)
            evidence_quality = self._calculate_evidence_quality(cdp_result)
            reasoning_clarity = self._calculate_reasoning_clarity(cdp_result)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                violations, taper_analysis, slope_resolution
            )
            
            result = FRAMEResult(
                boundaries_satisfied=boundaries_satisfied,
                boundary_violations=violations,
                taper_analysis=taper_analysis,
                slope_resolution=slope_resolution,
                structural_score=structural_score,
                logical_consistency=logical_consistency,
                evidence_quality=evidence_quality,
                reasoning_clarity=reasoning_clarity,
                recommendations=recommendations,
                metadata={
                    "frame_version": self.config.FRAME_VERSION,
                    "boundaries_checked": len(self.boundaries),
                    "processing_timestamp": self._get_timestamp()
                }
            )
            
            self.logger.info("FRAME processing completed", {
                "boundaries_satisfied": boundaries_satisfied,
                "structural_score": structural_score
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"FRAME processing failed: {str(e)}")
            raise

    def _initialize_boundaries(self) -> Dict[str, StructuralBoundary]:
        """Initialize structural boundary constraints."""
        return {
            "min_paragraphs": StructuralBoundary(
                boundary_type="paragraph_count",
                min_value=2.0,
                max_value=50.0,
                target_value=8.0,
                weight=0.8
            ),
            "logic_weight": StructuralBoundary(
                boundary_type="logic_weight",
                min_value=0.3,
                max_value=1.0,
                target_value=0.7,
                weight=1.0
            ),
            "clause_density": StructuralBoundary(
                boundary_type="clause_density", 
                min_value=0.2,
                max_value=1.0,
                target_value=0.6,
                weight=0.9
            ),
            "resolution_score": StructuralBoundary(
                boundary_type="resolution_score",
                min_value=0.4,
                max_value=1.0,
                target_value=0.8,
                weight=1.0
            ),
            "structural_integrity": StructuralBoundary(
                boundary_type="structural_integrity",
                min_value=0.5,
                max_value=1.0,
                target_value=0.75,
                weight=1.0
            ),
            "logic_continuity": StructuralBoundary(
                boundary_type="logic_continuity",
                min_value=0.4,
                max_value=1.0,
                target_value=0.7,
                weight=0.9
            )
        }

    def _check_boundaries(self, cdp_result: CDPResult) -> Tuple[bool, List[str]]:
        """Check if content satisfies structural boundaries."""
        violations = []
        
        # Check paragraph count
        para_count = len(cdp_result.paragraphs)
        para_boundary = self.boundaries["min_paragraphs"]
        if para_count < para_boundary.min_value:
            violations.append(f"Insufficient paragraphs: {para_count} < {para_boundary.min_value}")
        elif para_count > para_boundary.max_value:
            violations.append(f"Excessive paragraphs: {para_count} > {para_boundary.max_value}")
        
        # Check structural integrity
        integrity_boundary = self.boundaries["structural_integrity"]
        if cdp_result.structural_integrity < integrity_boundary.min_value:
            violations.append(f"Low structural integrity: {cdp_result.structural_integrity:.2f} < {integrity_boundary.min_value}")
        
        # Check logic continuity
        continuity_boundary = self.boundaries["logic_continuity"]
        if cdp_result.logic_continuity < continuity_boundary.min_value:
            violations.append(f"Poor logic continuity: {cdp_result.logic_continuity:.2f} < {continuity_boundary.min_value}")
        
        return len(violations) == 0, violations

    def _analyze_taper(self, paragraphs: List[ParagraphAnalysis]) -> TaperAnalysis:
        """Analyze content taper pattern."""
        if len(paragraphs) < 3:
            return TaperAnalysis(
                taper_achieved=False,
                taper_score=0.5,
                taper_pattern="insufficient_length",
                resolution_strength=paragraphs[-1].resolution_score if paragraphs else 0.0
            )
        
        # Analyze word count taper
        word_counts = [p.word_count for p in paragraphs]
        
        # Check for descending taper (preferred)
        descending_taper = self._check_descending_taper(word_counts)
        
        # Check for resolution taper (logic becomes more decisive)
        logic_weights = [p.logic_weight for p in paragraphs]
        resolution_taper = self._check_resolution_taper(logic_weights)
        
        # Determine taper pattern
        if descending_taper and resolution_taper:
            taper_pattern = "optimal_convergent"
            taper_score = 0.9
        elif descending_taper:
            taper_pattern = "length_convergent"
            taper_score = 0.7
        elif resolution_taper:
            taper_pattern = "logic_convergent"
            taper_score = 0.8
        else:
            taper_pattern = "non_convergent"
            taper_score = 0.3
        
        taper_achieved = taper_score >= 0.6
        
        return TaperAnalysis(
            taper_achieved=taper_achieved,
            taper_score=taper_score,
            taper_pattern=taper_pattern,
            resolution_strength=paragraphs[-1].resolution_score
        )

    def _check_descending_taper(self, word_counts: List[int]) -> bool:
        """Check if word counts show descending taper."""
        if len(word_counts) < 3:
            return False
        
        # Check if final third shows general decline
        third_length = len(word_counts) // 3
        if third_length == 0:
            third_length = 1
        
        first_third_avg = sum(word_counts[:third_length]) / third_length
        last_third_avg = sum(word_counts[-third_length:]) / third_length
        
        # Allow some variation but look for general decline
        return last_third_avg <= first_third_avg * 0.8

    def _check_resolution_taper(self, logic_weights: List[float]) -> bool:
        """Check if logic weights show resolution taper."""
        if len(logic_weights) < 3:
            return False
        
        # Final paragraph should show strong logic convergence
        final_weight = logic_weights[-1]
        avg_weight = sum(logic_weights[:-1]) / (len(logic_weights) - 1)
        
        # Final paragraph should be more decisive
        return final_weight >= avg_weight

    def _check_slope_resolution(self, cdp_result: CDPResult) -> bool:
        """Check if content achieves proper slope resolution."""
        # Must achieve convergence
        if not cdp_result.convergence_achieved:
            return False
        
        # Final paragraph must have strong resolution
        if not cdp_result.paragraphs:
            return False
        
        final_resolution = cdp_result.paragraphs[-1].resolution_score
        resolution_threshold = 0.6
        
        return final_resolution >= resolution_threshold

    def _calculate_structural_score(self, boundaries_satisfied: bool, 
                                  taper_analysis: TaperAnalysis, 
                                  slope_resolution: bool) -> float:
        """Calculate overall structural score."""
        # Base scores
        boundary_score = 1.0 if boundaries_satisfied else 0.5
        taper_score = taper_analysis.taper_score
        resolution_score = 1.0 if slope_resolution else 0.3
        
        # Weighted average
        weights = [0.4, 0.3, 0.3]  # boundaries, taper, resolution
        scores = [boundary_score, taper_score, resolution_score]
        
        return sum(w * s for w, s in zip(weights, scores))

    def _calculate_logical_consistency(self, cdp_result: CDPResult) -> float:
        """Calculate logical consistency score."""
        return cdp_result.logic_continuity

    def _calculate_evidence_quality(self, cdp_result: CDPResult) -> float:
        """Calculate evidence quality score."""
        if not cdp_result.paragraphs:
            return 0.0
        
        # Count primary source anchors
        primary_count = sum(1 for p in cdp_result.paragraphs 
                          if p.anchor_type == "PRIMARY_SOURCE")
        
        # Calculate evidence ratio
        evidence_ratio = primary_count / len(cdp_result.paragraphs)
        
        # Combine with structural integrity
        return (evidence_ratio + cdp_result.structural_integrity) / 2.0

    def _calculate_reasoning_clarity(self, cdp_result: CDPResult) -> float:
        """Calculate reasoning clarity score."""
        if not cdp_result.paragraphs:
            return 0.0
        
        # Average logic weight across paragraphs
        avg_logic_weight = sum(p.logic_weight for p in cdp_result.paragraphs) / len(cdp_result.paragraphs)
        
        # Combine with convergence achievement
        convergence_bonus = 0.2 if cdp_result.convergence_achieved else 0.0
        
        return min(avg_logic_weight + convergence_bonus, 1.0)

    def _generate_recommendations(self, violations: List[str], 
                                taper_analysis: TaperAnalysis,
                                slope_resolution: bool) -> List[str]:
        """Generate structural improvement recommendations."""
        recommendations = []
        
        # Address boundary violations
        for violation in violations:
            if "paragraphs" in violation.lower():
                if "insufficient" in violation.lower():
                    recommendations.append("Add more paragraphs to develop logic fully")
                else:
                    recommendations.append("Consolidate paragraphs to improve focus")
            
            elif "logic weight" in violation.lower():
                recommendations.append("Strengthen logical reasoning with more connectors and qualifiers")
            
            elif "clause density" in violation.lower():
                recommendations.append("Increase sentence complexity with more interlocking clauses")
            
            elif "resolution" in violation.lower():
                recommendations.append("Strengthen final paragraph with decisive conclusion")
            
            elif "continuity" in violation.lower():
                recommendations.append("Improve logical flow between paragraphs")
        
        # Address taper issues
        if not taper_analysis.taper_achieved:
            if taper_analysis.taper_pattern == "non_convergent":
                recommendations.append("Restructure content to converge toward clear resolution")
            elif "length" not in taper_analysis.taper_pattern:
                recommendations.append("Taper paragraph length toward conclusion")
        
        # Address resolution issues
        if not slope_resolution:
            recommendations.append("Strengthen logical conclusion to achieve slope resolution")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def update_boundaries(self, new_boundaries: Dict[str, Dict[str, float]]) -> None:
        """Update structural boundaries (for calibration)."""
        for boundary_name, params in new_boundaries.items():
            if boundary_name in self.boundaries:
                boundary = self.boundaries[boundary_name]
                boundary.min_value = params.get("min_value", boundary.min_value)
                boundary.max_value = params.get("max_value", boundary.max_value)
                boundary.target_value = params.get("target_value", boundary.target_value)
                boundary.weight = params.get("weight", boundary.weight)
        
        self.logger.info("Boundaries updated", {"updated_boundaries": list(new_boundaries.keys())})

