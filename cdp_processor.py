"""
CDP (Convergent Drafting Protocol) Processor
Core execution engine for structural nonfiction processing.
"""

import re
import statistics
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from certnode_config import CertNodeConfig, CertNodeLogger

@dataclass
class ParagraphAnalysis:
    """Analysis results for a single paragraph."""
    content: str
    word_count: int
    sentence_count: int
    slope_type: str
    anchor_type: str
    convergence_pattern: str
    logic_weight: float
    clause_density: float
    resolution_score: float

@dataclass
class CDPResult:
    """Complete CDP analysis result."""
    paragraphs: List[ParagraphAnalysis]
    overall_slope: str
    structural_integrity: float
    logic_continuity: float
    convergence_achieved: bool
    processing_metadata: Dict[str, Any]

class CDPProcessor:
    """
    Convergent Drafting Protocol processor.
    Analyzes nonfiction content for structural logic patterns.
    """

    def __init__(self):
        self.logger = CertNodeLogger("CDP")
        self.config = CertNodeConfig()

    def process_content(self, content: str, author_id: Optional[str] = None) -> CDPResult:
        """
        Process content through CDP analysis.
        
        Args:
            content: Raw nonfiction text
            author_id: Optional author identifier
            
        Returns:
            CDPResult with complete analysis
        """
        self.logger.info("Starting CDP processing", {"author_id": author_id})
        
        try:
            # Split into paragraphs
            paragraphs = self._extract_paragraphs(content)
            
            # Analyze each paragraph
            paragraph_analyses = []
            for i, para in enumerate(paragraphs):
                analysis = self._analyze_paragraph(para, i, len(paragraphs))
                paragraph_analyses.append(analysis)
            
            # Calculate overall metrics
            overall_slope = self._determine_overall_slope(paragraph_analyses)
            structural_integrity = self._calculate_structural_integrity(paragraph_analyses)
            logic_continuity = self._calculate_logic_continuity(paragraph_analyses)
            convergence_achieved = self._assess_convergence(paragraph_analyses)
            
            result = CDPResult(
                paragraphs=paragraph_analyses,
                overall_slope=overall_slope,
                structural_integrity=structural_integrity,
                logic_continuity=logic_continuity,
                convergence_achieved=convergence_achieved,
                processing_metadata={
                    "total_paragraphs": len(paragraphs),
                    "total_words": sum(p.word_count for p in paragraph_analyses),
                    "processing_version": self.config.CDP_VERSION,
                    "author_id": author_id
                }
            )
            
            self.logger.info("CDP processing completed", {
                "convergence_achieved": convergence_achieved,
                "structural_integrity": structural_integrity
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"CDP processing failed: {str(e)}")
            raise

    def _extract_paragraphs(self, content: str) -> List[str]:
        """Extract and clean paragraphs from content."""
        # Split on double newlines, clean whitespace
        paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
        
        # Filter out paragraphs that are too short
        valid_paragraphs = []
        for para in paragraphs:
            word_count = len(para.split())
            if word_count >= self.config.MIN_PARAGRAPH_MASS:
                valid_paragraphs.append(para)
        
        return valid_paragraphs

    def _analyze_paragraph(self, content: str, position: int, total: int) -> ParagraphAnalysis:
        """Analyze individual paragraph for structural patterns."""
        
        # Basic metrics
        words = content.split()
        sentences = self._split_sentences(content)
        word_count = len(words)
        sentence_count = len(sentences)
        
        # Slope type detection
        slope_type = self._detect_slope_type(content, position, total)
        
        # Anchor type detection  
        anchor_type = self._detect_anchor_type(content)
        
        # Convergence pattern
        convergence_pattern = self._detect_convergence_pattern(content, sentences)
        
        # Logic weight (complexity of reasoning)
        logic_weight = self._calculate_logic_weight(content, sentences)
        
        # Clause density (interlocking complexity)
        clause_density = self._calculate_clause_density(sentences)
        
        # Resolution score (how well paragraph resolves its logic)
        resolution_score = self._calculate_resolution_score(content, sentences)
        
        return ParagraphAnalysis(
            content=content,
            word_count=word_count,
            sentence_count=sentence_count,
            slope_type=slope_type,
            anchor_type=anchor_type,
            convergence_pattern=convergence_pattern,
            logic_weight=logic_weight,
            clause_density=clause_density,
            resolution_score=resolution_score
        )

    def _split_sentences(self, text: str) -> List[str]:
        """Split text into sentences."""
        # Simple sentence splitting (could be enhanced with NLTK)
        sentence_endings = r'[.!?]+(?:\s+|$)'
        sentences = re.split(sentence_endings, text)
        return [s.strip() for s in sentences if s.strip()]

    def _detect_slope_type(self, content: str, position: int, total: int) -> str:
        """Detect the logical slope type of the paragraph."""
        content_lower = content.lower()
        
        # Instructional indicators
        instructional_markers = ['how to', 'first', 'then', 'next', 'finally', 'step by', 'process']
        instructional_score = sum(1 for marker in instructional_markers if marker in content_lower)
        
        # Comparative indicators
        comparative_markers = ['compared to', 'in contrast', 'however', 'whereas', 'unlike', 'similar to']
        comparative_score = sum(1 for marker in comparative_markers if marker in content_lower)
        
        # Theoretical indicators
        theoretical_markers = ['theory', 'concept', 'principle', 'framework', 'model', 'paradigm']
        theoretical_score = sum(1 for marker in theoretical_markers if marker in content_lower)
        
        # Persuasive indicators
        persuasive_markers = ['should', 'must', 'ought', 'therefore', 'thus', 'clearly', 'obviously']
        persuasive_score = sum(1 for marker in persuasive_markers if marker in content_lower)
        
        # Diagnostic indicators
        diagnostic_markers = ['because', 'due to', 'caused by', 'result of', 'leads to', 'explains why']
        diagnostic_score = sum(1 for marker in diagnostic_markers if marker in content_lower)
        
        # Recursive indicators (self-referential logic)
        recursive_markers = ['as mentioned', 'as we saw', 'returning to', 'circle back', 'revisiting']
        recursive_score = sum(1 for marker in recursive_markers if marker in content_lower)
        
        scores = {
            "INSTRUCTIONAL": instructional_score,
            "COMPARATIVE": comparative_score,
            "THEORETICAL": theoretical_score,
            "PERSUASIVE": persuasive_score,
            "DIAGNOSTIC": diagnostic_score,
            "RECURSIVE": recursive_score
        }
        
        # Return highest scoring type, default to theoretical
        max_type = max(scores.items(), key=lambda x: x[1])
        return max_type[0] if max_type[1] > 0 else "THEORETICAL"

    def _detect_anchor_type(self, content: str) -> str:
        """Detect the anchor type (source of logical authority)."""
        content_lower = content.lower()
        
        # Primary source indicators
        primary_indicators = ['study shows', 'research indicates', 'data reveals', 'according to']
        primary_score = sum(1 for indicator in primary_indicators if indicator in content_lower)
        
        # Synthetic rationale indicators  
        synthetic_indicators = ['it follows that', 'we can conclude', 'this suggests', 'reasoning shows']
        synthetic_score = sum(1 for indicator in synthetic_indicators if indicator in content_lower)
        
        # Cross-sourced logic indicators
        cross_indicators = ['multiple sources', 'various studies', 'consensus shows', 'collectively']
        cross_score = sum(1 for indicator in cross_indicators if indicator in content_lower)
        
        # Contextual recall indicators
        recall_indicators = ['historically', 'traditionally', 'commonly known', 'established fact']
        recall_score = sum(1 for indicator in recall_indicators if indicator in content_lower)
        
        scores = {
            "PRIMARY_SOURCE": primary_score,
            "SYNTHETIC_RATIONALE": synthetic_score,
            "CROSS_SOURCED_LOGIC": cross_score,
            "CONTEXTUAL_RECALL": recall_score
        }
        
        max_type = max(scores.items(), key=lambda x: x[1])
        return max_type[0] if max_type[1] > 0 else "SYNTHETIC_RATIONALE"

    def _detect_convergence_pattern(self, content: str, sentences: List[str]) -> str:
        """Detect how the paragraph converges logically."""
        if len(sentences) < 2:
            return "TAPERED_LINEARITY"
        
        # Analyze sentence progression
        sentence_lengths = [len(s.split()) for s in sentences]
        
        # Tapered linearity: sentences get shorter/more decisive
        if len(sentence_lengths) >= 3:
            if sentence_lengths[-1] < sentence_lengths[0] and sentence_lengths[-2] < sentence_lengths[0]:
                return "TAPERED_LINEARITY"
        
        # Nested glide: complex to simple with embedding
        if any('(' in s and ')' in s for s in sentences):
            return "NESTED_GLIDE"
        
        # Spiral descent: recursive building
        spiral_markers = ['again', 'further', 'deeper', 'more importantly']
        if any(marker in content.lower() for marker in spiral_markers):
            return "SPIRAL_DESCENT"
        
        # Default: anchor lock chain
        return "ANCHOR_LOCK_CHAIN"

    def _calculate_logic_weight(self, content: str, sentences: List[str]) -> float:
        """Calculate the logical weight/complexity of reasoning."""
        # Count logical connectors
        logical_connectors = ['therefore', 'because', 'since', 'however', 'although', 'furthermore']
        connector_count = sum(1 for connector in logical_connectors 
                            if connector in content.lower())
        
        # Count qualifying phrases
        qualifiers = ['perhaps', 'likely', 'suggests', 'indicates', 'appears', 'seems']
        qualifier_count = sum(1 for qualifier in qualifiers if qualifier in content.lower())
        
        # Weight by sentence complexity
        avg_sentence_length = statistics.mean([len(s.split()) for s in sentences])
        complexity_factor = min(avg_sentence_length / 20, 2.0)  # Cap at 2.0
        
        # Combined logic weight (0.0 to 1.0 scale)
        raw_weight = (connector_count + qualifier_count) * complexity_factor
        return min(raw_weight / 10.0, 1.0)  # Normalize to 0-1

    def _calculate_clause_density(self, sentences: List[str]) -> float:
        """Calculate clause interlocking density."""
        total_clauses = 0
        for sentence in sentences:
            # Count commas, semicolons, and conjunctions as clause separators
            clause_markers = sentence.count(',') + sentence.count(';') + sentence.count(' and ') + sentence.count(' but ')
            total_clauses += clause_markers + 1  # +1 for main clause
        
        # Density as clauses per sentence
        if len(sentences) == 0:
            return 0.0
        
        density = total_clauses / len(sentences)
        return min(density / 5.0, 1.0)  # Normalize to 0-1, cap at 5 clauses per sentence

    def _calculate_resolution_score(self, content: str, sentences: List[str]) -> float:
        """Calculate how well the paragraph resolves its logical movement."""
        if len(sentences) < 2:
            return 0.5
        
        last_sentence = sentences[-1].lower()
        
        # Strong resolution indicators
        strong_resolution = ['therefore', 'thus', 'consequently', 'in conclusion', 'ultimately']
        strong_count = sum(1 for indicator in strong_resolution if indicator in last_sentence)
        
        # Weak resolution indicators
        weak_resolution = ['however', 'but', 'although', 'yet', 'still']
        weak_count = sum(1 for indicator in weak_resolution if indicator in last_sentence)
        
        # Calculate resolution strength
        if strong_count > 0:
            return min(0.7 + (strong_count * 0.1), 1.0)
        elif weak_count > 0:
            return max(0.3 - (weak_count * 0.1), 0.0)
        else:
            # Medium resolution by default
            return 0.5

    def _determine_overall_slope(self, paragraphs: List[ParagraphAnalysis]) -> str:
        """Determine the overall slope type of the content."""
        if not paragraphs:
            return "THEORETICAL"
        
        # Count slope types across paragraphs
        slope_counts = {}
        for para in paragraphs:
            slope_counts[para.slope_type] = slope_counts.get(para.slope_type, 0) + 1
        
        # Return most common slope type
        return max(slope_counts.items(), key=lambda x: x[1])[0]

    def _calculate_structural_integrity(self, paragraphs: List[ParagraphAnalysis]) -> float:
        """Calculate overall structural integrity."""
        if not paragraphs:
            return 0.0
        
        # Average logic weight across paragraphs
        avg_logic_weight = statistics.mean([p.logic_weight for p in paragraphs])
        
        # Average clause density
        avg_clause_density = statistics.mean([p.clause_density for p in paragraphs])
        
        # Average resolution score
        avg_resolution = statistics.mean([p.resolution_score for p in paragraphs])
        
        # Combined structural integrity
        return (avg_logic_weight + avg_clause_density + avg_resolution) / 3.0

    def _calculate_logic_continuity(self, paragraphs: List[ParagraphAnalysis]) -> float:
        """Calculate logical continuity between paragraphs."""
        if len(paragraphs) < 2:
            return 1.0
        
        continuity_scores = []
        for i in range(len(paragraphs) - 1):
            current = paragraphs[i]
            next_para = paragraphs[i + 1]
            
            # Slope type consistency
            slope_consistency = 1.0 if current.slope_type == next_para.slope_type else 0.5
            
            # Logic weight progression (should be relatively smooth)
            weight_diff = abs(current.logic_weight - next_para.logic_weight)
            weight_consistency = max(0.0, 1.0 - weight_diff)
            
            # Resolution to opening transition
            transition_score = (current.resolution_score + next_para.logic_weight) / 2.0
            
            paragraph_continuity = (slope_consistency + weight_consistency + transition_score) / 3.0
            continuity_scores.append(paragraph_continuity)
        
        return statistics.mean(continuity_scores)

    def _assess_convergence(self, paragraphs: List[ParagraphAnalysis]) -> bool:
        """Assess whether the content achieves logical convergence."""
        if not paragraphs:
            return False
        
        # Check overall structural integrity
        structural_integrity = self._calculate_structural_integrity(paragraphs)
        
        # Check logic continuity
        logic_continuity = self._calculate_logic_continuity(paragraphs)
        
        # Check final resolution
        final_resolution = paragraphs[-1].resolution_score if paragraphs else 0.0
        
        # Convergence requires high scores across all metrics
        convergence_threshold = 0.6
        return (structural_integrity >= convergence_threshold and 
                logic_continuity >= convergence_threshold and 
                final_resolution >= convergence_threshold)

