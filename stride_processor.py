"""
STRIDE (Suppression of Drift) Processor
Enforces tone neutrality and rhythm suppression to prevent rhetorical drift.
"""

import re
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from certnode_config import CertNodeConfig, CertNodeLogger
from cdp_processor import CDPResult, ParagraphAnalysis

@dataclass
class RhythmAnalysis:
    """Analysis of rhythmic patterns that might indicate drift."""
    rhythm_detected: bool
    rhythm_score: float
    rhythm_patterns: List[str]
    sentence_variation: float

@dataclass
class ToneAnalysis:
    """Analysis of tone markers that indicate non-neutral stance."""
    tone_neutrality: float
    emotional_markers: List[str]
    persuasion_intensity: float
    objectivity_score: float

@dataclass
class DriftDetection:
    """Detection of various forms of content drift."""
    rhetorical_drift: bool
    style_drift: bool
    emotional_drift: bool
    drift_severity: float
    drift_markers: List[str]

@dataclass
class STRIDEResult:
    """Complete STRIDE analysis result."""
    tone_analysis: ToneAnalysis
    rhythm_analysis: RhythmAnalysis
    drift_detection: DriftDetection
    suppression_needed: bool
    suppression_score: float
    recommendations: List[str]
    metadata: Dict[str, Any]

class STRIDEProcessor:
    """
    STRIDE processor for tone and rhythm suppression.
    Detects and flags content that drifts into rhetoric or style over logic.
    """

    def __init__(self):
        self.logger = CertNodeLogger("STRIDE")
        self.config = CertNodeConfig()
        self.drift_markers = self._initialize_drift_markers()

    def process_content(self, cdp_result: CDPResult) -> STRIDEResult:
        """
        Process CDP result through STRIDE suppression analysis.
        
        Args:
            cdp_result: CDP analysis result
            
        Returns:
            STRIDEResult with drift detection and suppression analysis
        """
        self.logger.info("Starting STRIDE processing", {
            "paragraph_count": len(cdp_result.paragraphs),
            "convergence_achieved": cdp_result.convergence_achieved
        })
        
        try:
            # Analyze tone neutrality
            tone_analysis = self._analyze_tone(cdp_result.paragraphs)
            
            # Analyze rhythm patterns
            rhythm_analysis = self._analyze_rhythm(cdp_result.paragraphs)
            
            # Detect drift patterns
            drift_detection = self._detect_drift(cdp_result.paragraphs, tone_analysis, rhythm_analysis)
            
            # Determine suppression needs
            suppression_needed = self._needs_suppression(tone_analysis, rhythm_analysis, drift_detection)
            
            # Calculate suppression score
            suppression_score = self._calculate_suppression_score(tone_analysis, rhythm_analysis, drift_detection)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(tone_analysis, rhythm_analysis, drift_detection)
            
            result = STRIDEResult(
                tone_analysis=tone_analysis,
                rhythm_analysis=rhythm_analysis,
                drift_detection=drift_detection,
                suppression_needed=suppression_needed,
                suppression_score=suppression_score,
                recommendations=recommendations,
                metadata={
                    "stride_version": self.config.STRIDE_VERSION,
                    "processing_timestamp": self._get_timestamp(),
                    "total_paragraphs": len(cdp_result.paragraphs)
                }
            )
            
            self.logger.info("STRIDE processing completed", {
                "suppression_needed": suppression_needed,
                "suppression_score": suppression_score,
                "drift_detected": drift_detection.rhetorical_drift or drift_detection.style_drift
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"STRIDE processing failed: {str(e)}")
            raise

    def _initialize_drift_markers(self) -> Dict[str, List[str]]:
        """Initialize markers for different types of drift."""
        return {
            "rhetorical": [
                "magnificent", "incredible", "amazing", "stunning", "remarkable",
                "extraordinary", "phenomenal", "fantastic", "brilliant", "spectacular",
                "obviously", "clearly", "undoubtedly", "certainly", "absolutely"
            ],
            "emotional": [
                "devastating", "heartbreaking", "thrilling", "exciting", "shocking",
                "alarming", "disturbing", "inspiring", "uplifting", "depressing",
                "frustrating", "infuriating", "delightful", "wonderful", "terrible"
            ],
            "persuasive": [
                "you must", "you should", "you need to", "you have to",
                "we must", "we should", "we need to", "it's essential",
                "it's crucial", "it's vital", "it's imperative", "don't forget"
            ],
            "stylistic": [
                "imagine", "picture this", "let me tell you", "here's the thing",
                "the bottom line", "at the end of the day", "when all is said and done",
                "truth be told", "to be honest", "frankly speaking"
            ],
            "rhythm_intensifiers": [
                "again and again", "over and over", "time and time again",
                "more and more", "bigger and bigger", "faster and faster",
                "round and round", "up and down", "back and forth"
            ]
        }

    def _analyze_tone(self, paragraphs: List[ParagraphAnalysis]) -> ToneAnalysis:
        """Analyze tone neutrality across content."""
        emotional_markers = []
        persuasion_scores = []
        objectivity_scores = []
        
        for para in paragraphs:
            content_lower = para.content.lower()
            
            # Count emotional markers
            para_emotional = []
            for marker in self.drift_markers["emotional"]:
                if marker in content_lower:
                    para_emotional.append(marker)
            emotional_markers.extend(para_emotional)
            
            # Calculate persuasion intensity
            persuasion_count = sum(1 for marker in self.drift_markers["persuasive"] 
                                 if marker in content_lower)
            persuasion_scores.append(min(persuasion_count / 5.0, 1.0))  # Normalize
            
            # Calculate objectivity (inverse of subjective markers)
            subjective_markers = self.drift_markers["rhetorical"] + self.drift_markers["stylistic"]
            subjective_count = sum(1 for marker in subjective_markers if marker in content_lower)
            objectivity_scores.append(max(0.0, 1.0 - (subjective_count / 10.0)))
        
        # Calculate overall metrics
        tone_neutrality = statistics.mean(objectivity_scores) if objectivity_scores else 0.0
        persuasion_intensity = statistics.mean(persuasion_scores) if persuasion_scores else 0.0
        objectivity_score = tone_neutrality
        
        return ToneAnalysis(
            tone_neutrality=tone_neutrality,
            emotional_markers=emotional_markers,
            persuasion_intensity=persuasion_intensity,
            objectivity_score=objectivity_score
        )

    def _analyze_rhythm(self, paragraphs: List[ParagraphAnalysis]) -> RhythmAnalysis:
        """Analyze rhythmic patterns that suggest stylistic rather than logical construction."""
        rhythm_patterns = []
        sentence_lengths = []
        
        for para in paragraphs:
            content = para.content
            sentences = self._split_sentences(content)
            
            # Collect sentence lengths for variation analysis
            para_lengths = [len(s.split()) for s in sentences]
            sentence_lengths.extend(para_lengths)
            
            # Check for rhythm intensifiers
            content_lower = content.lower()
            for marker in self.drift_markers["rhythm_intensifiers"]:
                if marker in content_lower:
                    rhythm_patterns.append(marker)
            
            # Check for repetitive patterns
            rhythm_patterns.extend(self._detect_repetitive_patterns(sentences))
            
            # Check for alliteration or assonance (style markers)
            rhythm_patterns.extend(self._detect_sound_patterns(sentences))
        
        # Calculate sentence variation
        sentence_variation = self._calculate_sentence_variation(sentence_lengths)
        
        # Calculate rhythm score (lower is better for logic-focused content)
        rhythm_score = min(len(rhythm_patterns) / 10.0, 1.0)
        rhythm_detected = rhythm_score > 0.3
        
        return RhythmAnalysis(
            rhythm_detected=rhythm_detected,
            rhythm_score=rhythm_score,
            rhythm_patterns=rhythm_patterns,
            sentence_variation=sentence_variation
        )

    def _detect_drift(self, paragraphs: List[ParagraphAnalysis], 
                     tone_analysis: ToneAnalysis, 
                     rhythm_analysis: RhythmAnalysis) -> DriftDetection:
        """Detect various forms of content drift."""
        drift_markers = []
        
        # Rhetorical drift detection
        rhetorical_count = 0
        for para in paragraphs:
            content_lower = para.content.lower()
            para_rhetorical = sum(1 for marker in self.drift_markers["rhetorical"] 
                                if marker in content_lower)
            rhetorical_count += para_rhetorical
        
        rhetorical_drift = rhetorical_count > len(paragraphs)  # More than 1 per paragraph average
        if rhetorical_drift:
            drift_markers.append("excessive_rhetorical_language")
        
        # Style drift detection
        style_count = 0
        for para in paragraphs:
            content_lower = para.content.lower()
            para_style = sum(1 for marker in self.drift_markers["stylistic"] 
                           if marker in content_lower)
            style_count += para_style
        
        style_drift = style_count > len(paragraphs) * 0.5  # More than 0.5 per paragraph
        if style_drift:
            drift_markers.append("stylistic_language_detected")
        
        # Emotional drift detection
        emotional_drift = len(tone_analysis.emotional_markers) > len(paragraphs)
        if emotional_drift:
            drift_markers.append("emotional_language_excessive")
        
        # Calculate overall drift severity
        drift_factors = [
            rhetorical_drift,
            style_drift, 
            emotional_drift,
            rhythm_analysis.rhythm_detected,
            tone_analysis.persuasion_intensity > 0.5
        ]
        drift_severity = sum(drift_factors) / len(drift_factors)
        
        return DriftDetection(
            rhetorical_drift=rhetorical_drift,
            style_drift=style_drift,
            emotional_drift=emotional_drift,
            drift_severity=drift_severity,
            drift_markers=drift_markers
        )

    def _detect_repetitive_patterns(self, sentences: List[str]) -> List[str]:
        """Detect repetitive sentence patterns that suggest rhythm over logic."""
        patterns = []
        
        if len(sentences) < 2:
            return patterns
        
        # Check for repeated sentence starters
        starters = [s.split()[:2] for s in sentences if len(s.split()) >= 2]
        starter_counts = {}
        for starter in starters:
            starter_key = ' '.join(starter).lower()
            starter_counts[starter_key] = starter_counts.get(starter_key, 0) + 1
        
        for starter, count in starter_counts.items():
            if count > 2:  # More than 2 sentences start the same way
                patterns.append(f"repeated_starter: {starter}")
        
        return patterns

    def _detect_sound_patterns(self, sentences: List[str]) -> List[str]:
        """Detect alliteration or other sound patterns that suggest style focus."""
        patterns = []
        
        for sentence in sentences:
            words = sentence.lower().split()
            if len(words) < 3:
                continue
            
            # Simple alliteration detection
            first_letters = [word[0] for word in words if word.isalpha()]
            if len(first_letters) >= 3:
                for i in range(len(first_letters) - 2):
                    if (first_letters[i] == first_letters[i+1] == first_letters[i+2]):
                        patterns.append(f"alliteration_detected: {first_letters[i]}")
                        break
        
        return patterns

    def _calculate_sentence_variation(self, sentence_lengths: List[int]) -> float:
        """Calculate sentence length variation (too much variation suggests style focus)."""
        if len(sentence_lengths) < 2:
            return 0.0
        
        mean_length = statistics.mean(sentence_lengths)
        if mean_length == 0:
            return 0.0
        
        # Calculate coefficient of variation
        std_dev = statistics.stdev(sentence_lengths)
        coefficient_of_variation = std_dev / mean_length
        
        # Return normalized variation (0-1 scale)
        return min(coefficient_of_variation, 1.0)

    def _needs_suppression(self, tone_analysis: ToneAnalysis, 
                          rhythm_analysis: RhythmAnalysis, 
                          drift_detection: DriftDetection) -> bool:
        """Determine if suppression is needed."""
        suppression_triggers = [
            tone_analysis.tone_neutrality < 0.6,
            rhythm_analysis.rhythm_detected,
            drift_detection.drift_severity > 0.4,
            tone_analysis.persuasion_intensity > 0.5
        ]
        
        return sum(suppression_triggers) >= 2  # At least 2 triggers

    def _calculate_suppression_score(self, tone_analysis: ToneAnalysis,
                                   rhythm_analysis: RhythmAnalysis,
                                   drift_detection: DriftDetection) -> float:
        """Calculate overall suppression score (0=no suppression needed, 1=maximum suppression)."""
        # Invert tone neutrality (low neutrality = high suppression need)
        tone_factor = 1.0 - tone_analysis.tone_neutrality
        
        # Rhythm score directly indicates suppression need
        rhythm_factor = rhythm_analysis.rhythm_score
        
        # Drift severity directly indicates suppression need
        drift_factor = drift_detection.drift_severity
        
        # Persuasion intensity indicates suppression need
        persuasion_factor = tone_analysis.persuasion_intensity
        
        # Weighted average
        weights = [0.3, 0.2, 0.3, 0.2]  # tone, rhythm, drift, persuasion
        factors = [tone_factor, rhythm_factor, drift_factor, persuasion_factor]
        
        return sum(w * f for w, f in zip(weights, factors))

    def _generate_recommendations(self, tone_analysis: ToneAnalysis,
                                rhythm_analysis: RhythmAnalysis,
                                drift_detection: DriftDetection) -> List[str]:
        """Generate suppression recommendations."""
        recommendations = []
        
        # Tone recommendations
        if tone_analysis.tone_neutrality < 0.6:
            recommendations.append("Increase tone neutrality by removing subjective language")
        
        if tone_analysis.emotional_markers:
            recommendations.append("Replace emotional language with objective descriptions")
        
        if tone_analysis.persuasion_intensity > 0.5:
            recommendations.append("Reduce persuasive language in favor of informational presentation")
        
        # Rhythm recommendations
        if rhythm_analysis.rhythm_detected:
            recommendations.append("Eliminate rhythmic patterns that prioritize sound over logic")
        
        if rhythm_analysis.sentence_variation > 0.7:
            recommendations.append("Standardize sentence structure for logical consistency")
        
        # Drift recommendations
        if drift_detection.rhetorical_drift:
            recommendations.append("Remove rhetorical embellishments and focus on logical content")
        
        if drift_detection.style_drift:
            recommendations.append("Eliminate stylistic devices that distract from logical flow")
        
        if drift_detection.emotional_drift:
            recommendations.append("Replace emotional appeals with factual presentation")
        
        # Specific pattern recommendations
        for marker in drift_detection.drift_markers:
            if "rhetorical" in marker:
                recommendations.append("Reduce use of rhetorical intensifiers")
            elif "stylistic" in marker:
                recommendations.append("Remove conversational and stylistic elements")
            elif "emotional" in marker:
                recommendations.append("Maintain emotional neutrality in presentation")
        
        return list(set(recommendations))  # Remove duplicates

    def _split_sentences(self, text: str) -> List[str]:
        """Split text into sentences."""
        sentence_endings = r'[.!?]+(?:\s+|$)'
        sentences = re.split(sentence_endings, text)
        return [s.strip() for s in sentences if s.strip()]

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat()

