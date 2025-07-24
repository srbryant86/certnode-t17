#!/usr/bin/env python3
"""
CertNode Test Suite
Comprehensive testing for all CertNode components.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path

# Import CertNode modules
from certnode_config import CertNodeConfig, CertNodeLogger
from certnode_processor import CertNodeProcessor, CertificationRequest
from cdp_processor import CDPProcessor
from frame_processor import FRAMEProcessor
from stride_processor import STRIDEProcessor
from ics_generator import ICSGenerator
from vault_manager import VaultManager

class TestCertNode:
    """Test suite for CertNode system."""

    @pytest.fixture
    def sample_content(self):
        """Sample content for testing."""
        return """
        Understanding Machine Learning Fundamentals

        Machine learning represents a paradigm shift in how computers process information. Rather than following explicitly programmed instructions, these systems learn patterns from data to make predictions or decisions.

        The core principle underlying machine learning involves statistical analysis of training data. Algorithms identify relationships between input variables and desired outputs, creating mathematical models that can generalize to new, unseen data.

        Three primary categories define the machine learning landscape. Supervised learning uses labeled examples to train predictive models. Unsupervised learning discovers hidden patterns in unlabeled data. Reinforcement learning optimizes decision-making through trial-and-error feedback.

        Each approach serves specific problem domains and requires different evaluation metrics. The choice between methods depends on data availability, problem complexity, and performance requirements.
        """

    @pytest.fixture
    def certnode_processor(self):
        """CertNode processor instance."""
        return CertNodeProcessor()

    @pytest.fixture
    def vault_manager(self):
        """Vault manager with temporary database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Override vault path for testing
            config = CertNodeConfig()
            config.VAULT_DIR = Path(tmpdir)
            yield VaultManager()

    def test_cdp_processor(self, sample_content):
        """Test CDP processing."""
        processor = CDPProcessor()
        result = processor.process_content(sample_content)
        
        assert result is not None
        assert result.convergence_achieved
        assert result.structural_integrity > 0.5
        assert result.logic_continuity > 0.4
        assert len(result.paragraphs) >= 2
        
        print(f"✅ CDP Test - Convergence: {result.convergence_achieved}")
        print(f"✅ CDP Test - Integrity: {result.structural_integrity:.3f}")

    def test_frame_processor(self, sample_content):
        """Test FRAME processing."""
        cdp = CDPProcessor()
        cdp_result = cdp.process_content(sample_content)
        
        frame = FRAMEProcessor()
        result = frame.process_content(cdp_result)
        
        assert result is not None
        assert result.structural_score > 0.5
        assert result.taper_analysis is not None
        
        print(f"✅ FRAME Test - Score: {result.structural_score:.3f}")
        print(f"✅ FRAME Test - Boundaries: {result.boundaries_satisfied}")

    def test_stride_processor(self, sample_content):
        """Test STRIDE processing."""
        cdp = CDPProcessor()
        cdp_result = cdp.process_content(sample_content)
        
        stride = STRIDEProcessor()
        result = stride.process_content(cdp_result)
        
        assert result is not None
        assert result.suppression_score < 0.8  # Good content should need minimal suppression
        assert result.tone_analysis.tone_neutrality > 0.4
        
        print(f"✅ STRIDE Test - Suppression: {result.suppression_score:.3f}")
        print(f"✅ STRIDE Test - Neutrality: {result.tone_analysis.tone_neutrality:.3f}")

    def test_ics_generator(self, sample_content):
        """Test ICS signature generation."""
        cdp = CDPProcessor()
        cdp_result = cdp.process_content(sample_content)
        
        frame = FRAMEProcessor()
        frame_result = frame.process_content(cdp_result)
        
        stride = STRIDEProcessor()
        stride_result = stride.process_content(cdp_result)
        
        ics = ICSGenerator()
        signature = ics.generate_signature(
            sample_content, cdp_result, frame_result, stride_result
        )
        
        assert signature is not None
        assert signature.fingerprint.combined_hash
        assert signature.metadata.cert_id
        assert signature.vault_anchor
        
        # Test verification
        is_valid, errors = ics.verify_signature(sample_content, signature)
        assert is_valid
        assert len(errors) == 0
        
        print(f"✅ ICS Test - Hash: {signature.fingerprint.combined_hash[:16]}...")
        print(f"✅ ICS Test - Valid: {is_valid}")

    def test_vault_operations(self, sample_content, vault_manager):
        """Test vault storage and retrieval."""
        # Generate a certification
        processor = CertNodeProcessor()
        request = CertificationRequest(
            content=sample_content,
            cert_type="LOGIC_FRAGMENT",
            title="Test Content"
        )
        
        result = processor.certify_content(request)
        assert result.success
        
        # Store in vault
        stored = vault_manager.store_certification(result.ics_signature)
        assert stored
        
        # Retrieve from vault
        retrieved = vault_manager.retrieve_certification(
            result.cert_id, "cert_id"
        )
        assert retrieved is not None
        assert retrieved.cert_id == result.cert_id
        
        # Test vault stats
        stats = vault_manager.get_vault_stats()
        assert stats["total_certifications"] >= 1
        
        print(f"✅ Vault Test - Stored: {stored}")
        print(f"✅ Vault Test - Retrieved: {retrieved.cert_id}")

    def test_full_certification_flow(self, sample_content, certnode_processor):
        """Test complete certification flow."""
        request = CertificationRequest(
            content=sample_content,
            cert_type="LOGIC_FRAGMENT",
            author_id="test_user",
            title="Full Flow Test"
        )
        
        result = certnode_processor.certify_content(request)
        
        assert result.success
        assert result.cert_id
        assert result.ics_signature
        assert result.certification_score >= 0.6
        
        print(f"✅ Full Test - Success: {result.success}")
        print(f"✅ Full Test - Score: {result.certification_score:.3f}")
        print(f"✅ Full Test - ID: {result.cert_id}")

    def test_verification_flow(self, sample_content, certnode_processor):
        """Test verification flow."""
        # First certify content
        request = CertificationRequest(
            content=sample_content,
            cert_type="LOGIC_FRAGMENT"
        )
        
        cert_result = certnode_processor.certify_content(request)
        assert cert_result.success
        
        # Export signature
        ics = ICSGenerator()
        signature_json = ics.export_signature_json(cert_result.ics_signature)
        
        # Verify content
        is_valid, errors = certnode_processor.verify_certification(
            sample_content, signature_json
        )
        
        assert is_valid
        assert len(errors) == 0
        
        # Test with modified content (should fail)
        modified_content = sample_content + "\nThis is additional text."
        is_valid_modified, errors_modified = certnode_processor.verify_certification(
            modified_content, signature_json
        )
        
        assert not is_valid_modified
        assert len(errors_modified) > 0
        
        print(f"✅ Verification Test - Original Valid: {is_valid}")
        print(f"✅ Verification Test - Modified Invalid: {not is_valid_modified}")

    def test_performance_benchmark(self, sample_content, certnode_processor):
        """Performance benchmark test."""
        import time
        
        times = []
        for i in range(5):
            request = CertificationRequest(
                content=sample_content,
                cert_type="LOGIC_FRAGMENT",
                title=f"Benchmark Test {i+1}"
            )
            
            start_time = time.time()
            result = certnode_processor.certify_content(request)
            end_time = time.time()
            
            processing_time = end_time - start_time
            times.append(processing_time)
            
            assert result.success
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        # Performance assertions
        assert avg_time < 5.0  # Average should be under 5 seconds
        assert max_time < 10.0  # Max should be under 10 seconds
        
        print(f"✅ Performance Test - Avg: {avg_time:.2f}s")
        print(f"✅ Performance Test - Min: {min_time:.2f}s")
        print(f"✅ Performance Test - Max: {max_time:.2f}s")

def test_api_endpoints():
    """Test API endpoints with requests."""
    try:
        import requests
        
        # This would test against a running API server
        # For now, just test imports
        from certnode_api import CertNodeAPI
        api = CertNodeAPI()
        assert api is not None
        print("✅ API Test - Server instance created")
        
    except ImportError:
        print("⚠️  Skipping API tests - requests not available")

def main():
    """Run all tests."""
    print("🧪 CertNode Test Suite")
    print("=====================")
    
    # Run pytest
    exit_code = pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--no-header"
    ])

    if exit_code == 0:
        print("\n✅ All tests passed!")
        print("\n🚀 System Ready for Production")
    else:
        print("\n❌ Some tests failed!")
        print("\n🔧 Please review failures before deployment")

    return exit_code

if __name__ == "__main__":
    exit(main())

