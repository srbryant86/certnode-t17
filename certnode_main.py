#!/usr/bin/env python3
"""
CertNode Main Entry Point
Primary interface for the CertNode certification system.
"""

import sys
import os
import argparse
import json
from pathlib import Path
from typing import Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from certnode_config import CertNodeConfig, CertNodeLogger
from certnode_processor import CertNodeProcessor, CertificationRequest
from vault_manager import VaultManager
from badge_generator import BadgeGenerator
from ics_generator import ICSGenerator

class CertNodeMain:
    """Main CertNode system controller."""
    
    def __init__(self):
        self.config = CertNodeConfig()
        self.logger = CertNodeLogger("Main")
        self.processor = CertNodeProcessor()
        self.vault = VaultManager()
        self.badge_generator = BadgeGenerator()
        self.ics_generator = ICSGenerator()
        
        print(f"CertNode v{self.config.CERTNODE_VERSION}")
        print(f"Operator: {self.config.OPERATOR}")
        print()
    
    def quick_certify(self, content: str, title: Optional[str] = None) -> bool:
        """Quick certification with minimal output."""
        try:
            request = CertificationRequest(
                content=content,
                cert_type="LOGIC_FRAGMENT",
                title=title
            )
            
            print("Processing certification...")
            result = self.processor.certify_content(request)
            
            if result.success:
                print(f"✅ CERTIFIED - ID: {result.cert_id}")
                print(f"   Score: {result.certification_score:.3f}")
                print(f"   Hash: {result.ics_signature.fingerprint.combined_hash}")
                
                # Store in vault
                self.vault.store_certification(result.ics_signature)
                print("   Stored in vault")
                
                return True
            else:
                print(f"❌ FAILED - Score: {result.certification_score:.3f}")
                if result.issues:
                    print("   Issues:")
                    for issue in result.issues[:3]:  # Show top 3
                        print(f"   • {issue}")
                return False
                
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            return False
    
    def detailed_certify(self, content: str, cert_type: str = "LOGIC_FRAGMENT",
                        author_id: Optional[str] = None, title: Optional[str] = None,
                        export_badges: bool = False) -> bool:
        """Detailed certification with full analysis."""
        try:
            request = CertificationRequest(
                content=content,
                cert_type=cert_type,
                author_id=author_id,
                title=title
            )
            
            print("Running detailed certification analysis...")
            print(f"Content length: {len(content)} characters")
            print(f"Word count: {len(content.split())} words")
            print(f"Certification type: {cert_type}")
            print()
            
            result = self.processor.certify_content(request)
            
            # Display CDP results
            if result.cdp_result:
                print("📊 CDP ANALYSIS:")
                print(f"   Overall slope: {result.cdp_result.overall_slope}")
                print(f"   Structural integrity: {result.cdp_result.structural_integrity:.3f}")
                print(f"   Logic continuity: {result.cdp_result.logic_continuity:.3f}")
                print(f"   Convergence achieved: {result.cdp_result.convergence_achieved}")
                print(f"   Paragraphs analyzed: {len(result.cdp_result.paragraphs)}")
                print()
            
            # Display FRAME results
            if result.frame_result:
                print("🔍 FRAME ANALYSIS:")
                print(f"   Structural score: {result.frame_result.structural_score:.3f}")
                print(f"   Logical consistency: {result.frame_result.logical_consistency:.3f}")
                print(f"   Evidence quality: {result.frame_result.evidence_quality:.3f}")
                print(f"   Reasoning clarity: {result.frame_result.reasoning_clarity:.3f}")
                print()
            
            # Display STRIDE results
            if result.stride_result:
                print("⚡ STRIDE ANALYSIS:")
                print(f"   Optimization score: {result.stride_result.optimization_score:.3f}")
                print(f"   Performance gain: {result.stride_result.performance_gain:.3f}")
                print(f"   Efficiency rating: {result.stride_result.efficiency_rating:.3f}")
                print()
            
            # Display final result
            if result.success:
                print(f"✅ CERTIFICATION SUCCESSFUL")
                print(f"   Certificate ID: {result.cert_id}")
                print(f"   Overall Score: {result.certification_score:.3f}")
                print(f"   ICS Hash: {result.ics_signature.fingerprint.combined_hash}")
                print(f"   Timestamp: {result.ics_signature.timestamp}")
                
                # Store in vault
                self.vault.store_certification(result.ics_signature)
                print("   ✓ Stored in vault")
                
                # Generate badges if requested
                if export_badges:
                    badge_path = self.badge_generator.generate_badge(result.ics_signature)
                    print(f"   ✓ Badge generated: {badge_path}")
                
                return True
            else:
                print(f"❌ CERTIFICATION FAILED")
                print(f"   Score: {result.certification_score:.3f}")
                print(f"   Threshold: {self.config.CERTIFICATION_THRESHOLD}")
                
                if result.issues:
                    print("   Issues identified:")
                    for i, issue in enumerate(result.issues, 1):
                        print(f"   {i}. {issue}")
                
                return False
                
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CertNode T17+ Logic Governance Infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 certnode_main.py --quick-certify content.txt
  python3 certnode_main.py --detailed-certify content.txt --export-badges
  python3 certnode_main.py --interactive
  python3 certnode_main.py --system-info
        """
    )
    
    parser.add_argument('--quick-certify', metavar='FILE',
                       help='Quick certification of content file')
    parser.add_argument('--detailed-certify', metavar='FILE',
                       help='Detailed certification with full analysis')
    parser.add_argument('--cert-type', default='LOGIC_FRAGMENT',
                       choices=['LOGIC_FRAGMENT', 'FULL_DOCUMENT', 'RESEARCH_PAPER'],
                       help='Certification type (default: LOGIC_FRAGMENT)')
    parser.add_argument('--author-id', help='Author identifier')
    parser.add_argument('--title', help='Content title')
    parser.add_argument('--export-badges', action='store_true',
                       help='Generate certification badges')
    parser.add_argument('--interactive', action='store_true',
                       help='Start interactive mode')
    parser.add_argument('--system-info', action='store_true',
                       help='Display system information')
    parser.add_argument('--version', action='version', version='CertNode 2.0.0')
    
    args = parser.parse_args()
    
    # Initialize CertNode
    certnode = CertNodeMain()
    
    if args.system_info:
        print("🏛️ CertNode T17+ Logic Governance Infrastructure")
        print("=" * 50)
        print(f"Version: {certnode.config.CERTNODE_VERSION}")
        print(f"Operator: {certnode.config.OPERATOR}")
        print(f"Environment: {certnode.config.ENVIRONMENT}")
        print(f"Vault Path: {certnode.config.VAULT_PATH}")
        print(f"Certification Threshold: {certnode.config.CERTIFICATION_THRESHOLD}")
        print(f"Debug Mode: {certnode.config.DEBUG}")
        print()
        
        # System status
        vault_status = "✓ Available" if certnode.vault.is_available() else "✗ Unavailable"
        print(f"Vault Status: {vault_status}")
        
        cert_count = certnode.vault.get_certification_count()
        print(f"Stored Certifications: {cert_count}")
        
        return
    
    if args.interactive:
        print("🔧 CertNode Interactive Mode")
        print("Type 'help' for commands, 'exit' to quit")
        print()
        
        while True:
            try:
                command = input("certnode> ").strip()
                
                if command == 'exit':
                    break
                elif command == 'help':
                    print("Available commands:")
                    print("  certify <text>     - Quick certification")
                    print("  status            - System status")
                    print("  vault             - Vault information")
                    print("  exit              - Exit interactive mode")
                elif command == 'status':
                    print(f"System: Operational")
                    print(f"Vault: {'Available' if certnode.vault.is_available() else 'Unavailable'}")
                    print(f"Certifications: {certnode.vault.get_certification_count()}")
                elif command == 'vault':
                    certifications = certnode.vault.list_certifications(limit=5)
                    print(f"Recent certifications ({len(certifications)}):")
                    for cert in certifications:
                        print(f"  {cert['cert_id']} - {cert['timestamp']}")
                elif command.startswith('certify '):
                    content = command[8:]  # Remove 'certify '
                    certnode.quick_certify(content)
                else:
                    print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except EOFError:
                break
        
        return
    
    if args.quick_certify:
        if not os.path.exists(args.quick_certify):
            print(f"❌ File not found: {args.quick_certify}")
            return 1
        
        with open(args.quick_certify, 'r', encoding='utf-8') as f:
            content = f.read()
        
        success = certnode.quick_certify(content, args.title)
        return 0 if success else 1
    
    if args.detailed_certify:
        if not os.path.exists(args.detailed_certify):
            print(f"❌ File not found: {args.detailed_certify}")
            return 1
        
        with open(args.detailed_certify, 'r', encoding='utf-8') as f:
            content = f.read()
        
        success = certnode.detailed_certify(
            content, 
            args.cert_type, 
            args.author_id, 
            args.title,
            args.export_badges
        )
        return 0 if success else 1
    
    # No arguments provided
    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())

