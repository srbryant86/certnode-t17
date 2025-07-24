#!/usr/bin/env python3
"""
CertNode CLI Interface
Command-line interface for content certification and verification.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional
import time

from certnode_config import CertNodeConfig, CertNodeLogger
from certnode_processor import CertNodeProcessor, CertificationRequest
from vault_manager import VaultManager
from ics_generator import ICSGenerator

class CertNodeCLI:
    """Command-line interface for CertNode operations."""

    def __init__(self):
        self.config = CertNodeConfig()
        self.logger = CertNodeLogger("CLI")
        self.processor = CertNodeProcessor()
        self.vault = VaultManager()
        self.ics_generator = ICSGenerator()

    def certify_content(self, args) -> int:
        """Certify content from file or stdin."""
        try:
            # Read content
            if args.file and args.file != '-':
                content_path = Path(args.file)
                if not content_path.exists():
                    print(f"Error: File '{args.file}' not found", file=sys.stderr)
                    return 1
                
                with open(content_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                title = args.title or content_path.stem
            else:
                # Read from stdin
                content = sys.stdin.read()
                title = args.title or "stdin_content"
            
            if len(content.strip()) < 100:
                print("Error: Content too short (minimum 100 characters)", file=sys.stderr)
                return 1
            
            # Create certification request
            request = CertificationRequest(
                content=content,
                cert_type=args.cert_type,
                author_id=args.author_id,
                author_name=args.author_name,
                title=title
            )
            
            # Process certification
            print(f"Certifying content: {title}")
            print(f"Content length: {len(content)} characters")
            print(f"Certification type: {args.cert_type}")
            
            start_time = time.time()
            result = self.processor.certify_content(request)
            end_time = time.time()
            
            # Display results
            if result.success:
                print("\n✅ CERTIFICATION SUCCESSFUL")
                print(f"Certificate ID: {result.cert_id}")
                print(f"ICS Hash: {result.ics_signature.fingerprint.combined_hash}")
                print(f"Certification Score: {result.certification_score:.3f}")
                print(f"Processing Time: {end_time - start_time:.2f}s")
                
                if result.ics_signature:
                    print(f"Verification URL: {result.ics_signature.verification_data['verification_url']}")
                
                # Store in vault
                if result.ics_signature:
                    vault_stored = self.vault.store_certification(result.ics_signature)
                    if vault_stored:
                        print("✅ Stored in vault")
                    else:
                        print("⚠️  Vault storage failed")
                
                # Save output files
                if args.output_dir:
                    output_dir = Path(args.output_dir)
                    output_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Save certified content
                    cert_file = output_dir / f"{result.cert_id}_certified.txt"
                    with open(cert_file, 'w', encoding='utf-8') as f:
                        f.write(self._create_certified_output(content, result.ics_signature))
                    
                    # Save signature
                    sig_file = output_dir / f"{result.cert_id}_signature.json"
                    with open(sig_file, 'w', encoding='utf-8') as f:
                        json.dump(result.ics_signature.to_dict(), f, indent=2)
                    
                    print(f"✅ Output saved to {output_dir}")
                
                return 0
            else:
                print("\n❌ CERTIFICATION FAILED")
                print(f"Score: {result.certification_score:.3f}")
                print(f"Threshold: {self.config.CERTIFICATION_THRESHOLD}")
                
                if result.issues:
                    print("\nIssues identified:")
                    for i, issue in enumerate(result.issues, 1):
                        print(f"{i}. {issue}")
                
                return 1
                
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            return 1

    def verify_content(self, args) -> int:
        """Verify content against certification."""
        try:
            # Read content
            if args.file and args.file != '-':
                content_path = Path(args.file)
                if not content_path.exists():
                    print(f"Error: File '{args.file}' not found", file=sys.stderr)
                    return 1
                
                with open(content_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            else:
                content = sys.stdin.read()
            
            # Calculate content hash
            import hashlib
            content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            
            # Verify against vault
            if args.cert_id:
                verified = self.vault.verify_certification(args.cert_id, content_hash)
                if verified:
                    print("✅ VERIFICATION SUCCESSFUL")
                    print(f"Certificate ID: {args.cert_id}")
                    print(f"Content hash matches vault record")
                    return 0
                else:
                    print("❌ VERIFICATION FAILED")
                    print(f"Certificate ID: {args.cert_id}")
                    print("Content hash does not match vault record")
                    return 1
            
            # Check for drift
            if args.drift_check:
                drift_result = self.vault.detect_drift(args.cert_id, content)
                if drift_result.get("drift_detected"):
                    print("⚠️  CONTENT DRIFT DETECTED")
                    print(f"Drift severity: {drift_result['drift_severity']:.3f}")
                    print(f"Original hash: {drift_result['original_hash']}")
                    print(f"Current hash: {drift_result['current_hash']}")
                    return 1
                else:
                    print("✅ NO DRIFT DETECTED")
                    return 0
            
            print("Error: Must specify --cert-id for verification", file=sys.stderr)
            return 1
            
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            return 1

    def list_certifications(self, args) -> int:
        """List certifications in vault."""
        try:
            certifications = self.vault.list_certifications(
                limit=args.limit,
                offset=args.offset
            )
            
            if not certifications:
                print("No certifications found")
                return 0
            
            print(f"Found {len(certifications)} certifications:")
            print()
            
            for cert in certifications:
                print(f"ID: {cert['cert_id']}")
                print(f"Type: {cert['cert_type']}")
                print(f"Timestamp: {cert['timestamp']}")
                print("-" * 40)
            
            return 0
            
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            return 1

    def vault_status(self, args) -> int:
        """Display vault status."""
        try:
            print("🗄️  CertNode Vault Status")
            print("=" * 30)
            
            available = self.vault.is_available()
            print(f"Status: {'Available' if available else 'Unavailable'}")
            
            if available:
                count = self.vault.get_certification_count()
                print(f"Total certifications: {count}")
                print(f"Database path: {self.vault.db_path}")
            
            return 0
            
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            return 1

    def _create_certified_output(self, content: str, signature: 'ICSSignature') -> str:
        """Create certified content output."""
        return f"""# CERTIFIED CONTENT
# CertNode T17+ Logic Governance Infrastructure
# Certificate ID: {signature.cert_id}
# ICS Hash: {signature.fingerprint.combined_hash}
# Timestamp: {signature.timestamp}
# Verification URL: {signature.verification_data.get('verification_url', 'N/A')}

{content}

# END CERTIFIED CONTENT
# This content has been certified by CertNode T17+ Logic Governance Infrastructure
# Verification: python3 certnode_cli.py verify --cert-id {signature.cert_id} <content_file>
"""

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CertNode T17+ Logic Governance Infrastructure CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Certify content
  certnode_cli.py certify document.txt --author-id "john_doe"
  
  # Certify with output
  certnode_cli.py certify document.txt --output-dir ./certified/
  
  # Verify content
  certnode_cli.py verify document.txt --cert-id abc123...
  
  # Check for drift
  certnode_cli.py verify document.txt --cert-id abc123... --drift-check
  
  # List certifications
  certnode_cli.py list --limit 10
  
  # Vault status
  certnode_cli.py vault-status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Certify command
    certify_parser = subparsers.add_parser('certify', help='Certify content')
    certify_parser.add_argument('file', nargs='?', default='-', 
                               help='Content file (use - for stdin)')
    certify_parser.add_argument('--cert-type', default='LOGIC_FRAGMENT',
                               choices=['LOGIC_FRAGMENT', 'FULL_DOCUMENT', 'RESEARCH_PAPER'],
                               help='Certification type')
    certify_parser.add_argument('--author-id', help='Author identifier')
    certify_parser.add_argument('--author-name', help='Author name')
    certify_parser.add_argument('--title', help='Content title')
    certify_parser.add_argument('--output-dir', help='Output directory for certified files')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify content')
    verify_parser.add_argument('file', nargs='?', default='-',
                              help='Content file (use - for stdin)')
    verify_parser.add_argument('--cert-id', required=True,
                              help='Certificate ID to verify against')
    verify_parser.add_argument('--drift-check', action='store_true',
                              help='Check for content drift')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List certifications')
    list_parser.add_argument('--limit', type=int, default=20,
                            help='Maximum number of results')
    list_parser.add_argument('--offset', type=int, default=0,
                            help='Offset for pagination')
    
    # Vault status command
    subparsers.add_parser('vault-status', help='Display vault status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = CertNodeCLI()
    
    if args.command == 'certify':
        return cli.certify_content(args)
    elif args.command == 'verify':
        return cli.verify_content(args)
    elif args.command == 'list':
        return cli.list_certifications(args)
    elif args.command == 'vault-status':
        return cli.vault_status(args)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())

