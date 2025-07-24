#!/usr/bin/env python3
"""
CertNode API Server
HTTP API server for content certification and verification.
"""

import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
import traceback

try:
    from flask import Flask, request, jsonify, Response
    from flask_cors import CORS
    from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
except ImportError:
    print("Flask not installed. Install with: pip install flask flask-cors")
    exit(1)

from certnode_config import CertNodeConfig, CertNodeLogger
from certnode_processor import CertNodeProcessor, CertificationRequest
from vault_manager import VaultManager
from ics_generator import ICSGenerator

class CertNodeAPI:
    """CertNode HTTP API server."""

    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for web integration
        
        self.config = CertNodeConfig()
        self.logger = CertNodeLogger("API")
        self.processor = CertNodeProcessor()
        self.vault = VaultManager()
        self.ics_generator = ICSGenerator()
        
        # Rate limiting (simple in-memory)
        self.rate_limits = {}
        self.rate_limit_window = 3600  # 1 hour
        self.rate_limit_max = 100  # requests per hour
        
        self._setup_routes()
        self.logger.info("CertNode API server initialized")

    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.before_request
        def before_request():
            """Pre-request processing."""
            # Rate limiting
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Clean old entries
            cutoff_time = current_time - self.rate_limit_window
            self.rate_limits = {ip: times for ip, times in self.rate_limits.items() 
                               if any(t > cutoff_time for t in times)}
            
            # Check rate limit
            if client_ip in self.rate_limits:
                recent_requests = [t for t in self.rate_limits[client_ip] if t > cutoff_time]
                if len(recent_requests) >= self.rate_limit_max:
                    return jsonify({
                        "error": "Rate limit exceeded",
                        "message": f"Maximum {self.rate_limit_max} requests per hour"
                    }), 429
                self.rate_limits[client_ip] = recent_requests + [current_time]
            else:
                self.rate_limits[client_ip] = [current_time]
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({
                "error": "Bad Request",
                "message": str(error.description)
            }), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not Found",
                "message": "Resource not found"
            }), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred"
            }), 500
        
        # API Routes
        self.app.add_url_rule('/api/v1/certify', 'certify', self.certify_content, methods=['POST'])
        self.app.add_url_rule('/api/v1/verify', 'verify', self.verify_content, methods=['POST'])
        self.app.add_url_rule('/api/v1/verify/<ics_hash>', 'verify_hash', self.verify_by_hash, methods=['GET'])
        self.app.add_url_rule('/api/v1/badge/<cert_id>', 'badge', self.get_badge, methods=['GET'])
        self.app.add_url_rule('/api/v1/status', 'status', self.get_status, methods=['GET'])
        self.app.add_url_rule('/api/v1/vault/stats', 'vault_stats', self.get_vault_stats, methods=['GET'])
        self.app.add_url_rule('/api/v1/vault/search', 'vault_search', self.search_vault, methods=['GET'])
        
        # Health check
        self.app.add_url_rule('/health', 'health', self.health_check, methods=['GET'])
        
        # Root endpoint
        self.app.add_url_rule('/', 'root', self.api_info, methods=['GET'])

    def certify_content(self):
        """POST /api/v1/certify - Certify content."""
        try:
            data = request.get_json()
            if not data:
                raise BadRequest("JSON body required")
            
            # Validate required fields
            if 'content' not in data:
                raise BadRequest("'content' field required")
            
            content = data['content']
            if len(content.strip()) < 100:
                raise BadRequest("Content too short (minimum 100 characters)")
            
            cert_type = data.get('cert_type', 'LOGIC_FRAGMENT')
            if cert_type not in self.config.CERT_TYPES:
                raise BadRequest(f"Invalid cert_type. Must be one of: {list(self.config.CERT_TYPES.keys())}")
            
            # Create certification request
            request_obj = CertificationRequest(
                content=content,
                cert_type=cert_type,
                author_id=data.get('author_id'),
                author_name=data.get('author_name'),
                title=data.get('title'),
                metadata=data.get('metadata')
            )
            
            # Process certification
            start_time = time.time()
            result = self.processor.certify_content(request_obj)
            processing_time = time.time() - start_time
            
            # Store in vault if successful
            if result.success and result.ics_signature:
                vault_stored = self.vault.store_certification(result.ics_signature)
                if not vault_stored:
                    self.logger.warning("Failed to store certification in vault", {
                        "cert_id": result.cert_id
                    })
            
            # Build response
            response_data = {
                "success": result.success,
                "cert_id": result.cert_id,
                "certification_score": round(result.certification_score, 3),
                "processing_time": round(processing_time, 3),
                "issues": result.issues,
                "recommendations": result.recommendations
            }
            
            if result.success and result.ics_signature:
                response_data.update({
                    "ics_hash": result.ics_signature.fingerprint.combined_hash,
                    "verification_url": result.ics_signature.verification_data['verification_url'],
                    "badge_url": result.ics_signature.verification_data['badge_url'],
                    "vault_anchor": result.ics_signature.vault_anchor,
                    "analysis_summary": result.ics_signature.analysis_summary
                })
            
            status_code = 200 if result.success else 422
            
            self.logger.info("Content certification completed via API", {
                "success": result.success,
                "cert_id": result.cert_id,
                "processing_time": processing_time,
                "client_ip": request.remote_addr
            })
            
            return jsonify(response_data), status_code
            
        except BadRequest:
            raise
        except Exception as e:
            self.logger.error(f"API certification failed: {str(e)}")
            raise InternalServerError(f"Certification processing failed: {str(e)}")

    def verify_content(self):
        """POST /api/v1/verify - Verify content against certification."""
        try:
            data = request.get_json()
            if not data:
                raise BadRequest("JSON body required")
            
            if 'content' not in data:
                raise BadRequest("'content' field required")
            
            content = data['content']
            
            # Get signature data
            if 'signature_data' in data:
                signature_data = data['signature_data']
                if isinstance(signature_data, dict):
                    signature_data = json.dumps(signature_data)
            elif 'ics_hash' in data:
                # Look up in vault
                entry = self.vault.retrieve_certification(data['ics_hash'], "ics_hash")
                if not entry:
                    return jsonify({
                        "valid": False,
                        "errors": [f"No certification found for hash {data['ics_hash']}"]
                    }), 404
                signature_data = json.dumps(entry.metadata)
            else:
                raise BadRequest("Either 'signature_data' or 'ics_hash' required")
            
            # Verify
            is_valid, errors = self.processor.verify_certification(content, signature_data)
            
            response_data = {
                "valid": is_valid,
                "errors": errors
            }
            
            if is_valid:
                # Parse signature for additional info
                try:
                    signature = self.ics_generator.import_signature_json(signature_data)
                    response_data.update({
                        "cert_id": signature.metadata.cert_id,
                        "issued_date": signature.metadata.timestamp,
                        "cert_type": signature.metadata.content_type,
                        "operator": signature.metadata.operator
                    })
                    
                    # Check for drift if requested
                    if data.get('check_drift', False):
                        drift_alert = self.vault.detect_content_drift(
                            signature.metadata.cert_id, content
                        )
                        response_data["drift_detected"] = drift_alert is not None
                        if drift_alert:
                            response_data["drift_severity"] = drift_alert.drift_severity
                
                except Exception as e:
                    self.logger.warning(f"Failed to parse signature for additional info: {str(e)}")
            
            self.logger.info("Content verification completed via API", {
                "valid": is_valid,
                "client_ip": request.remote_addr
            })
            
            return jsonify(response_data)
            
        except BadRequest:
            raise
        except Exception as e:
            self.logger.error(f"API verification failed: {str(e)}")
            raise InternalServerError(f"Verification failed: {str(e)}")

    def verify_by_hash(self, ics_hash: str):
        """GET /api/v1/verify/{hash} - Verify certification by hash only."""
        try:
            # Validate hash format
            if not ics_hash or len(ics_hash) != 64:
                raise BadRequest("Invalid ICS hash format")
            
            # Look up in vault
            entry = self.vault.retrieve_certification(ics_hash, "ics_hash")
            if not entry:
                return jsonify({
                    "valid": False,
                    "errors": ["No certification found for this hash"]
                }), 404
            
            # Return certification info
            response_data = {
                "valid": True,
                "cert_id": entry.cert_id,
                "issued_date": entry.timestamp,
                "cert_type": entry.cert_type,
                "operator": self.config.OPERATOR,
                "vault_anchor": entry.vault_anchor
            }
            
            return jsonify(response_data)
            
        except BadRequest:
            raise
        except Exception as e:
            self.logger.error(f"API hash verification failed: {str(e)}")
            raise InternalServerError(f"Hash verification failed: {str(e)}")

    def get_badge(self, cert_id: str):
        """GET /api/v1/badge/{cert_id} - Get badge data for certificate."""
        try:
            # Look up certification
            entry = self.vault.retrieve_certification(cert_id, "cert_id")
            if not entry:
                raise NotFound("Certificate not found")
            
            # Create badge data
            badge_data = {
                "cert_id": entry.cert_id,
                "badge_type": "CertNode Verified",
                "cert_type": entry.cert_type,
                "issued_date": entry.timestamp,
                "operator": self.config.OPERATOR,
                "verification_url": f"/api/v1/verify/{entry.ics_hash}",
                "vault_anchor": entry.vault_anchor
            }
            
            # Add analysis summary if available
            if hasattr(entry, 'metadata') and "analysis_summary" in entry.metadata:
                analysis = entry.metadata["analysis_summary"]
                badge_data.update({
                    "structural_score": analysis.get("frame_analysis", {}).get("structural_score"),
                    "convergence_achieved": analysis.get("cdp_analysis", {}).get("convergence_achieved")
                })
            
            return jsonify(badge_data)
            
        except NotFound:
            raise
        except Exception as e:
            self.logger.error(f"API badge retrieval failed: {str(e)}")
            raise InternalServerError(f"Badge retrieval failed: {str(e)}")

    def get_status(self):
        """GET /api/v1/status - Get system status."""
        try:
            status = self.processor.get_system_status()
            vault_stats = self.vault.get_vault_stats()
            
            # Combine status info
            combined_status = {
                **status,
                "vault_stats": {
                    "total_certifications": vault_stats.get("total_certifications", 0),
                    "unresolved_drift_alerts": vault_stats.get("unresolved_drift_alerts", 0)
                },
                "api_info": {
                    "version": "1.0.0",
                    "rate_limit": f"{self.rate_limit_max} requests per hour",
                    "endpoints": [
                        "POST /api/v1/certify",
                        "POST /api/v1/verify", 
                        "GET /api/v1/verify/{hash}",
                        "GET /api/v1/badge/{cert_id}",
                        "GET /api/v1/status",
                        "GET /api/v1/vault/stats",
                        "GET /api/v1/vault/search"
                    ]
                }
            }
            
            return jsonify(combined_status)
            
        except Exception as e:
            self.logger.error(f"API status check failed: {str(e)}")
            raise InternalServerError(f"Status check failed: {str(e)}")

    def get_vault_stats(self):
        """GET /api/v1/vault/stats - Get vault statistics."""
        try:
            stats = self.vault.get_vault_stats()
            return jsonify(stats)
            
        except Exception as e:
            self.logger.error(f"API vault stats failed: {str(e)}")
            raise InternalServerError(f"Vault stats failed: {str(e)}")

    def search_vault(self):
        """GET /api/v1/vault/search - Search vault certifications."""
        try:
            # Parse query parameters
            filters = {}
            
            cert_type = request.args.get('cert_type')
            if cert_type:
                filters['cert_type'] = cert_type
            
            author_signature = request.args.get('author_signature')
            if author_signature:
                filters['author_signature'] = author_signature
            
            date_from = request.args.get('date_from')
            if date_from:
                filters['date_from'] = date_from
            
            date_to = request.args.get('date_to')
            if date_to:
                filters['date_to'] = date_to
            
            limit = request.args.get('limit', 10, type=int)
            limit = min(limit, 100)  # Cap at 100
            
            # Search vault
            results = self.vault.search_certifications(filters, limit)
            
            # Format results
            search_results = []
            for entry in results:
                search_results.append({
                    "cert_id": entry.cert_id,
                    "ics_hash": entry.ics_hash,
                    "cert_type": entry.cert_type,
                    "timestamp": entry.timestamp,
                    "vault_anchor": entry.vault_anchor
                })
            
            return jsonify({
                "total_results": len(search_results),
                "results": search_results,
                "filters_applied": filters
            })
            
        except Exception as e:
            self.logger.error(f"API vault search failed: {str(e)}")
            raise InternalServerError(f"Vault search failed: {str(e)}")

    def health_check(self):
        """GET /health - Health check endpoint."""
        try:
            # Basic health checks
            health_status = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "checks": {
                    "processor": "ok",
                    "vault": "ok",
                    "ics_generator": "ok"
                }
            }
            
            # Test vault connection
            try:
                self.vault.get_vault_stats()
            except Exception:
                health_status["checks"]["vault"] = "error"
                health_status["status"] = "degraded"
            
            # Test processor
            try:
                self.processor.get_system_status()
            except Exception:
                health_status["checks"]["processor"] = "error"
                health_status["status"] = "degraded"
            
            status_code = 200 if health_status["status"] == "healthy" else 503
            return jsonify(health_status), status_code
            
        except Exception as e:
            return jsonify({
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }), 503

    def api_info(self):
        """GET / - API information."""
        return jsonify({
            "name": "CertNode API",
            "version": "1.0.0",
            "description": "Nonfiction Logic Certification System",
            "operator": self.config.OPERATOR,
            "documentation": "/api/v1/status",
            "health": "/health",
            "endpoints": {
                "certify": "POST /api/v1/certify",
                "verify": "POST /api/v1/verify",
                "verify_hash": "GET /api/v1/verify/{hash}",
                "badge": "GET /api/v1/badge/{cert_id}",
                "status": "GET /api/v1/status",
                "vault_stats": "GET /api/v1/vault/stats",
                "vault_search": "GET /api/v1/vault/search"
            }
        })

    def run(self, host: str = '0.0.0.0', port: int = 8000, debug: bool = False):
        """Run the API server."""
        self.logger.info(f"Starting CertNode API server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main entry point for API server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CertNode API Server")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    api = CertNodeAPI()
    api.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()

