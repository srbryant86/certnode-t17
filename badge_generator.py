"""
Badge Generator - Visual certification badges
Generates SVG, PNG, and HTML badges for certified content.
"""

import json
import base64
import qrcode
from io import BytesIO
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from certnode_config import CertNodeConfig, CertNodeLogger
from ics_generator import ICSSignature

@dataclass
class BadgeStyle:
    """Badge styling configuration."""
    primary_color: str
    secondary_color: str
    text_color: str
    background_color: str
    border_color: str
    font_family: str
    width: int
    height: int

class BadgeGenerator:
    """
    Generates visual certification badges in multiple formats.
    Creates SVG, HTML, and badge data for certified content.
    """

    def __init__(self):
        self.logger = CertNodeLogger("Badge")
        self.config = CertNodeConfig()
        
        # Default badge styles
        self.styles = {
            "default": BadgeStyle(
                primary_color="#2563eb",
                secondary_color="#1d4ed8", 
                text_color="#ffffff",
                background_color="#f8fafc",
                border_color="#e2e8f0",
                font_family="Arial, sans-serif",
                width=300,
                height=120
            ),
            "compact": BadgeStyle(
                primary_color="#059669",
                secondary_color="#047857",
                text_color="#ffffff", 
                background_color="#ecfdf5",
                border_color="#d1fae5",
                font_family="Arial, sans-serif",
                width=200,
                height=80
            ),
            "premium": BadgeStyle(
                primary_color="#7c3aed",
                secondary_color="#6d28d9",
                text_color="#ffffff",
                background_color="#faf5ff", 
                border_color="#e9d5ff",
                font_family="Arial, sans-serif",
                width=350,
                height=140
            )
        }
        
        self.logger.info("Badge generator initialized")

    def generate_svg_badge(self, signature: ICSSignature, 
                          style: str = "default",
                          include_qr: bool = True) -> str:
        """
        Generate SVG badge for certification.
        
        Args:
            signature: ICS signature
            style: Badge style name
            include_qr: Whether to include QR code
            
        Returns:
            SVG markup as string
        """
        try:
            badge_style = self.styles.get(style, self.styles["default"])
            
            # Prepare badge data
            cert_data = self._extract_badge_data(signature)
            
            # Generate QR code if requested
            qr_data = ""
            if include_qr:
                qr_data = self._generate_qr_svg(cert_data["verification_url"], 60)
            
            # Create SVG
            svg = self._create_svg_badge(cert_data, badge_style, qr_data)
            
            self.logger.info("SVG badge generated", {
                "cert_id": signature.metadata.cert_id,
                "style": style,
                "include_qr": include_qr
            })
            
            return svg
            
        except Exception as e:
            self.logger.error(f"SVG badge generation failed: {str(e)}")
            raise

    def generate_html_badge(self, signature: ICSSignature,
                           style: str = "default",
                           interactive: bool = True) -> str:
        """
        Generate HTML badge with optional interactivity.
        
        Args:
            signature: ICS signature
            style: Badge style name
            interactive: Whether to include hover effects and links
            
        Returns:
            HTML markup as string
        """
        try:
            badge_style = self.styles.get(style, self.styles["default"])
            cert_data = self._extract_badge_data(signature)
            
            html = self._create_html_badge(cert_data, badge_style, interactive)
            
            self.logger.info("HTML badge generated", {
                "cert_id": signature.metadata.cert_id,
                "style": style,
                "interactive": interactive
            })
            
            return html
            
        except Exception as e:
            self.logger.error(f"HTML badge generation failed: {str(e)}")
            raise

    def generate_embed_code(self, signature: ICSSignature,
                           style: str = "default",
                           format_type: str = "iframe") -> str:
        """
        Generate embed code for websites.
        
        Args:
            signature: ICS signature
            style: Badge style name
            format_type: "iframe", "inline", or "script"
            
        Returns:
            Embed code as string
        """
        try:
            cert_data = self._extract_badge_data(signature)
            base_url = "https://certnode.io"  # Configure as needed
            
            if format_type == "iframe":
                embed_code = f'''<iframe 
src="{base_url}/badge/{signature.metadata.cert_id}?style={style}" 
width="{self.styles[style].width}" 
height="{self.styles[style].height}"
frameborder="0" 
title="CertNode Certification Badge">
</iframe>'''
            
            elif format_type == "inline":
                html_badge = self.generate_html_badge(signature, style, True)
                embed_code = f'''<!-- CertNode Badge -->
<div class="certnode-badge" data-cert-id="{signature.metadata.cert_id}">
{html_badge}
</div>
<!-- End CertNode Badge -->'''
            
            elif format_type == "script":
                embed_code = f'''<script 
src="{base_url}/js/certnode-badge.js" 
data-cert-id="{signature.metadata.cert_id}"
data-style="{style}">
</script>'''
            
            else:
                raise ValueError(f"Invalid format_type: {format_type}")
            
            self.logger.info("Embed code generated", {
                "cert_id": signature.metadata.cert_id,
                "format_type": format_type
            })
            
            return embed_code
            
        except Exception as e:
            self.logger.error(f"Embed code generation failed: {str(e)}")
            raise

    def generate_badge_json(self, signature: ICSSignature) -> Dict[str, Any]:
        """
        Generate badge metadata as JSON.
        
        Args:
            signature: ICS signature
            
        Returns:
            Badge metadata dictionary
        """
        try:
            cert_data = self._extract_badge_data(signature)
            
            badge_json = {
                "cert_id": signature.metadata.cert_id,
                "badge_type": "CertNode Verified",
                "cert_type": signature.metadata.content_type,
                "issued_date": signature.metadata.timestamp,
                "operator": signature.metadata.operator,
                "verification_url": cert_data["verification_url"],
                "badge_styles": list(self.styles.keys()),
                "embed_formats": ["iframe", "inline", "script"],
                "vault_anchor": signature.vault_anchor,
                "ics_hash": signature.fingerprint.combined_hash,
                "analysis_summary": {
                    "structural_score": cert_data.get("structural_score"),
                    "convergence_achieved": cert_data.get("convergence_achieved"),
                    "suppression_score": cert_data.get("suppression_score")
                }
            }
            
            return badge_json
            
        except Exception as e:
            self.logger.error(f"Badge JSON generation failed: {str(e)}")
            raise

    def _extract_badge_data(self, signature: ICSSignature) -> Dict[str, Any]:
        """Extract data needed for badge generation."""
        analysis = signature.analysis_summary
        
        return {
            "cert_id": signature.metadata.cert_id,
            "cert_type": signature.metadata.content_type,
            "issued_date": signature.metadata.timestamp,
            "operator": signature.metadata.operator,
            "verification_url": signature.verification_data["verification_url"],
            "ics_hash": signature.fingerprint.combined_hash[:16] + "...",  # Truncated for display
            "structural_score": analysis.get("frame_analysis", {}).get("structural_score"),
            "convergence_achieved": analysis.get("cdp_analysis", {}).get("convergence_achieved"),
            "suppression_score": analysis.get("stride_analysis", {}).get("suppression_score"),
            "boundaries_satisfied": analysis.get("frame_analysis", {}).get("boundaries_satisfied")
        }

    def _create_svg_badge(self, cert_data: Dict[str, Any], 
                         style: BadgeStyle, qr_data: str) -> str:
        """Create SVG badge markup."""
        # Format date
        try:
            date_obj = datetime.fromisoformat(cert_data["issued_date"].replace('Z', '+00:00'))
            formatted_date = date_obj.strftime("%Y-%m-%d")
        except:
            formatted_date = cert_data["issued_date"][:10]
        
        # Status indicators
        convergence_icon = "✓" if cert_data.get("convergence_achieved") else "○"
        boundaries_icon = "✓" if cert_data.get("boundaries_satisfied") else "○"
        
        # QR code positioning
        qr_x = style.width - 70 if qr_data else style.width
        content_width = style.width - 80 if qr_data else style.width - 20
        
        svg = f'''<svg width="{style.width}" height="{style.height}" xmlns="http://www.w3.org/2000/svg">
<defs>
    <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:{style.primary_color}" />
        <stop offset="100%" style="stop-color:{style.secondary_color}" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="2" dy="2" stdDeviation="3" flood-color="rgba(0,0,0,0.1)"/>
    </filter>
</defs>

<!-- Background -->
<rect width="{style.width}" height="{style.height}" rx="8" ry="8" 
      fill="{style.background_color}" stroke="{style.border_color}" stroke-width="2" filter="url(#shadow)"/>

<!-- Header -->
<rect width="{style.width}" height="30" rx="8" ry="8" fill="url(#gradient)"/>
<rect width="{style.width}" height="22" fill="url(#gradient)"/>

<!-- Title -->
<text x="15" y="20" font-family="{style.font_family}" font-size="12" font-weight="bold" fill="{style.text_color}">
    CertNode Verified
</text>

<!-- Cert Type -->
<text x="15" y="50" font-family="{style.font_family}" font-size="11" font-weight="bold" fill="#374151">
    {cert_data["cert_type"]}
</text>

<!-- Cert ID -->
<text x="15" y="67" font-family="{style.font_family}" font-size="9" fill="#6b7280">
    ID: {cert_data["cert_id"][:8]}...
</text>

<!-- Date -->
<text x="15" y="82" font-family="{style.font_family}" font-size="9" fill="#6b7280">
    Issued: {formatted_date}
</text>

<!-- Status Indicators -->
<text x="15" y="100" font-family="{style.font_family}" font-size="8" fill="#374151">
    Logic: {convergence_icon} Structure: {boundaries_icon}
</text>

<!-- QR Code -->
{qr_data}

<!-- Link -->
<a href="{cert_data['verification_url']}" target="_blank">
    <rect width="{style.width}" height="{style.height}" fill="transparent"/>
</a>
</svg>'''
        
        return svg

    def _create_html_badge(self, cert_data: Dict[str, Any],
                          style: BadgeStyle, interactive: bool) -> str:
        """Create HTML badge markup."""
        # Format date
        try:
            date_obj = datetime.fromisoformat(cert_data["issued_date"].replace('Z', '+00:00'))
            formatted_date = date_obj.strftime("%Y-%m-%d")
        except:
            formatted_date = cert_data["issued_date"][:10]
        
        # Status indicators
        convergence_status = "verified" if cert_data.get("convergence_achieved") else "pending"
        boundaries_status = "verified" if cert_data.get("boundaries_satisfied") else "pending"
        
        # Interactive styles
        hover_style = ""
        if interactive:
            hover_style = """
        .certnode-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(37, 99, 235, 0.15);
        }
        .certnode-badge:hover .badge-header {
            background: linear-gradient(135deg, #1d4ed8, #1e40af);
        }
        """
        
        # Link wrapper
        link_start = f'<a href="{cert_data["verification_url"]}" target="_blank" style="text-decoration: none;">' if interactive else ""
        link_end = "</a>" if interactive else ""
        
        html = f'''
<style>
    .certnode-badge {{
        width: {style.width}px;
        height: {style.height}px;
        background: {style.background_color};
        border: 2px solid {style.border_color};
        border-radius: 8px;
        font-family: {style.font_family};
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
        cursor: {'pointer' if interactive else 'default'};
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }}
    
    .badge-header {{
        height: 30px;
        background: linear-gradient(135deg, {style.primary_color}, {style.secondary_color});
        display: flex;
        align-items: center;
        padding: 0 15px;
        transition: background 0.3s ease;
    }}
    
    .badge-title {{
        color: {style.text_color};
        font-size: 12px;
        font-weight: bold;
        margin: 0;
    }}
    
    .badge-content {{
        padding: 15px;
        color: #374151;
    }}
    
    .cert-type {{
        font-size: 11px;
        font-weight: bold;
        margin-bottom: 5px;
    }}
    
    .cert-meta {{
        font-size: 9px;
        color: #6b7280;
        margin-bottom: 3px;
    }}
    
    .cert-status {{
        font-size: 8px;
        margin-top: 8px;
        display: flex;
        gap: 10px;
    }}
    
    .status-item {{
        display: flex;
        align-items: center;
        gap: 3px;
    }}
    
    .status-icon {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }}
    
    .status-verified {{
        background: #10b981;
    }}
    
    .status-pending {{
        background: #f59e0b;
    }}
    
    {hover_style}
</style>

{link_start}
<div class="certnode-badge">
    <div class="badge-header">
        <h3 class="badge-title">CertNode Verified</h3>
    </div>
    <div class="badge-content">
        <div class="cert-type">{cert_data["cert_type"]}</div>
        <div class="cert-meta">ID: {cert_data["cert_id"][:8]}...</div>
        <div class="cert-meta">Issued: {formatted_date}</div>
        <div class="cert-status">
            <div class="status-item">
                <div class="status-icon status-{convergence_status}"></div>
                <span>Logic</span>
            </div>
            <div class="status-item">
                <div class="status-icon status-{boundaries_status}"></div>
                <span>Structure</span>
            </div>
        </div>
    </div>
</div>
{link_end}
'''
        
        return html

    def _generate_qr_svg(self, url: str, size: int) -> str:
        """Generate QR code as SVG."""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=1,
                border=1,
            )
            qr.add_data(url)
            qr.make(fit=True)
            
            # Get QR code matrix
            matrix = qr.get_matrix()
            
            # Calculate scaling
            matrix_size = len(matrix)
            scale = size / matrix_size
            
            # Generate SVG paths
            paths = []
            for y, row in enumerate(matrix):
                for x, cell in enumerate(row):
                    if cell:
                        paths.append(f"M{x*scale},{y*scale}h{scale}v{scale}h-{scale}z")
            
            qr_svg = f'''
<g transform="translate({300-size-10},{10})">
    <rect x="0" y="0" width="{size}" height="{size}" fill="white" stroke="#e5e7eb" stroke-width="1"/>
    <path d="{''.join(paths)}" fill="black"/>
</g>'''
            
            return qr_svg
            
        except Exception as e:
            self.logger.warning(f"QR code generation failed: {str(e)}")
            return ""

    def create_custom_style(self, name: str, **kwargs) -> None:
        """Create a custom badge style."""
        default_style = self.styles["default"]
        
        custom_style = BadgeStyle(
            primary_color=kwargs.get("primary_color", default_style.primary_color),
            secondary_color=kwargs.get("secondary_color", default_style.secondary_color),
            text_color=kwargs.get("text_color", default_style.text_color),
            background_color=kwargs.get("background_color", default_style.background_color),
            border_color=kwargs.get("border_color", default_style.border_color),
            font_family=kwargs.get("font_family", default_style.font_family),
            width=kwargs.get("width", default_style.width),
            height=kwargs.get("height", default_style.height)
        )
        
        self.styles[name] = custom_style
        
        self.logger.info("Custom badge style created", {"style_name": name})

    def export_badge_package(self, signature: ICSSignature, 
                            output_dir: str) -> Dict[str, str]:
        """
        Export complete badge package with all formats.
        
        Args:
            signature: ICS signature
            output_dir: Output directory path
            
        Returns:
            Dictionary of generated file paths
        """
        try:
            from pathlib import Path
            
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            cert_id = signature.metadata.cert_id
            files = {}
            
            # Generate all badge formats
            for style_name in self.styles.keys():
                # SVG badge
                svg_content = self.generate_svg_badge(signature, style_name, True)
                svg_file = output_path / f"{cert_id}_badge_{style_name}.svg"
                with open(svg_file, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
                files[f"svg_{style_name}"] = str(svg_file)
                
                # HTML badge
                html_content = self.generate_html_badge(signature, style_name, True)
                html_file = output_path / f"{cert_id}_badge_{style_name}.html"
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                files[f"html_{style_name}"] = str(html_file)
                
                # Embed codes
                for format_type in ["iframe", "inline", "script"]:
                    embed_content = self.generate_embed_code(signature, style_name, format_type)
                    embed_file = output_path / f"{cert_id}_embed_{style_name}_{format_type}.txt"
                    with open(embed_file, 'w', encoding='utf-8') as f:
                        f.write(embed_content)
                    files[f"embed_{style_name}_{format_type}"] = str(embed_file)
            
            # Badge JSON metadata
            badge_json = self.generate_badge_json(signature)
            json_file = output_path / f"{cert_id}_badge_data.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(badge_json, f, indent=2)
            files["badge_data"] = str(json_file)
            
            self.logger.info("Badge package exported", {
                "cert_id": cert_id,
                "output_dir": output_dir,
                "file_count": len(files)
            })
            
            return files
            
        except Exception as e:
            self.logger.error(f"Badge package export failed: {str(e)}")
            raise

