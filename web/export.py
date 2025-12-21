"""Export scan results in multiple formats (JSON, CSV, PDF).

Provides functions to generate and serve reports in different formats.
"""
import json
import csv
import logging
from io import StringIO, BytesIO
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent
# Use a secure location for reports not directly accessible via web
REPORTS_DIR = Path(BASE_DIR).parent / '.secrets' / 'reports'


def export_scan_json(target: str, scan_output: str, enrichment: Optional[Dict] = None) -> str:
    """Export scan result as JSON."""
    try:
        report = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'scan_output': scan_output,
            'enrichment': enrichment or {}
        }
        return json.dumps(report, indent=2)
    except Exception as e:
        logger.exception(f'Error exporting JSON: {e}')
        return json.dumps({'error': str(e)})


def export_scan_csv(target: str, scan_output: str, enrichment: Optional[Dict] = None) -> str:
    """Export scan result as CSV."""
    try:
        output = StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(['Field', 'Value'])
        
        # Basic info
        writer.writerow(['Target', target])
        writer.writerow(['Timestamp', datetime.utcnow().isoformat() + 'Z'])
        writer.writerow(['', ''])
        
        # Scan output (first few lines as summary)
        writer.writerow(['Scan Output Summary', ''])
        for line in scan_output.splitlines()[:20]:
            if line.strip():
                writer.writerow(['', line])
        
        # Enrichment
        if enrichment:
            writer.writerow(['', ''])
            writer.writerow(['Services Detected', ''])
            for port, service in enrichment.get('services', {}).items():
                writer.writerow(['', f'{port}: {service}'])
            
            if enrichment.get('cves'):
                writer.writerow(['', ''])
                writer.writerow(['CVEs Found', ''])
                for service, cves in enrichment.get('cves', {}).items():
                    writer.writerow(['', f'{service}:'])
                    for cve in cves:
                        writer.writerow(['', f"  {cve.get('id')} ({cve.get('severity')})"])
        
        return output.getvalue()
    except Exception as e:
        logger.exception(f'Error exporting CSV: {e}')
        return f'Error: {str(e)}'


def export_scan_pdf(target: str, scan_output: str, enrichment: Optional[Dict] = None) -> Optional[bytes]:
    """Export scan result as PDF (requires reportlab)."""
    if not HAS_REPORTLAB:
        logger.warning('reportlab not available; PDF export disabled')
        return None
    
    try:
        # Create a BytesIO buffer
        pdf_buffer = BytesIO()
        
        # Create PDF document
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f2937'),
            spaceAfter=30,
            alignment=1  # Center
        )
        story.append(Paragraph(f'Scan Report: {target}', title_style))
        story.append(Spacer(1, 0.3 * inch))
        
        # Metadata
        meta_style = styles['Normal']
        story.append(Paragraph(f'<b>Target:</b> {target}', meta_style))
        story.append(Paragraph(f'<b>Timestamp:</b> {datetime.utcnow().isoformat() + "Z"}', meta_style))
        story.append(Spacer(1, 0.2 * inch))
        
        # Scan Output Section
        story.append(Paragraph('Scan Output', styles['Heading2']))
        scan_lines = scan_output.splitlines()[:30]  # Limit to first 30 lines
        for line in scan_lines:
            if line.strip():
                story.append(Paragraph(line, styles['Normal']))
        
        # Enrichment Section
        if enrichment and (enrichment.get('services') or enrichment.get('cves')):
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph('Services & CVEs', styles['Heading2']))
            
            if enrichment.get('services'):
                story.append(Paragraph('<b>Detected Services:</b>', styles['Normal']))
                for port, service in enrichment.get('services', {}).items():
                    story.append(Paragraph(f'  • {port}: {service}', styles['Normal']))
            
            if enrichment.get('cves'):
                story.append(Spacer(1, 0.1 * inch))
                story.append(Paragraph('<b>CVEs Found:</b>', styles['Normal']))
                for service, cves in enrichment.get('cves', {}).items():
                    story.append(Paragraph(f'  <b>{service}:</b>', styles['Normal']))
                    for cve in cves:
                        severity_color = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#f59e0b', 'LOW': '#10b981'}.get(
                            cve.get('severity', ''),
                            '#6b7280'
                        )
                        story.append(Paragraph(
                            f'    • <font color="{severity_color}">{cve.get("id")}</font> ({cve.get("severity")})',
                            styles['Normal']
                        ))
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
    except Exception as e:
        logger.exception(f'Error exporting PDF: {e}')
        return None


def save_report(target: str, scan_output: str, enrichment: Optional[Dict] = None, fmt: str = 'json') -> Optional[str]:
    """Save a report to disk in the specified format.
    
    Returns the file path if successful, None otherwise.
    """
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('.', '_').replace('/', '_')
        
        if fmt == 'json':
            content = export_scan_json(target, scan_output, enrichment)
            filename = REPORTS_DIR / f'report_{safe_target}_{timestamp}.json'
            with open(filename, 'w') as f:
                f.write(content)
        elif fmt == 'csv':
            content = export_scan_csv(target, scan_output, enrichment)
            filename = REPORTS_DIR / f'report_{safe_target}_{timestamp}.csv'
            with open(filename, 'w') as f:
                f.write(content)
        elif fmt == 'pdf':
            if not HAS_REPORTLAB:
                logger.warning('PDF export not available')
                return None
            content = export_scan_pdf(target, scan_output, enrichment)
            if content is None:
                return None
            filename = REPORTS_DIR / f'report_{safe_target}_{timestamp}.pdf'
            with open(filename, 'wb') as f:
                f.write(content)
        else:
            logger.warning(f'Unknown format: {fmt}')
            return None
        
        logger.info(f'Saved {fmt.upper()} report to {filename}')
        return str(filename)
    except Exception as e:
        logger.exception(f'Error saving report: {e}')
        return None
