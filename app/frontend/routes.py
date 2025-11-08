"""
CVEhive Frontend Routes
Web interface routes for the CVEhive application.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import and_, or_, desc
from app.models.base import get_db
from app.models import CVE, Exploit, ValidationResult
from app.utils.search import SearchEngine
from datetime import datetime, timedelta
import logging

frontend_bp = Blueprint('frontend', __name__)

@frontend_bp.route('/')
def index():
    """Home page with search interface."""
    try:
        db_session = next(get_db())
        
        # Get recent statistics
        total_cves = db_session.query(CVE).count()
        total_exploits = db_session.query(Exploit).count()
        validated_exploits = db_session.query(ValidationResult).filter(
            ValidationResult.is_validated == True
        ).count()
        
        # Get recent CVEs (last 7 days)
        last_week = datetime.utcnow() - timedelta(days=7)
        recent_cves = db_session.query(CVE).filter(
            CVE.published_date >= last_week
        ).order_by(desc(CVE.published_date)).limit(5).all()
        
        # Get high severity CVEs
        high_severity_cves = db_session.query(CVE).filter(
            or_(CVE.cvss_v3_score >= 7.0, CVE.cvss_v2_score >= 7.0)
        ).order_by(desc(CVE.published_date)).limit(5).all()
        
        db_session.close()
        
        return render_template('index.html',
                             total_cves=total_cves,
                             total_exploits=total_exploits,
                             validated_exploits=validated_exploits,
                             recent_cves=recent_cves,
                             high_severity_cves=high_severity_cves)
                             
    except Exception as e:
        logging.error(f"Error loading home page: {str(e)}")
        return render_template('index.html',
                             total_cves=0,
                             total_exploits=0,
                             validated_exploits=0,
                             recent_cves=[],
                             high_severity_cves=[])

@frontend_bp.route('/search')
def search():
    """Search results page."""
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'cves')  # cves or exploits
    page = int(request.args.get('page', 1))
    severity = request.args.get('severity', '')
    vendor = request.args.get('vendor', '')
    year = request.args.get('year', '')
    has_exploit = request.args.get('has_exploit', '')
    
    if not query:
        flash('Please enter a search query', 'warning')
        return redirect(url_for('frontend.index'))
    
    try:
        search_engine = SearchEngine()
        
        if search_type == 'exploits':
            results, total_results = search_engine.search_exploits_paginated(
                query=query,
                page=page,
                per_page=20,
                language=request.args.get('language', ''),
                source=request.args.get('source', ''),
                validated_only=request.args.get('validated_only', '') == 'true'
            )
        else:
            results, total_results = search_engine.search_cves_paginated(
                query=query,
                page=page,
                per_page=20,
                severity=severity,
                vendor=vendor,
                year=year,
                has_exploit=(has_exploit == 'true') if has_exploit else None
            )
        
        # Calculate pagination
        total_pages = (total_results + 19) // 20  # Ceiling division
        has_prev = page > 1
        has_next = page < total_pages
        
        return render_template('search_results.html',
                             query=query,
                             search_type=search_type,
                             results=results,
                             total_results=total_results,
                             page=page,
                             total_pages=total_pages,
                             has_prev=has_prev,
                             has_next=has_next,
                             severity=severity,
                             vendor=vendor,
                             year=year,
                             has_exploit=has_exploit)
                             
    except Exception as e:
        logging.error(f"Error during search: {str(e)}")
        flash(f'Search error: {str(e)}', 'error')
        return redirect(url_for('frontend.index'))

@frontend_bp.route('/cve/<cve_id>')
def cve_detail(cve_id):
    """CVE detail page."""
    try:
        db_session = next(get_db())
        
        # Get CVE details
        cve = db_session.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            db_session.close()
            flash(f'CVE {cve_id} not found', 'error')
            return redirect(url_for('frontend.index'))
        
        # Get related exploits
        exploits = db_session.query(Exploit).filter(
            or_(
                Exploit.cve_ids.contains(cve_id),
                Exploit.title.contains(cve_id),
                Exploit.description.contains(cve_id)
            )
        ).all()
        
        # Get validation results for exploits
        exploit_validations = {}
        for exploit in exploits:
            validation = db_session.query(ValidationResult).filter(
                ValidationResult.exploit_id == exploit.id
            ).order_by(desc(ValidationResult.created_at)).first()
            exploit_validations[exploit.id] = validation
        
        db_session.close()
        
        return render_template('cve_detail.html',
                             cve=cve,
                             exploits=exploits,
                             exploit_validations=exploit_validations)
                             
    except Exception as e:
        logging.error(f"Error loading CVE detail: {str(e)}")
        flash(f'Error loading CVE details: {str(e)}', 'error')
        return redirect(url_for('frontend.index'))

@frontend_bp.route('/exploit/<int:exploit_id>')
def exploit_detail(exploit_id):
    """Exploit detail page."""
    try:
        db_session = next(get_db())
        
        # Get exploit details
        exploit = db_session.query(Exploit).filter(Exploit.id == exploit_id).first()
        if not exploit:
            db_session.close()
            flash('Exploit not found', 'error')
            return redirect(url_for('frontend.index'))
        
        # Get validation results
        validations = db_session.query(ValidationResult).filter(
            ValidationResult.exploit_id == exploit_id
        ).order_by(desc(ValidationResult.created_at)).all()
        
        # Get related CVEs
        related_cves = []
        if exploit.cve_ids:
            cve_list = [cve.strip() for cve in exploit.cve_ids.split(',')]
            related_cves = db_session.query(CVE).filter(
                CVE.cve_id.in_(cve_list)
            ).all()
        
        db_session.close()
        
        return render_template('exploit_detail.html',
                             exploit=exploit,
                             validations=validations,
                             related_cves=related_cves)
                             
    except Exception as e:
        logging.error(f"Error loading exploit detail: {str(e)}")
        flash(f'Error loading exploit details: {str(e)}', 'error')
        return redirect(url_for('frontend.index'))

@frontend_bp.route('/stats')
def stats():
    """Statistics page."""
    try:
        db_session = next(get_db())
        
        # Basic counts
        total_cves = db_session.query(CVE).count()
        total_exploits = db_session.query(Exploit).count()
        total_validations = db_session.query(ValidationResult).count()
        validated_exploits = db_session.query(ValidationResult).filter(
            ValidationResult.is_validated == True
        ).count()
        
        # Recent activity (last 30 days)
        last_month = datetime.utcnow() - timedelta(days=30)
        recent_cves = db_session.query(CVE).filter(
            CVE.created_at >= last_month
        ).count()
        recent_exploits = db_session.query(Exploit).filter(
            Exploit.created_at >= last_month
        ).count()
        
        # Severity breakdown
        critical_cves = db_session.query(CVE).filter(
            or_(CVE.cvss_v3_score >= 9.0, CVE.cvss_v2_score >= 9.0)
        ).count()
        high_cves = db_session.query(CVE).filter(
            or_(
                and_(CVE.cvss_v3_score >= 7.0, CVE.cvss_v3_score < 9.0),
                and_(CVE.cvss_v2_score >= 7.0, CVE.cvss_v2_score < 9.0)
            )
        ).count()
        medium_cves = db_session.query(CVE).filter(
            or_(
                and_(CVE.cvss_v3_score >= 4.0, CVE.cvss_v3_score < 7.0),
                and_(CVE.cvss_v2_score >= 4.0, CVE.cvss_v2_score < 7.0)
            )
        ).count()
        
        # Exploit sources
        github_exploits = db_session.query(Exploit).filter(
            Exploit.source == 'github'
        ).count()
        exploitdb_exploits = db_session.query(Exploit).filter(
            Exploit.source == 'exploitdb'
        ).count()
        
        db_session.close()
        
        stats_data = {
            'total_cves': total_cves,
            'total_exploits': total_exploits,
            'total_validations': total_validations,
            'validated_exploits': validated_exploits,
            'recent_cves': recent_cves,
            'recent_exploits': recent_exploits,
            'critical_cves': critical_cves,
            'high_cves': high_cves,
            'medium_cves': medium_cves,
            'github_exploits': github_exploits,
            'exploitdb_exploits': exploitdb_exploits,
            'validation_rate': (validated_exploits / total_validations * 100) if total_validations > 0 else 0
        }
        
        return render_template('stats.html', stats=stats_data)
        
    except Exception as e:
        logging.error(f"Error loading stats: {str(e)}")
        flash(f'Error loading statistics: {str(e)}', 'error')
        return redirect(url_for('frontend.index'))

@frontend_bp.route('/about')
def about():
    """About page."""
    return render_template('about.html')

# AJAX endpoints for dynamic content
@frontend_bp.route('/api/search/suggestions')
def search_suggestions():
    """Get search suggestions as user types."""
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify([])
    
    try:
        db_session = next(get_db())
        
        # Get CVE suggestions
        cve_suggestions = db_session.query(CVE.cve_id, CVE.summary).filter(
            or_(
                CVE.cve_id.contains(query),
                CVE.summary.contains(query)
            )
        ).limit(5).all()
        
        # Get vendor suggestions from CVEs
        vendor_suggestions = db_session.query(CVE.vendor_name).filter(
            CVE.vendor_name.contains(query)
        ).distinct().limit(3).all()
        
        db_session.close()
        
        suggestions = []
        
        # Add CVE suggestions
        for cve_id, summary in cve_suggestions:
            suggestions.append({
                'type': 'cve',
                'value': cve_id,
                'label': f"{cve_id} - {summary[:60]}..."
            })
        
        # Add vendor suggestions
        for (vendor_name,) in vendor_suggestions:
            if vendor_name:
                suggestions.append({
                    'type': 'vendor',
                    'value': vendor_name,
                    'label': f"Vendor: {vendor_name}"
                })
        
        return jsonify(suggestions)
        
    except Exception as e:
        logging.error(f"Error getting search suggestions: {str(e)}")
        return jsonify([])

@frontend_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('404.html'), 404

@frontend_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return render_template('500.html'), 500 