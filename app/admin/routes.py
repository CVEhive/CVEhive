"""
Admin Panel Routes for CVEhive
Provides administrative interface for CVE and PoC management.
"""

import json
import requests
from datetime import datetime, timedelta
from flask import render_template, request, jsonify, flash, redirect, url_for, current_app
from sqlalchemy import func, desc, and_, or_
from sqlalchemy.orm import joinedload

from app.admin import admin_bp
from app.models import CVE, Exploit, ValidationResult
from app.models.base import db
from app.utils.search import SearchEngine
from app.validators.exploit_validator import ExploitValidator

@admin_bp.route('/')
def dashboard():
    """Admin dashboard with key metrics and quick actions."""
    try:
        # Get dashboard statistics
        stats = {
            'total_cves': CVE.query.count(),
            'total_exploits': Exploit.query.count(),
            'validated_exploits': Exploit.query.filter_by(validation_status='validated').count(),
            'pending_validation': Exploit.query.filter_by(validation_status='pending').count(),
            'failed_validation': Exploit.query.filter_by(validation_status='failed').count(),
            'cves_with_exploits': CVE.query.filter(CVE.has_exploit == True).count(),
            'recent_validations': ValidationResult.query.filter(
                ValidationResult.validation_date > datetime.now() - timedelta(days=7)
            ).count()
        }
        
        # Get recent CVEs without exploits
        cves_without_exploits = CVE.query.filter(
            or_(CVE.has_exploit == False, CVE.has_exploit == None)
        ).order_by(desc(CVE.published_date)).limit(10).all()
        
        # Get recent validation results
        recent_validations = ValidationResult.query.order_by(
            desc(ValidationResult.validation_date)
        ).limit(10).all()
        
        # Get high priority CVEs (critical/high severity without exploits)
        priority_cves = CVE.query.filter(
            and_(
                CVE.severity.in_(['CRITICAL', 'HIGH']),
                or_(CVE.has_exploit == False, CVE.has_exploit == None)
            )
        ).order_by(desc(CVE.published_date)).limit(5).all()
        
        return render_template('admin/dashboard.html',
                             stats=stats,
                             cves_without_exploits=cves_without_exploits,
                             recent_validations=recent_validations,
                             priority_cves=priority_cves)
                             
    except Exception as e:
        current_app.logger.error(f"Error loading admin dashboard: {e}")
        flash(f"Error loading dashboard: {str(e)}", 'error')
        return render_template('admin/dashboard.html', stats={})

@admin_bp.route('/cves')
def cve_management():
    """CVE management interface with filtering and bulk operations."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Filters
    severity = request.args.get('severity')
    has_exploit = request.args.get('has_exploit')
    validation_status = request.args.get('validation_status')
    search_query = request.args.get('q', '').strip()
    
    # Build query
    query = CVE.query
    
    if search_query:
        query = query.filter(
            or_(
                CVE.cve_id.contains(search_query),
                CVE.summary.contains(search_query),
                CVE.vendor.contains(search_query),
                CVE.product.contains(search_query)
            )
        )
    
    if severity:
        query = query.filter(CVE.severity == severity)
        
    if has_exploit == 'true':
        query = query.filter(CVE.has_exploit == True)
    elif has_exploit == 'false':
        query = query.filter(or_(CVE.has_exploit == False, CVE.has_exploit == None))
    
    # Order by most recent first
    query = query.order_by(desc(CVE.published_date))
    
    # Paginate results
    cves = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/cve_management.html', 
                         cves=cves,
                         current_filters={
                             'severity': severity,
                             'has_exploit': has_exploit,
                             'validation_status': validation_status,
                             'q': search_query
                         })

@admin_bp.route('/exploits')
def exploit_management():
    """Exploit management interface with validation controls."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Filters
    validation_status = request.args.get('validation_status')
    source = request.args.get('source')
    programming_language = request.args.get('programming_language')
    search_query = request.args.get('q', '').strip()
    
    # Build query with eager loading
    query = Exploit.query.options(joinedload(Exploit.cve))
    
    if search_query:
        query = query.filter(
            or_(
                Exploit.cve_id.contains(search_query),
                Exploit.title.contains(search_query),
                Exploit.author.contains(search_query)
            )
        )
    
    if validation_status:
        query = query.filter(Exploit.validation_status == validation_status)
        
    if source:
        query = query.filter(Exploit.source == source)
        
    if programming_language:
        query = query.filter(Exploit.programming_language == programming_language)
    
    # Order by most recent first
    query = query.order_by(desc(Exploit.created_at))
    
    # Paginate results
    exploits = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get filter options
    sources = db.session.query(Exploit.source).distinct().all()
    languages = db.session.query(Exploit.programming_language).distinct().all()
    
    return render_template('admin/exploit_management.html',
                         exploits=exploits,
                         sources=[s[0] for s in sources if s[0]],
                         languages=[l[0] for l in languages if l[0]],
                         current_filters={
                             'validation_status': validation_status,
                             'source': source,
                             'programming_language': programming_language,
                             'q': search_query
                         })

@admin_bp.route('/repository-monitor')
def repository_monitor():
    """Monitor notable repositories for new PoCs."""
    
    # Repository configurations
    repositories = [
        {
            'name': 'Trickest CVE',
            'url': 'https://github.com/trickest/cve',
            'api_url': 'https://api.github.com/repos/trickest/cve',
            'description': 'Curated list of CVE PoCs with high validation rate',
            'priority': 'high'
        },
        {
            'name': 'PoC-in-GitHub',
            'url': 'https://github.com/nomi-sec/PoC-in-GitHub',
            'api_url': 'https://api.github.com/repos/nomi-sec/PoC-in-GitHub',
            'description': 'Comprehensive collection of GitHub PoCs',
            'priority': 'medium'
        },
        {
            'name': 'Pocsuite3',
            'url': 'https://github.com/knownsec/Pocsuite3',
            'api_url': 'https://api.github.com/repos/knownsec/Pocsuite3',
            'description': 'Testing framework and PoC collection',
            'priority': 'medium'
        }
    ]
    
    # Get recent activity for each repository
    for repo in repositories:
        try:
            response = requests.get(f"{repo['api_url']}/commits", timeout=10)
            if response.status_code == 200:
                commits = response.json()[:5]  # Last 5 commits
                repo['recent_commits'] = commits
                repo['status'] = 'active'
            else:
                repo['status'] = 'error'
                repo['recent_commits'] = []
        except Exception as e:
            repo['status'] = 'error'
            repo['recent_commits'] = []
            current_app.logger.error(f"Error fetching {repo['name']}: {e}")
    
    return render_template('admin/repository_monitor.html', repositories=repositories)

@admin_bp.route('/validate-exploit/<int:exploit_id>', methods=['POST'])
def validate_exploit(exploit_id):
    """Manually trigger validation for a specific exploit."""
    try:
        exploit = Exploit.query.get_or_404(exploit_id)
        
        # Initialize validator
        validator = ExploitValidator()
        
        # Set status to pending
        exploit.validation_status = 'pending'
        db.session.commit()
        
        # Run validation (this should be async in production)
        result = validator.validate_exploit(exploit)
        
        if result:
            flash(f"Validation completed for {exploit.cve_id}", 'success')
        else:
            flash(f"Validation failed for {exploit.cve_id}", 'error')
            
        return redirect(url_for('admin.exploit_management'))
        
    except Exception as e:
        current_app.logger.error(f"Error validating exploit {exploit_id}: {e}")
        flash(f"Error during validation: {str(e)}", 'error')
        return redirect(url_for('admin.exploit_management'))

@admin_bp.route('/bulk-validate', methods=['POST'])
def bulk_validate():
    """Bulk validation of pending exploits."""
    try:
        exploit_ids = request.json.get('exploit_ids', [])
        
        if not exploit_ids:
            return jsonify({'error': 'No exploits selected'}), 400
        
        # Get exploits
        exploits = Exploit.query.filter(Exploit.id.in_(exploit_ids)).all()
        
        validator = ExploitValidator()
        results = []
        
        for exploit in exploits:
            exploit.validation_status = 'pending'
            db.session.commit()
            
            # In production, this should be queued as async tasks
            result = validator.validate_exploit(exploit)
            results.append({
                'exploit_id': exploit.id,
                'cve_id': exploit.cve_id,
                'success': result is not None
            })
        
        return jsonify({
            'message': f'Bulk validation completed for {len(exploits)} exploits',
            'results': results
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in bulk validation: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/sync-trickest', methods=['POST'])
def sync_trickest():
    """Sync with Trickest repository to find new validated PoCs."""
    try:
        # This would implement the Trickest workflow
        # For now, return a placeholder response
        
        return jsonify({
            'message': 'Trickest sync initiated',
            'status': 'pending'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error syncing with Trickest: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/api/stats')
def api_stats():
    """API endpoint for dashboard statistics."""
    try:
        stats = {
            'total_cves': CVE.query.count(),
            'total_exploits': Exploit.query.count(),
            'validated_exploits': Exploit.query.filter_by(validation_status='validated').count(),
            'pending_validation': Exploit.query.filter_by(validation_status='pending').count(),
            'failed_validation': Exploit.query.filter_by(validation_status='failed').count(),
            'validation_rate': 0
        }
        
        # Calculate validation rate
        if stats['total_exploits'] > 0:
            stats['validation_rate'] = round(
                (stats['validated_exploits'] / stats['total_exploits']) * 100, 2
            )
        
        # Get validation trends (last 30 days)
        thirty_days_ago = datetime.now() - timedelta(days=30)
        daily_validations = db.session.query(
            func.date(ValidationResult.validation_date).label('date'),
            func.count(ValidationResult.id).label('count'),
            func.sum(func.case([(ValidationResult.success == True, 1)], else_=0)).label('successful')
        ).filter(
            ValidationResult.validation_date >= thirty_days_ago
        ).group_by(
            func.date(ValidationResult.validation_date)
        ).all()
        
        trends = []
        for validation in daily_validations:
            trends.append({
                'date': validation.date.isoformat(),
                'total': validation.count,
                'successful': validation.successful or 0
            })
        
        stats['trends'] = trends
        
        return jsonify(stats)
        
    except Exception as e:
        current_app.logger.error(f"Error getting admin stats: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/search-missing-pocs')
def search_missing_pocs():
    """Find CVEs that need PoC research."""
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', 'CRITICAL,HIGH')
    
    severities = severity_filter.split(',') if severity_filter else []
    
    # Find CVEs without exploits, focusing on high severity
    query = CVE.query.filter(
        and_(
            or_(CVE.has_exploit == False, CVE.has_exploit == None),
            CVE.severity.in_(severities) if severities else True
        )
    ).order_by(desc(CVE.published_date))
    
    missing_pocs = query.paginate(page=page, per_page=25, error_out=False)
    
    return render_template('admin/missing_pocs.html', 
                         missing_pocs=missing_pocs,
                         current_severity=severity_filter)

@admin_bp.route('/update-cve/<cve_id>', methods=['GET', 'POST'])
def update_cve(cve_id):
    """Update CVE information manually."""
    cve = CVE.query.filter_by(cve_id=cve_id).first_or_404()
    
    if request.method == 'POST':
        try:
            # Update CVE fields
            cve.summary = request.form.get('summary', cve.summary)
            cve.description = request.form.get('description', cve.description)
            cve.severity = request.form.get('severity', cve.severity)
            cve.vendor = request.form.get('vendor', cve.vendor)
            cve.product = request.form.get('product', cve.product)
            
            # Update exploit status
            has_exploit = request.form.get('has_exploit') == 'true'
            cve.has_exploit = has_exploit
            
            cve.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash(f'CVE {cve_id} updated successfully', 'success')
            return redirect(url_for('admin.cve_management'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating CVE: {str(e)}', 'error')
    
    return render_template('admin/update_cve.html', cve=cve) 