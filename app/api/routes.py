"""
CVEhive API Routes
RESTful API endpoints for programmatic access to CVEhive data.
"""

from flask import Blueprint, jsonify, request, abort
from sqlalchemy import and_, or_, desc
from app.models.base import get_db
from app.models import CVE, Exploit, ValidationResult
from app.utils.search import SearchEngine
from datetime import datetime, timedelta
import logging

api_bp = Blueprint('api', __name__)

# API versioning
API_VERSION = "v1"

def paginate_query(query, page, per_page, max_per_page=100):
    """Helper function to paginate queries."""
    per_page = min(per_page, max_per_page)
    offset = (page - 1) * per_page
    total = query.count()
    items = query.offset(offset).limit(per_page).all()
    
    return {
        'items': items,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'has_prev': page > 1,
        'has_next': page * per_page < total
    }

def serialize_cve(cve):
    """Serialize CVE object to dictionary."""
    return {
        'id': cve.id,
        'cve_id': cve.cve_id,
        'summary': cve.summary,
        'description': cve.description,
        'published_date': cve.published_date.isoformat() if cve.published_date else None,
        'modified_date': cve.modified_date.isoformat() if cve.modified_date else None,
        'cvss_v2_score': cve.cvss_v2_score,
        'cvss_v2_vector': cve.cvss_v2_vector,
        'cvss_v3_score': cve.cvss_v3_score,
        'cvss_v3_vector': cve.cvss_v3_vector,
        'cwe_id': cve.cwe_id,
        'vendor_name': cve.vendor_name,
        'product_name': cve.product_name,
        'version_affected': cve.version_affected,
        'references': cve.references.split(',') if cve.references else [],
        'created_at': cve.created_at.isoformat() if cve.created_at else None,
        'updated_at': cve.updated_at.isoformat() if cve.updated_at else None
    }

def serialize_exploit(exploit):
    """Serialize Exploit object to dictionary."""
    return {
        'id': exploit.id,
        'title': exploit.title,
        'description': exploit.description,
        'source': exploit.source,
        'source_url': exploit.source_url,
        'author': exploit.author,
        'date_published': exploit.date_published.isoformat() if exploit.date_published else None,
        'language': exploit.language,
        'platform': exploit.platform,
        'exploit_type': exploit.exploit_type,
        'cve_ids': exploit.cve_ids.split(',') if exploit.cve_ids else [],
        'tags': exploit.tags.split(',') if exploit.tags else [],
        'quality_score': exploit.quality_score,
        'code_snippet': exploit.code_snippet[:500] + '...' if exploit.code_snippet and len(exploit.code_snippet) > 500 else exploit.code_snippet,
        'created_at': exploit.created_at.isoformat() if exploit.created_at else None,
        'updated_at': exploit.updated_at.isoformat() if exploit.updated_at else None
    }

def serialize_validation(validation):
    """Serialize ValidationResult object to dictionary."""
    return {
        'id': validation.id,
        'exploit_id': validation.exploit_id,
        'is_validated': validation.is_validated,
        'validation_level': validation.validation_level,
        'success_rate': validation.success_rate,
        'error_message': validation.error_message,
        'validation_output': validation.validation_output,
        'execution_time': validation.execution_time,
        'environment_info': validation.environment_info,
        'created_at': validation.created_at.isoformat() if validation.created_at else None
    }

# Health check endpoint
@api_bp.route('/health')
def health_check():
    """API health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': API_VERSION,
        'timestamp': datetime.utcnow().isoformat()
    })

# CVE endpoints
@api_bp.route('/cves')
def get_cves():
    """Get list of CVEs with pagination and filtering."""
    try:
        db_session = next(get_db())
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Build query with filters
        query = db_session.query(CVE)
        
        # Filter by severity
        severity = request.args.get('severity')
        if severity:
            if severity == 'critical':
                query = query.filter(or_(CVE.cvss_v3_score >= 9.0, CVE.cvss_v2_score >= 9.0))
            elif severity == 'high':
                query = query.filter(or_(
                    and_(CVE.cvss_v3_score >= 7.0, CVE.cvss_v3_score < 9.0),
                    and_(CVE.cvss_v2_score >= 7.0, CVE.cvss_v2_score < 9.0)
                ))
            elif severity == 'medium':
                query = query.filter(or_(
                    and_(CVE.cvss_v3_score >= 4.0, CVE.cvss_v3_score < 7.0),
                    and_(CVE.cvss_v2_score >= 4.0, CVE.cvss_v2_score < 7.0)
                ))
        
        # Filter by vendor
        vendor = request.args.get('vendor')
        if vendor:
            query = query.filter(CVE.vendor_name.ilike(f'%{vendor}%'))
        
        # Filter by year
        year = request.args.get('year')
        if year:
            try:
                year_int = int(year)
                start_date = datetime(year_int, 1, 1)
                end_date = datetime(year_int + 1, 1, 1)
                query = query.filter(CVE.published_date >= start_date, CVE.published_date < end_date)
            except ValueError:
                pass
        
        # Filter by exploit availability
        has_exploit = request.args.get('has_exploit')
        if has_exploit == 'true':
            # Subquery to find CVEs with exploits
            exploit_cve_ids = db_session.query(Exploit.cve_ids).filter(Exploit.cve_ids.isnot(None)).all()
            cve_ids_with_exploits = set()
            for (cve_ids_str,) in exploit_cve_ids:
                if cve_ids_str:
                    cve_ids_with_exploits.update(cve.strip() for cve in cve_ids_str.split(','))
            if cve_ids_with_exploits:
                query = query.filter(CVE.cve_id.in_(cve_ids_with_exploits))
        
        # Search query
        q = request.args.get('q')
        if q:
            query = query.filter(or_(
                CVE.cve_id.ilike(f'%{q}%'),
                CVE.summary.ilike(f'%{q}%'),
                CVE.description.ilike(f'%{q}%')
            ))
        
        # Order by published date (newest first)
        query = query.order_by(desc(CVE.published_date))
        
        # Paginate
        result = paginate_query(query, page, per_page)
        
        db_session.close()
        
        return jsonify({
            'cves': [serialize_cve(cve) for cve in result['items']],
            'pagination': {
                'total': result['total'],
                'page': result['page'],
                'per_page': result['per_page'],
                'pages': result['pages'],
                'has_prev': result['has_prev'],
                'has_next': result['has_next']
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting CVEs: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/cves/<cve_id>')
def get_cve(cve_id):
    """Get specific CVE by ID."""
    try:
        db_session = next(get_db())
        
        cve = db_session.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not cve:
            db_session.close()
            return jsonify({'error': 'CVE not found'}), 404
        
        # Get related exploits
        exploits = db_session.query(Exploit).filter(
            or_(
                Exploit.cve_ids.contains(cve_id),
                Exploit.title.contains(cve_id),
                Exploit.description.contains(cve_id)
            )
        ).all()
        
        db_session.close()
        
        return jsonify({
            'cve': serialize_cve(cve),
            'exploits': [serialize_exploit(exploit) for exploit in exploits]
        })
        
    except Exception as e:
        logging.error(f"Error getting CVE {cve_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Exploit endpoints
@api_bp.route('/exploits')
def get_exploits():
    """Get list of exploits with pagination and filtering."""
    try:
        db_session = next(get_db())
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        # Build query with filters
        query = db_session.query(Exploit)
        
        # Filter by source
        source = request.args.get('source')
        if source:
            query = query.filter(Exploit.source == source)
        
        # Filter by language
        language = request.args.get('language')
        if language:
            query = query.filter(Exploit.language.ilike(f'%{language}%'))
        
        # Filter by platform
        platform = request.args.get('platform')
        if platform:
            query = query.filter(Exploit.platform.ilike(f'%{platform}%'))
        
        # Filter validated only
        validated_only = request.args.get('validated_only') == 'true'
        if validated_only:
            validated_exploit_ids = db_session.query(ValidationResult.exploit_id).filter(
                ValidationResult.is_validated == True
            ).distinct().all()
            if validated_exploit_ids:
                query = query.filter(Exploit.id.in_([id[0] for id in validated_exploit_ids]))
        
        # Search query
        q = request.args.get('q')
        if q:
            query = query.filter(or_(
                Exploit.title.ilike(f'%{q}%'),
                Exploit.description.ilike(f'%{q}%'),
                Exploit.cve_ids.ilike(f'%{q}%')
            ))
        
        # Order by quality score and date
        query = query.order_by(desc(Exploit.quality_score), desc(Exploit.date_published))
        
        # Paginate
        result = paginate_query(query, page, per_page)
        
        db_session.close()
        
        return jsonify({
            'exploits': [serialize_exploit(exploit) for exploit in result['items']],
            'pagination': {
                'total': result['total'],
                'page': result['page'],
                'per_page': result['per_page'],
                'pages': result['pages'],
                'has_prev': result['has_prev'],
                'has_next': result['has_next']
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting exploits: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/exploits/<int:exploit_id>')
def get_exploit(exploit_id):
    """Get specific exploit by ID."""
    try:
        db_session = next(get_db())
        
        exploit = db_session.query(Exploit).filter(Exploit.id == exploit_id).first()
        if not exploit:
            db_session.close()
            return jsonify({'error': 'Exploit not found'}), 404
        
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
        
        return jsonify({
            'exploit': serialize_exploit(exploit),
            'validations': [serialize_validation(validation) for validation in validations],
            'related_cves': [serialize_cve(cve) for cve in related_cves]
        })
        
    except Exception as e:
        logging.error(f"Error getting exploit {exploit_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Search endpoints
@api_bp.route('/search')
def search():
    """Universal search endpoint."""
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # all, cves, exploits
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        
        if not query:
            return jsonify({'error': 'Query parameter is required'}), 400
        
        search_engine = SearchEngine()
        
        results = {}
        
        if search_type in ['all', 'cves']:
            cve_results, cve_total = search_engine.search_cves_paginated(
                query=query,
                page=page if search_type == 'cves' else 1,
                per_page=per_page if search_type == 'cves' else 10
            )
            results['cves'] = {
                'items': [serialize_cve(cve) for cve in cve_results],
                'total': cve_total
            }
        
        if search_type in ['all', 'exploits']:
            exploit_results, exploit_total = search_engine.search_exploits_paginated(
                query=query,
                page=page if search_type == 'exploits' else 1,
                per_page=per_page if search_type == 'exploits' else 10
            )
            results['exploits'] = {
                'items': [serialize_exploit(exploit) for exploit in exploit_results],
                'total': exploit_total
            }
        
        return jsonify({
            'query': query,
            'search_type': search_type,
            'results': results
        })
        
    except Exception as e:
        logging.error(f"Error during search: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Statistics endpoint
@api_bp.route('/stats')
def get_stats():
    """Get database statistics."""
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
        severity_stats = {
            'critical': db_session.query(CVE).filter(
                or_(CVE.cvss_v3_score >= 9.0, CVE.cvss_v2_score >= 9.0)
            ).count(),
            'high': db_session.query(CVE).filter(
                or_(
                    and_(CVE.cvss_v3_score >= 7.0, CVE.cvss_v3_score < 9.0),
                    and_(CVE.cvss_v2_score >= 7.0, CVE.cvss_v2_score < 9.0)
                )
            ).count(),
            'medium': db_session.query(CVE).filter(
                or_(
                    and_(CVE.cvss_v3_score >= 4.0, CVE.cvss_v3_score < 7.0),
                    and_(CVE.cvss_v2_score >= 4.0, CVE.cvss_v2_score < 7.0)
                )
            ).count(),
            'low': db_session.query(CVE).filter(
                or_(CVE.cvss_v3_score < 4.0, CVE.cvss_v2_score < 4.0)
            ).count()
        }
        
        # Source breakdown
        source_stats = {
            'github': db_session.query(Exploit).filter(Exploit.source == 'github').count(),
            'exploitdb': db_session.query(Exploit).filter(Exploit.source == 'exploitdb').count(),
            'other': db_session.query(Exploit).filter(
                and_(Exploit.source != 'github', Exploit.source != 'exploitdb')
            ).count()
        }
        
        db_session.close()
        
        return jsonify({
            'summary': {
                'total_cves': total_cves,
                'total_exploits': total_exploits,
                'total_validations': total_validations,
                'validated_exploits': validated_exploits,
                'validation_rate': (validated_exploits / total_validations * 100) if total_validations > 0 else 0
            },
            'recent_activity': {
                'cves_last_30_days': recent_cves,
                'exploits_last_30_days': recent_exploits
            },
            'severity_breakdown': severity_stats,
            'source_breakdown': source_stats,
            'generated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers
@api_bp.errorhandler(404)
def api_not_found(error):
    """Handle API 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(400)
def api_bad_request(error):
    """Handle API 400 errors."""
    return jsonify({'error': 'Bad request'}), 400

@api_bp.errorhandler(500)
def api_internal_error(error):
    """Handle API 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500 