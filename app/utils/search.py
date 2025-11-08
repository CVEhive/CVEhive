from sqlalchemy.orm import sessionmaker
from sqlalchemy import and_, or_, func
from app.models.base import engine
from app.models import CVE, Exploit
import logging

class SearchEngine:
    """Search engine for CVEs and exploits."""
    
    def __init__(self):
        self.Session = sessionmaker(bind=engine)
    
    def search(self, query, page=1, per_page=20, filters=None):
        """
        Search CVEs and exploits.
        
        Args:
            query (str): Search query
            page (int): Page number
            per_page (int): Results per page
            filters (dict): Additional filters
        
        Returns:
            dict: Search results with pagination info
        """
        db = self.Session()
        try:
            # Build base query
            base_query = db.query(CVE)
            
            # Apply search filters
            if query:
                search_conditions = []
                
                # Search in CVE ID
                search_conditions.append(CVE.cve_id.ilike(f'%{query}%'))
                
                # Search in summary and description
                search_conditions.append(CVE.summary.ilike(f'%{query}%'))
                search_conditions.append(CVE.description.ilike(f'%{query}%'))
                
                # Search in vendor and product
                search_conditions.append(CVE.vendor.ilike(f'%{query}%'))
                search_conditions.append(CVE.product.ilike(f'%{query}%'))
                
                # Search in vulnerability type
                search_conditions.append(CVE.vulnerability_type.ilike(f'%{query}%'))
                
                base_query = base_query.filter(or_(*search_conditions))
            
            # Apply additional filters
            if filters:
                if filters.get('severity'):
                    base_query = base_query.filter(CVE.severity == filters['severity'])
                
                if filters.get('has_exploit') == 'true':
                    base_query = base_query.filter(CVE.has_exploit == True)
                elif filters.get('has_exploit') == 'false':
                    base_query = base_query.filter(CVE.has_exploit == False)
                
                if filters.get('source'):
                    base_query = base_query.filter(CVE.source == filters['source'])
            
            # Order by relevance (has exploit first, then by CVSS score, then by date)
            base_query = base_query.order_by(
                CVE.has_exploit.desc(),
                CVE.cvss_v3_score.desc().nullslast(),
                CVE.cvss_v2_score.desc().nullslast(),
                CVE.published_date.desc().nullslast()
            )
            
            # Get total count
            total = base_query.count()
            
            # Apply pagination
            offset = (page - 1) * per_page
            results = base_query.offset(offset).limit(per_page).all()
            
            # Calculate pagination info
            total_pages = (total + per_page - 1) // per_page
            has_prev = page > 1
            has_next = page < total_pages
            
            return {
                'items': results,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'has_prev': has_prev,
                'has_next': has_next,
                'prev_num': page - 1 if has_prev else None,
                'next_num': page + 1 if has_next else None
            }
            
        except Exception as e:
            logging.error(f"Search error: {str(e)}")
            raise
        finally:
            db.close()
    
    def search_exploits(self, cve_id=None, query=None, source=None, validated_only=False):
        """
        Search exploits.
        
        Args:
            cve_id (str): CVE ID to filter by
            query (str): Search query
            source (str): Exploit source filter
            validated_only (bool): Only return validated exploits
        
        Returns:
            list: List of exploits
        """
        db = self.Session()
        try:
            base_query = db.query(Exploit)
            
            # Filter by CVE ID
            if cve_id:
                cve = db.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
                if cve:
                    base_query = base_query.filter(Exploit.cve_id == cve.id)
                else:
                    return []
            
            # Search in title and description
            if query:
                search_conditions = [
                    Exploit.title.ilike(f'%{query}%'),
                    Exploit.description.ilike(f'%{query}%'),
                    Exploit.author.ilike(f'%{query}%')
                ]
                base_query = base_query.filter(or_(*search_conditions))
            
            # Filter by source
            if source:
                base_query = base_query.filter(Exploit.source == source)
            
            # Filter validated only
            if validated_only:
                base_query = base_query.filter(Exploit.validation_status == 'validated')
            
            # Order by quality rating and popularity
            base_query = base_query.order_by(
                Exploit.confidence_score.desc(),
                Exploit.popularity_score.desc(),
                Exploit.created_at.desc()
            )
            
            return base_query.all()
            
        except Exception as e:
            logging.error(f"Exploit search error: {str(e)}")
            raise
        finally:
            db.close()
    
    def get_search_suggestions(self, query, limit=10):
        """
        Get search suggestions based on query.
        
        Args:
            query (str): Partial search query
            limit (int): Maximum number of suggestions
        
        Returns:
            list: List of suggestions
        """
        if not query or len(query) < 2:
            return []
        
        db = self.Session()
        try:
            suggestions = []
            
            # CVE ID suggestions
            cve_suggestions = db.query(CVE.cve_id).filter(
                CVE.cve_id.ilike(f'{query}%')
            ).limit(limit // 2).all()
            
            suggestions.extend([cve[0] for cve in cve_suggestions])
            
            # Vendor suggestions
            vendor_suggestions = db.query(CVE.vendor).filter(
                and_(
                    CVE.vendor.ilike(f'{query}%'),
                    CVE.vendor.isnot(None)
                )
            ).distinct().limit(limit // 2).all()
            
            suggestions.extend([vendor[0] for vendor in vendor_suggestions])
            
            return suggestions[:limit]
            
        except Exception as e:
            logging.error(f"Search suggestions error: {str(e)}")
            return []
        finally:
            db.close()
    
    def get_popular_searches(self, limit=10):
        """Get popular/trending CVEs."""
        db = self.Session()
        try:
            # Get CVEs with most exploits
            popular = db.query(CVE).filter(
                CVE.has_exploit == True
            ).order_by(
                CVE.exploit_count.desc(),
                CVE.cvss_v3_score.desc().nullslast(),
                CVE.published_date.desc()
            ).limit(limit).all()
            
            return popular
            
        except Exception as e:
            logging.error(f"Popular searches error: {str(e)}")
            return []
        finally:
            db.close() 