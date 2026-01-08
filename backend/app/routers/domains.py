"""
API endpoints for domains management with DNS validation
"""
import logging
import asyncio
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
import dns.resolver
import dns.asyncresolver
from datetime import datetime, timezone

from app.mailcow_api import mailcow_api

from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database import get_db
from app.models import DomainDNSCheck
from fastapi import Depends
from app.utils import format_datetime_for_api

logger = logging.getLogger(__name__)

router = APIRouter()


async def check_spf_record(domain: str) -> Dict[str, Any]:
    """
    Check SPF record for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with SPF check results
    """
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Query TXT records
        answers = await resolver.resolve(domain, 'TXT')
        
        # Find SPF record
        spf_record = None
        for rdata in answers:
            txt_data = b''.join(rdata.strings).decode('utf-8')
            if txt_data.startswith('v=spf1'):
                spf_record = txt_data
                break
        
        if not spf_record:
            return {
                'status': 'error',
                'message': 'SPF record not found',
                'record': None,
                'has_strict_all': False,
                'includes_mx': False,
                'includes': []
            }
        
        # Check for different 'all' policies
        spf_lower = spf_record.lower()
        has_strict_all = '-all' in spf_lower
        has_soft_fail = '~all' in spf_lower
        has_neutral = '?all' in spf_lower
        has_pass_all = '+all' in spf_lower
        
        # Check for mx mechanism
        includes_mx = ' mx' in spf_record or spf_record.startswith('v=spf1 mx')
        
        # Extract include directives
        includes = []
        parts = spf_record.split()
        for part in parts:
            if part.startswith('include:'):
                includes.append(part.replace('include:', ''))
        
        # Determine status and message
        if has_strict_all:
            status = 'success'
            message = 'SPF configured correctly with strict -all policy'
            warnings = []
        elif has_soft_fail:
            status = 'warning'
            message = 'SPF uses ~all (soft fail). Consider using -all for stricter policy'
            warnings = ['Using ~all allows some spoofing attempts to pass']
        elif has_neutral:
            status = 'warning'
            message = 'SPF uses ?all (neutral). Consider using -all for stricter policy'
            warnings = ['Using ?all provides minimal protection']
        elif has_pass_all:
            status = 'error'
            message = 'SPF uses +all (allows any server). This provides no protection!'
            warnings = ['+all allows anyone to send email as your domain']
        else:
            status = 'error'
            message = 'SPF record missing "all" mechanism (no policy defined)'
            warnings = ['SPF should end with -all or ~all']
        
        return {
            'status': status,
            'message': message,
            'record': spf_record,
            'has_strict_all': has_strict_all,
            'includes_mx': includes_mx,
            'includes': includes,
            'warnings': warnings
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            'status': 'error',
            'message': 'Domain does not exist',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }
    except dns.resolver.NoAnswer:
        return {
            'status': 'error',
            'message': 'No TXT records found',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }
    except Exception as e:
        logger.error(f"Error checking SPF for {domain}: {e}")
        return {
            'status': 'error',
            'message': f'Failed to check SPF: {str(e)}',
            'record': None,
            'has_strict_all': False,
            'includes_mx': False,
            'includes': []
        }


async def check_dkim_record(domain: str) -> Dict[str, Any]:
    """
    Check DKIM record for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with DKIM check results
    """
    try:
        # Get DKIM configuration from Mailcow using httpx directly
        import httpx
        from app.config import settings
        
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                response = await client.get(
                    f"{settings.mailcow_url}/api/v1/get/dkim/{domain}",
                    headers={"X-API-Key": settings.mailcow_api_key}
                )
                response.raise_for_status()
                dkim_data = response.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error fetching DKIM from Mailcow for {domain}: {e.response.status_code}")
                return {
                    'status': 'error',
                    'message': f'Mailcow API error: HTTP {e.response.status_code}',
                    'selector': None,
                    'expected_record': None,
                    'actual_record': None,
                    'match': False
                }
            except httpx.RequestError as e:
                logger.error(f"Request error fetching DKIM from Mailcow for {domain}: {e}")
                return {
                    'status': 'error',
                    'message': 'Failed to connect to Mailcow API',
                    'selector': None,
                    'expected_record': None,
                    'actual_record': None,
                    'match': False
                }
        
        # Validate response structure - API can return either dict or list
        if isinstance(dkim_data, dict):
            # API returned dict directly
            dkim_config = dkim_data
        elif isinstance(dkim_data, list):
            # API returned list
            if len(dkim_data) == 0:
                logger.warning(f"DKIM not configured in Mailcow for {domain}")
                return {
                    'status': 'error',
                    'message': 'DKIM not configured in Mailcow',
                    'selector': None,
                    'expected_record': None,
                    'actual_record': None,
                    'match': False
                }
            # Get first element from list
            dkim_config = dkim_data[0]
        else:
            logger.error(f"DKIM API returned unexpected format for {domain}: {type(dkim_data)}")
            return {
                'status': 'error',
                'message': f'Invalid API response format: {type(dkim_data).__name__}',
                'selector': None,
                'expected_record': None,
                'actual_record': None,
                'match': False
            }
        
        # Validate required fields
        if not isinstance(dkim_config, dict):
            logger.error(f"DKIM config is not a dict for {domain}: {type(dkim_config)}")
            return {
                'status': 'error',
                'message': 'Invalid DKIM configuration format',
                'selector': None,
                'expected_record': None,
                'actual_record': None,
                'match': False
            }
        
        selector = dkim_config.get('dkim_selector', 'dkim')
        expected_value = dkim_config.get('dkim_txt', '')
        
        if not expected_value:
            logger.warning(f"DKIM record is empty in Mailcow for {domain}")
            return {
                'status': 'error',
                'message': 'DKIM record is empty in Mailcow configuration',
                'selector': selector,
                'expected_record': None,
                'actual_record': None,
                'match': False
            }
        
        # Construct DKIM domain
        dkim_domain = f"{selector}._domainkey.{domain}"
        
        # Query DKIM TXT record
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = await resolver.resolve(dkim_domain, 'TXT')
            
            # Get actual DKIM record
            actual_record = ''
            for rdata in answers:
                actual_record = b''.join(rdata.strings).decode('utf-8')
                break
            
            # Clean up records for comparison (remove whitespace)
            expected_clean = expected_value.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
            actual_clean = actual_record.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
            
            match = expected_clean == actual_clean
            
            if match:
                logger.info(f"DKIM check passed for {domain}")
            else:
                logger.warning(f"DKIM mismatch for {domain}")
            
            return {
                'status': 'success' if match else 'error',
                'message': 'DKIM configured correctly' if match else 'DKIM record mismatch',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': actual_record,
                'match': match
            }
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"DKIM record not found for {domain} at {dkim_domain}")
            return {
                'status': 'error',
                'message': f'DKIM record not found at {dkim_domain}',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False
            }
        except dns.resolver.NoAnswer:
            logger.warning(f"No TXT record at {dkim_domain} for {domain}")
            return {
                'status': 'error',
                'message': f'No TXT record at {dkim_domain}',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False
            }
        except dns.exception.Timeout:
            logger.error(f"DNS timeout checking DKIM for {domain}")
            return {
                'status': 'error',
                'message': 'DNS query timeout',
                'selector': selector,
                'dkim_domain': dkim_domain,
                'expected_record': expected_value,
                'actual_record': None,
                'match': False
            }
            
    except Exception as e:
        logger.error(f"Unexpected error checking DKIM for {domain}: {type(e).__name__} - {str(e)}")
        return {
            'status': 'error',
            'message': f'Failed to check DKIM: {type(e).__name__}',
            'selector': None,
            'expected_record': None,
            'actual_record': None,
            'match': False
        }


async def check_dmarc_record(domain: str) -> Dict[str, Any]:
    """
    Check DMARC record for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with DMARC check results
    """
    try:
        dmarc_domain = f"_dmarc.{domain}"
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Query DMARC TXT record
        answers = await resolver.resolve(dmarc_domain, 'TXT')
        
        # Get DMARC record
        dmarc_record = None
        for rdata in answers:
            txt_data = b''.join(rdata.strings).decode('utf-8')
            if txt_data.startswith('v=DMARC1'):
                dmarc_record = txt_data
                break
        
        if not dmarc_record:
            return {
                'status': 'error',
                'message': 'DMARC record not found',
                'record': None,
                'policy': None,
                'is_strong': False,
                'warnings': ['Add a DMARC record with at least "quarantine" policy']
            }
        
        # Extract policy
        import re
        policy_match = re.search(r'p=(none|quarantine|reject)', dmarc_record)
        policy = policy_match.group(1) if policy_match else 'unknown'
        
        # Check if policy is strong enough
        is_strong = policy in ['quarantine', 'reject']
        
        status = 'success' if is_strong else 'warning'
        message = f'DMARC configured with {policy} policy'
        
        if not is_strong:
            message = f'DMARC policy is too weak ({policy})'
        
        warnings = []
        if not is_strong:
            warnings.append('Consider using "quarantine" or "reject" policy for better email protection')
        
        return {
            'status': status,
            'message': message,
            'record': dmarc_record,
            'policy': policy,
            'is_strong': is_strong,
            'warnings': warnings
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            'status': 'error',
            'message': 'DMARC record not found',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': ['Add a DMARC record with at least "quarantine" policy']
        }
    except dns.resolver.NoAnswer:
        return {
            'status': 'error',
            'message': 'No DMARC record configured',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': ['Add a DMARC record with at least "quarantine" policy']
        }
    except Exception as e:
        logger.error(f"Error checking DMARC for {domain}: {e}")
        return {
            'status': 'error',
            'message': f'Failed to check DMARC: {str(e)}',
            'record': None,
            'policy': None,
            'is_strong': False,
            'warnings': []
        }


async def check_domain_dns(domain: str) -> Dict[str, Any]:
    """
    Check all DNS records (SPF, DKIM, DMARC) for a domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with all DNS check results
    """
    try:
        # Run all checks in parallel
        spf_result, dkim_result, dmarc_result = await asyncio.gather(
            check_spf_record(domain),
            check_dkim_record(domain),
            check_dmarc_record(domain)
        )
        
        return {
            'domain': domain,
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result,
            'checked_at': format_datetime_for_api(datetime.now(timezone.utc))
        }
        
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        return {
            'domain': domain,
            'error': str(e),
            'checked_at': format_datetime_for_api(datetime.now(timezone.utc))
        }


@router.get("/domains/all")
async def get_all_domains_with_dns(db: Session = Depends(get_db)):
    """Get all domains with cached DNS checks"""
    try:
        domains = await mailcow_api.get_domains()
        
        # Get last DNS check time FIRST
        last_check = db.query(DomainDNSCheck).filter(
        DomainDNSCheck.is_full_check == True
        ).order_by(
            DomainDNSCheck.checked_at.desc()
        ).first()
        
        if not domains:
            return {
                'domains': [],
                'total': 0,
                'active': 0,
                'last_dns_check': format_datetime_for_api(last_check.checked_at) if (last_check and last_check.checked_at) else None
            }
        
        result_domains = []
        for domain_data in domains:
            domain_name = domain_data.get('domain_name')
            if not domain_name:
                continue
            
            # Get cached DNS check
            dns_checks = get_cached_dns_check(db, domain_name)
            
            result_domains.append({
                'domain_name': domain_name,
                'active': domain_data.get('active', 0) == 1,
                'mboxes_in_domain': domain_data.get('mboxes_in_domain', 0),
                'mboxes_left': domain_data.get('mboxes_left', 0),
                'max_num_mboxes_for_domain': domain_data.get('max_num_mboxes_for_domain', 0),
                'aliases_in_domain': domain_data.get('aliases_in_domain', 0),
                'aliases_left': domain_data.get('aliases_left', 0),
                'max_num_aliases_for_domain': domain_data.get('max_num_aliases_for_domain', 0),
                'created': domain_data.get('created'),
                'bytes_total': domain_data.get('bytes_total', 0),
                'msgs_total': domain_data.get('msgs_total', 0),
                'quota_used_in_domain': domain_data.get('quota_used_in_domain', '0'),
                'max_quota_for_domain': domain_data.get('max_quota_for_domain', 0),
                'backupmx': domain_data.get('backupmx', 0) == 1,
                'relay_all_recipients': domain_data.get('relay_all_recipients', 0) == 1,
                'relay_unknown_only': domain_data.get('relay_unknown_only', 0) == 1,
                'dns_checks': dns_checks or {}
            })
        
        active_count = sum(1 for d in result_domains if d.get('active'))
        
        return {
            'domains': result_domains,
            'total': len(result_domains),
            'active': active_count,
            'last_dns_check': format_datetime_for_api(last_check.checked_at) if (last_check and last_check.checked_at) else None
        }
        
    except Exception as e:
        logger.error(f"Error fetching domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/domains/{domain}/dns-check")
async def check_single_domain_dns(domain: str):
    """
    Check DNS records for a specific domain
    
    Args:
        domain: Domain name to check
        
    Returns:
        DNS check results for the domain
    """
    try:
        dns_data = await check_domain_dns(domain)
        return dns_data
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def save_dns_check_to_db(db: Session, domain_name: str, dns_data: Dict[str, Any], is_full_check: bool = False):
    """Save DNS check results to database (upsert)"""
    try:
        checked_at = datetime.now(timezone.utc)
        
        existing = db.query(DomainDNSCheck).filter(
            DomainDNSCheck.domain_name == domain_name
        ).first()
        
        if existing:
            existing.spf_check = dns_data.get('spf')
            existing.dkim_check = dns_data.get('dkim')
            existing.dmarc_check = dns_data.get('dmarc')
            existing.checked_at = checked_at
            existing.updated_at = checked_at
            existing.is_full_check = is_full_check  # ← הוסף
        else:
            new_check = DomainDNSCheck(
                domain_name=domain_name,
                spf_check=dns_data.get('spf'),
                dkim_check=dns_data.get('dkim'),
                dmarc_check=dns_data.get('dmarc'),
                checked_at=checked_at,
                is_full_check=is_full_check  # ← הוסף
            )
            db.add(new_check)
        
        db.commit()
        logger.info(f"Saved DNS check for {domain_name}")
        
    except Exception as e:
        logger.error(f"Error saving DNS check for {domain_name}: {e}")
        db.rollback()
        raise


def get_cached_dns_check(db: Session, domain_name: str) -> Dict[str, Any]:
    """Get cached DNS check from database"""
    try:
        cached = db.query(DomainDNSCheck).filter(
            DomainDNSCheck.domain_name == domain_name
        ).first()
        
        if cached:
            return {
                'spf': cached.spf_check,
                'dkim': cached.dkim_check,
                'dmarc': cached.dmarc_check,
                'checked_at': format_datetime_for_api(cached.checked_at) if cached.checked_at else None
            }
        return None
        
    except Exception as e:
        logger.error(f"Error getting cached DNS for {domain_name}: {e}")
        return None


@router.post("/domains/check-all-dns")
async def check_all_domains_dns_manual(db: Session = Depends(get_db)):
    """Manually trigger DNS check for all active domains"""
    try:
        domains = await mailcow_api.get_domains()
        
        if not domains:
            return {
                'status': 'success',
                'message': 'No domains to check',
                'domains_checked': 0,
                'errors': []
            }
        
        active_domains = [d for d in domains if d.get('active', 0) == 1]
        
        checked_count = 0
        errors = []
        
        for domain_data in active_domains:
            domain_name = domain_data.get('domain_name')
            if not domain_name:
                continue
            
            try:
                dns_data = await check_domain_dns(domain_name)
                await save_dns_check_to_db(db, domain_name, dns_data, is_full_check=True)
                checked_count += 1
            except Exception as e:
                errors.append(f"{domain_name}: {str(e)}")
        
        status = 'success' if checked_count == len(active_domains) else 'partial'
        
        return {
            'status': status,
            'message': f'Checked {checked_count} domains',
            'domains_checked': checked_count,
            'errors': errors
        }
        
    except Exception as e:
        logger.error(f"Error in manual DNS check: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/domains/{domain}/check-dns")
async def check_single_domain_dns_manual(domain: str, db: Session = Depends(get_db)):
    """Manually trigger DNS check for a single domain"""
    try:
        dns_data = await check_domain_dns(domain)
        await save_dns_check_to_db(db, domain, dns_data, is_full_check=False)
        
        return {
            'status': 'success',
            'message': f'DNS checked for {domain}',
            'data': dns_data
        }
        
    except Exception as e:
        logger.error(f"Error checking DNS for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))