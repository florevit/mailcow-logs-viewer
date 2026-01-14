"""
GeoIP Service for DMARC
Uses MaxMind GeoLite2-City and GeoLite2-ASN databases
"""
import logging
from typing import Optional, Dict
from pathlib import Path

logger = logging.getLogger(__name__)

GEOIP_CITY_DB_PATH = "/app/data/GeoLite2-City.mmdb"
GEOIP_ASN_DB_PATH = "/app/data/GeoLite2-ASN.mmdb"

_city_reader = None
_asn_reader = None
_geoip_available = None


def is_geoip_available() -> bool:
    """Check if GeoIP databases are available"""
    global _geoip_available
    
    if _geoip_available is None:
        city_exists = Path(GEOIP_CITY_DB_PATH).exists()
        asn_exists = Path(GEOIP_ASN_DB_PATH).exists()
        
        _geoip_available = city_exists
        
        if not city_exists:
            logger.warning(f"GeoIP City database not found at {GEOIP_CITY_DB_PATH}")
            logger.info("GeoIP features will be disabled. To enable, configure MAXMIND_LICENSE_KEY")
        
        if not asn_exists:
            logger.warning(f"GeoIP ASN database not found at {GEOIP_ASN_DB_PATH}")
            logger.info("ASN information will not be available")
    
    return _geoip_available


def get_city_reader():
    """Get or create GeoIP City database reader"""
    global _city_reader
    
    if not Path(GEOIP_CITY_DB_PATH).exists():
        return None
    
    if _city_reader is None:
        try:
            import geoip2.database
            _city_reader = geoip2.database.Reader(GEOIP_CITY_DB_PATH)
            logger.info(f"✓ GeoIP City database loaded from {GEOIP_CITY_DB_PATH}")
        except ImportError:
            logger.error("geoip2 module not installed. Install with: pip install geoip2")
            _city_reader = None
        except Exception as e:
            logger.error(f"Failed to load GeoIP City database: {e}")
            _city_reader = None
    
    return _city_reader


def get_asn_reader():
    """Get or create GeoIP ASN database reader"""
    global _asn_reader
    
    if not Path(GEOIP_ASN_DB_PATH).exists():
        return None
    
    if _asn_reader is None:
        try:
            import geoip2.database
            _asn_reader = geoip2.database.Reader(GEOIP_ASN_DB_PATH)
            logger.info(f"✓ GeoIP ASN database loaded from {GEOIP_ASN_DB_PATH}")
        except ImportError:
            logger.error("geoip2 module not installed. Install with: pip install geoip2")
            _asn_reader = None
        except Exception as e:
            logger.error(f"Failed to load GeoIP ASN database: {e}")
            _asn_reader = None
    
    return _asn_reader


def get_country_emoji(country_code: str) -> str:
    """
    Convert ISO country code to flag emoji
    Example: 'US' -> '🇺🇸'
    """
    if not country_code or len(country_code) != 2:
        return '🌍'
    
    try:
        code_points = [127462 + ord(c) - ord('A') for c in country_code.upper()]
        return ''.join(chr(c) for c in code_points)
    except:
        return '🌍'


def lookup_ip(ip_address: str) -> Dict[str, Optional[str]]:
    """
    Lookup IP address and return geo information
    Uses both City and ASN databases
    
    Returns:
        {
            'country_code': 'US',
            'country_name': 'United States',
            'city': 'Mountain View',
            'asn': 'AS15169',
            'asn_org': 'Google LLC'
        }
    
    If GeoIP is not available, returns all None values (graceful degradation)
    """
    result = {
        'country_code': None,
        'country_name': None,
        'city': None,
        'asn': None,
        'asn_org': None
    }
    
    city_reader = get_city_reader()
    if city_reader:
        try:
            import geoip2.errors
            
            response = city_reader.city(ip_address)
            
            if response.country.iso_code:
                result['country_code'] = response.country.iso_code
                result['country_name'] = response.country.name
            
            if response.city.name:
                result['city'] = response.city.name
            
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Error looking up IP {ip_address} in City database: {e}")
    
    asn_reader = get_asn_reader()
    if asn_reader:
        try:
            import geoip2.errors
            
            response = asn_reader.asn(ip_address)
            
            if response.autonomous_system_number:
                result['asn'] = f"AS{response.autonomous_system_number}"
            
            if response.autonomous_system_organization:
                result['asn_org'] = response.autonomous_system_organization
            
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Error looking up IP {ip_address} in ASN database: {e}")
    
    return result


def enrich_dmarc_record(record_data: Dict) -> Dict:
    """
    Enrich DMARC record with GeoIP data
    
    Args:
        record_data: Dictionary with 'source_ip' key
    
    Returns:
        Enhanced dictionary with geo data (or None values if GeoIP unavailable)
    """
    if not is_geoip_available():
        record_data.update({
            'country_code': None,
            'country_name': None,
            'country_emoji': '🌍',
            'city': None,
            'asn': None,
            'asn_org': None
        })
        return record_data
    
    if 'source_ip' in record_data:
        geo_info = lookup_ip(record_data['source_ip'])
        record_data.update(geo_info)
        record_data['country_emoji'] = get_country_emoji(geo_info.get('country_code'))

    return record_data


def reload_geoip_readers():
    """
    Reload GeoIP readers (after database update)
    Call this after downloading new databases
    """
    global _city_reader, _asn_reader, _geoip_available
    
    if _city_reader:
        try:
            _city_reader.close()
        except:
            pass
        _city_reader = None
    
    if _asn_reader:
        try:
            _asn_reader.close()
        except:
            pass
        _asn_reader = None
    
    _geoip_available = None
    
    city_ok = get_city_reader() is not None
    asn_ok = get_asn_reader() is not None
    
    if city_ok and asn_ok:
        logger.info("✓ GeoIP databases reloaded successfully (City + ASN)")
        return True
    elif city_ok:
        logger.info("✓ GeoIP City database reloaded (ASN unavailable)")
        return True
    else:
        logger.warning("Failed to reload GeoIP databases")
        return False