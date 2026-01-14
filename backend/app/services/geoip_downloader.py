"""
MaxMind GeoIP Auto-Downloader
Downloads and updates GeoLite2 databases automatically
"""
import logging
import os
import tarfile
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)

# Configuration from environment
MAXMIND_LICENSE_KEY = os.getenv('MAXMIND_LICENSE_KEY', '')
MAXMIND_ACCOUNT_ID = os.getenv('MAXMIND_ACCOUNT_ID', '')
GEOIP_DB_DIR = os.getenv('GEOIP_DB_DIR', '/app/data')

# Database paths
GEOIP_CITY_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-City.mmdb')
GEOIP_ASN_DB_PATH = os.path.join(GEOIP_DB_DIR, 'GeoLite2-ASN.mmdb')

# MaxMind download URL
MAXMIND_DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"

# Update frequency (days)
UPDATE_CHECK_DAYS = 7

# Databases to download
DATABASES = {
    'City': {
        'edition_id': 'GeoLite2-City',
        'path': GEOIP_CITY_DB_PATH,
        'description': 'Country + City + Coordinates'
    },
    'ASN': {
        'edition_id': 'GeoLite2-ASN',
        'path': GEOIP_ASN_DB_PATH,
        'description': 'ASN + ISP information'
    }
}


def is_license_configured() -> bool:
    """Check if MaxMind license key is configured"""
    return bool(MAXMIND_LICENSE_KEY and MAXMIND_ACCOUNT_ID)


def get_db_age_days(db_path: str) -> int:
    """
    Get age of database in days
    Returns -1 if database doesn't exist
    """
    path = Path(db_path)
    
    if not path.exists():
        return -1
    
    # Get file modification time
    mtime = path.stat().st_mtime
    modified_date = datetime.fromtimestamp(mtime)
    age_days = (datetime.now() - modified_date).days
    
    return age_days


def should_update_database(db_name: str) -> bool:
    """
    Check if database should be updated
    Returns True if:
    - Database doesn't exist
    - Database is older than UPDATE_CHECK_DAYS days
    """
    db_path = DATABASES[db_name]['path']
    age_days = get_db_age_days(db_path)
    
    if age_days == -1:
        logger.info(f"{db_name} database not found, download required")
        return True
    
    if age_days >= UPDATE_CHECK_DAYS:
        logger.info(f"{db_name} database is {age_days} days old, update required")
        return True
    
    logger.info(f"{db_name} database is {age_days} days old, no update needed")
    return False


def download_single_database(db_name: str) -> bool:
    """
    Download a single GeoIP database from MaxMind
    
    Args:
        db_name: 'City' or 'ASN'
    
    Returns:
        True if successful, False otherwise
    """
    db_info = DATABASES[db_name]
    
    try:
        logger.info(f"Downloading GeoLite2-{db_name} database from MaxMind...")
        logger.info(f"  ({db_info['description']})")
        
        # Construct download URL
        params = {
            'edition_id': db_info['edition_id'],
            'license_key': MAXMIND_LICENSE_KEY,
            'suffix': 'tar.gz'
        }
        
        # Download
        response = requests.get(MAXMIND_DOWNLOAD_URL, params=params, stream=True, timeout=300)
        
        if response.status_code == 401:
            logger.error("MaxMind license key is invalid or expired")
            return False
        
        if response.status_code != 200:
            logger.error(f"Failed to download {db_name} database: HTTP {response.status_code}")
            return False
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
            tmp_path = tmp_file.name
            
            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            for chunk in response.iter_content(chunk_size=8192):
                tmp_file.write(chunk)
                downloaded += len(chunk)
                
                if total_size > 0 and downloaded % (5 * 1024 * 1024) == 0:  # Log every 5MB
                    progress = (downloaded / total_size) * 100
                    logger.info(f"  Download progress: {progress:.1f}%")
        
        size_mb = downloaded / (1024 * 1024)
        logger.info(f"  Downloaded {size_mb:.1f}MB")
        
        # Extract tar.gz
        logger.info(f"  Extracting GeoLite2-{db_name} database...")
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            with tarfile.open(tmp_path, 'r:gz') as tar:
                tar.extractall(tmp_dir)
            
            # Find the .mmdb file (it's in a subdirectory)
            mmdb_files = list(Path(tmp_dir).rglob('*.mmdb'))
            
            if not mmdb_files:
                logger.error(f"No .mmdb file found in downloaded {db_name} archive")
                os.unlink(tmp_path)
                return False
            
            mmdb_file = mmdb_files[0]
            
            # Ensure destination directory exists
            os.makedirs(GEOIP_DB_DIR, exist_ok=True)
            
            # Move to destination
            import shutil
            shutil.copy2(mmdb_file, db_info['path'])
            
            logger.info(f"✓ GeoLite2-{db_name} database installed at {db_info['path']}")
        
        # Cleanup
        os.unlink(tmp_path)
        
        # Log database info
        db_size = Path(db_info['path']).stat().st_size / (1024 * 1024)
        logger.info(f"  Database size: {db_size:.1f}MB")
        
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error downloading {db_name} database: {e}")
        return False
    except Exception as e:
        logger.error(f"Error downloading {db_name} database: {e}")
        return False


def download_geoip_databases() -> dict:
    """
    Download both City and ASN databases from MaxMind
    
    Returns:
        {'City': bool, 'ASN': bool} - success status for each database
    """
    if not is_license_configured():
        logger.warning("MaxMind license key not configured, skipping download")
        return {'City': False, 'ASN': False}
    
    results = {}
    
    for db_name in ['City', 'ASN']:
        if should_update_database(db_name):
            results[db_name] = download_single_database(db_name)
        else:
            logger.info(f"{db_name} database is up to date, skipping download")
            results[db_name] = True  # Already exists and up-to-date
    
    return results


def update_geoip_database_if_needed() -> dict:
    """
    Update GeoIP databases if needed
    Called on startup and periodically
    
    Returns:
        {
            'City': {'available': bool, 'updated': bool},
            'ASN': {'available': bool, 'updated': bool}
        }
    """
    if not is_license_configured():
        logger.info("MaxMind license key not configured, GeoIP features will be disabled")
        return {
            'City': {'available': False, 'updated': False},
            'ASN': {'available': False, 'updated': False}
        }
    
    status = {}
    
    for db_name in ['City', 'ASN']:
        db_path = DATABASES[db_name]['path']
        needs_update = should_update_database(db_name)
        
        if not needs_update:
            # Already up-to-date
            status[db_name] = {
                'available': True,
                'updated': False  # Didn't need update
            }
            continue
        
        # Download
        success = download_single_database(db_name)
        
        if success:
            status[db_name] = {
                'available': True,
                'updated': True
            }
        else:
            # Check if old database exists
            if Path(db_path).exists():
                logger.info(f"Using existing (outdated) {db_name} database")
                status[db_name] = {
                    'available': True,
                    'updated': False
                }
            else:
                logger.error(f"No {db_name} database available")
                status[db_name] = {
                    'available': False,
                    'updated': False
                }
    
    return status


def get_geoip_status() -> dict:
    """
    Get current GeoIP databases status
    
    Returns:
        {
            'configured': bool,
            'City': {
                'available': bool,
                'age_days': int,
                'size_mb': float,
                'last_modified': str
            },
            'ASN': {
                'available': bool,
                'age_days': int,
                'size_mb': float,
                'last_modified': str
            }
        }
    """
    status = {
        'configured': is_license_configured(),
        'City': {
            'available': False,
            'age_days': -1,
            'size_mb': 0,
            'last_modified': None
        },
        'ASN': {
            'available': False,
            'age_days': -1,
            'size_mb': 0,
            'last_modified': None
        }
    }
    
    for db_name in ['City', 'ASN']:
        db_path = Path(DATABASES[db_name]['path'])
        
        if db_path.exists():
            status[db_name]['available'] = True
            status[db_name]['age_days'] = get_db_age_days(str(db_path))
            status[db_name]['size_mb'] = round(db_path.stat().st_size / (1024 * 1024), 1)
            
            mtime = db_path.stat().st_mtime
            status[db_name]['last_modified'] = datetime.fromtimestamp(mtime).isoformat()
    
    return status