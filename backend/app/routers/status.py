"""
API endpoints for system status and health monitoring
"""
import logging
import httpx
from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
from typing import Dict, Any

from ..mailcow_api import mailcow_api

logger = logging.getLogger(__name__)

router = APIRouter()

# Cache for version check (check once per day)
version_cache = {
    "checked_at": None,
    "current_version": None,
    "latest_version": None,
    "update_available": False,
    "changelog": None
}

@router.get("/status/containers")
async def get_containers_status():
    """
    Get status of all Mailcow containers
    Returns simplified container info: name (without -mailcow), state, started_at
    """
    try:
        containers_data = await mailcow_api.get_status_containers()
        
        if not containers_data or len(containers_data) == 0:
            return {"containers": {}, "summary": {"running": 0, "stopped": 0, "total": 0}}
        
        # Extract the containers dict from the list
        containers_dict = containers_data[0] if isinstance(containers_data, list) else containers_data
        
        # Build simplified response
        simplified_containers = {}
        running_count = 0
        stopped_count = 0
        
        for container_key, info in containers_dict.items():
            # Get state
            state = info.get('state', 'unknown')
            if state == 'running':
                running_count += 1
            else:
                stopped_count += 1
            
            # Simplify container name (remove -mailcow suffix)
            display_name = container_key.replace('-mailcow', '')
            
            # Build simplified entry
            simplified_containers[container_key] = {
                "name": display_name,
                "state": state,
                "started_at": info.get('started_at', None)
            }
        
        return {
            "containers": simplified_containers,
            "summary": {
                "running": running_count,
                "stopped": stopped_count,
                "total": len(simplified_containers)
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching container status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch container status: {str(e)}")

@router.get("/status/storage")
async def get_storage_status():
    """
    Get storage/disk usage information
    """
    try:
        vmail_data = await mailcow_api.get_status_vmail()
        
        if not vmail_data:
            return {
                "disk": "unknown",
                "used": "0",
                "total": "0",
                "used_percent": "0%"
            }
        
        return {
            "disk": vmail_data.get('disk', 'unknown'),
            "used": vmail_data.get('used', '0'),
            "total": vmail_data.get('total', '0'),
            "used_percent": vmail_data.get('used_percent', '0%')
        }
        
    except Exception as e:
        logger.error(f"Error fetching storage status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to fetch storage status: {str(e)}")

@router.get("/status/version")
async def get_version_status():
    """
    Get current Mailcow version and check for updates
    Checks GitHub once per day and caches the result
    """
    try:
        global version_cache
        
        # Check if we need to refresh the cache (once per day)
        now = datetime.utcnow()
        if (version_cache["checked_at"] is None or 
            now - version_cache["checked_at"] > timedelta(days=1)):
            
            logger.info("Checking Mailcow version and updates...")
            
            # Get current version
            current_version = await mailcow_api.get_status_version()
            version_cache["current_version"] = current_version
            
            # Check GitHub for latest version
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(
                        "https://api.github.com/repos/mailcow/mailcow-dockerized/releases/latest"
                    )
                    
                    if response.status_code == 200:
                        release_data = response.json()
                        latest_version = release_data.get('tag_name', 'unknown')
                        changelog = release_data.get('body', '')
                        
                        version_cache["latest_version"] = latest_version
                        version_cache["changelog"] = changelog
                        
                        # Compare versions (simple string comparison)
                        version_cache["update_available"] = current_version != latest_version
                        
                        logger.info(f"Version check: Current={current_version}, Latest={latest_version}")
                    else:
                        logger.warning(f"GitHub API returned status {response.status_code}")
                        version_cache["latest_version"] = "unknown"
                        version_cache["update_available"] = False
                        
            except Exception as e:
                logger.error(f"Failed to check GitHub for updates: {e}")
                version_cache["latest_version"] = "unknown"
                version_cache["update_available"] = False
            
            version_cache["checked_at"] = now
        
        return {
            "current_version": version_cache["current_version"],
            "latest_version": version_cache["latest_version"],
            "update_available": version_cache["update_available"],
            "changelog": version_cache["changelog"],
            "last_checked": version_cache["checked_at"].isoformat() if version_cache["checked_at"] else None
        }
    except Exception as e:
        logger.error(f"Error fetching version status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/mailcow-info")
async def get_mailcow_info():
    """
    Get Mailcow system information (domains, mailboxes, aliases)
    """
    try:
        # Fetch all info in parallel
        import asyncio
        domains, mailboxes, aliases = await asyncio.gather(
            mailcow_api.get_domains(),
            mailcow_api.get_mailboxes(),
            mailcow_api.get_aliases()
        )
        
        # Count active items
        active_domains = sum(1 for d in domains if d.get('active', 0) == 1)
        active_mailboxes = sum(1 for m in mailboxes if m.get('active', 0) == 1)
        active_aliases = sum(1 for a in aliases if a.get('active', 0) == 1)
        
        return {
            "domains": {
                "total": len(domains),
                "active": active_domains
            },
            "mailboxes": {
                "total": len(mailboxes),
                "active": active_mailboxes
            },
            "aliases": {
                "total": len(aliases),
                "active": active_aliases
            }
        }
    except Exception as e:
        logger.error(f"Error fetching Mailcow info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/summary")
async def get_status_summary():
    """
    Get combined status summary for dashboard
    """
    try:
        import asyncio
        
        # Fetch all status info in parallel
        containers_data, storage_data, mailcow_info = await asyncio.gather(
            get_containers_status(),
            get_storage_status(),
            get_mailcow_info(),
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(containers_data, Exception):
            containers_data = {"summary": {"running": 0, "stopped": 0, "total": 0}}
        if isinstance(storage_data, Exception):
            storage_data = {"used_percent": "0%"}
        if isinstance(mailcow_info, Exception):
            mailcow_info = {"domains": {"total": 0}, "mailboxes": {"total": 0}, "aliases": {"total": 0}}
        
        return {
            "containers": containers_data.get("summary", {}),
            "storage": {
                "used_percent": storage_data.get("used_percent", "0%"),
                "used": storage_data.get("used", "0"),
                "total": storage_data.get("total", "0")
            },
            "system": {
                "domains": mailcow_info.get("domains", {}).get("total", 0),
                "mailboxes": mailcow_info.get("mailboxes", {}).get("total", 0),
                "aliases": mailcow_info.get("aliases", {}).get("total", 0)
            }
        }
    except Exception as e:
        logger.error(f"Error fetching status summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))