"""
Version management - reads version from VERSION file
"""
import os
from pathlib import Path

def get_version() -> str:
    """
    Read version from VERSION file in project root
    
    Returns:
        Version string (e.g., "1.4.2")
    """
    # Try multiple possible paths
    possible_paths = [
        Path("/app/VERSION"),  # Docker container path
        Path(__file__).parent.parent.parent / "VERSION",  # Development path
        Path(__file__).parent.parent.parent.parent / "VERSION",  # Alternative dev path
    ]
    
    for version_path in possible_paths:
        if version_path.exists():
            try:
                with open(version_path, "r") as f:
                    version = f.read().strip()
                    if version:
                        return version
            except Exception as e:
                print(f"Error reading VERSION file from {version_path}: {e}")
                continue
    
    # Fallback to default version if file not found
    return "1.4.2"

# Cache the version on import
__version__ = get_version()

