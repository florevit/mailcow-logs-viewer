"""
Load/save app config overrides from DB (system_settings table, keys config.*).
Used when SETTINGS_EDIT_VIA_UI_ENABLED is True.
"""
import json
import logging
from typing import Dict, Any

from sqlalchemy.orm import Session

from ..models import SystemSetting

logger = logging.getLogger(__name__)

CONFIG_PREFIX = "config."


def _serialize_value(value: Any) -> str:
    """Serialize a Python value to string for DB storage."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def _get_effective_type(annotation: type) -> type:
    """Resolve Optional[X] / Union[X, None] to X for type-based coercion."""
    if getattr(annotation, "__args__", None):
        args = [a for a in annotation.__args__ if a is not type(None)]
        if args:
            return args[0]
    return annotation


def _deserialize_value(value_str: str, field_name: str, annotation: type) -> Any:
    """Deserialize DB string to Python value based on field type."""
    effective = _get_effective_type(annotation)
    is_optional = getattr(annotation, "__args__", None) and type(None) in getattr(annotation, "__args__", ())
    if value_str is None or value_str == "":
        if is_optional:
            return None
        if effective == bool:
            return False
        if effective == int:
            return 0
        return ""
    if effective == bool:
        return value_str.lower() in ("true", "1", "yes")
    if effective == int:
        try:
            return int(value_str)
        except ValueError:
            return 0
    if effective == float:
        try:
            return float(value_str)
        except ValueError:
            return 0.0
    return value_str


def has_config_overrides_in_db(db: Session) -> bool:
    """Return True if any config.* override exists in system_settings (migration was done)."""
    return db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).first() is not None


def get_config_overrides_from_db(db: Session, field_types: Dict[str, type]) -> Dict[str, Any]:
    """
    Load all config.* keys from system_settings and return as dict of field_name -> value.
    Values are coerced to types from field_types (e.g. from Settings model).
    """
    rows = db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).all()
    out = {}
    for row in rows:
        key = row.key
        if not key.startswith(CONFIG_PREFIX):
            continue
        field_name = key[len(CONFIG_PREFIX) :]
        if field_name not in field_types:
            continue
        annotation = field_types[field_name]
        try:
            out[field_name] = _deserialize_value(row.value or "", field_name, annotation)
        except Exception as e:
            logger.warning("Skip config key %s: %s", field_name, e)
    return out


def save_config_overrides_to_db(db: Session, overrides: Dict[str, Any]) -> None:
    """
    Upsert config overrides into system_settings (keys config.<field_name>).
    Only keys present in overrides are updated; pass full set to replace all UI config.
    """
    for field_name, value in overrides.items():
        key = CONFIG_PREFIX + field_name
        value_str = _serialize_value(value)
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = value_str
        else:
            row = SystemSetting(key=key, value=value_str)
            db.add(row)
    db.commit()


def delete_all_config_overrides_from_db(db: Session) -> None:
    """Remove all config.* keys from system_settings (e.g. to reset to ENV-only)."""
    db.query(SystemSetting).filter(SystemSetting.key.startswith(CONFIG_PREFIX)).delete(synchronize_session=False)
    db.commit()
