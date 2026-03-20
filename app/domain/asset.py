from pydantic import BaseModel, field_validator
from enum import Enum
from typing import Optional
import re


class AssetType(str, Enum):
    domain = "domain"
    ip = "ip"
    service = "service"


class AssetStatus(str, Enum):
    active = "active"
    inactive = "inactive"


class Asset(BaseModel):
    id: Optional[str] = None
    name: str
    type: AssetType
    status: AssetStatus = AssetStatus.active

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 255:
            raise ValueError("name too long (max 255 chars)")
        # Defense-in-depth: block obviously malicious patterns
        if re.search(r"[\x00\x1a]", v):
            raise ValueError("name contains invalid characters")
        return v


class AssetStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_status: dict[str, int]
