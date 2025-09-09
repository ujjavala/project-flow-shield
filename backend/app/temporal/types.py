"""Common types for Temporal workflows and activities"""
from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class UserCreateData:
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None

@dataclass
class UserUpdateData:
    user_id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    is_verified: Optional[bool] = None
    is_active: Optional[bool] = None

@dataclass
class RegistrationRequest:
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    
    def to_dict(self):
        """Convert to dictionary, excluding password for security"""
        data = asdict(self)
        data.pop('password', None)  # Remove password for security
        return data