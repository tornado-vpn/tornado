# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

from pydantic import BaseModel, EmailStr, Field, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from typing import Literal
from typing import List
from uuid import UUID



class ServiceControl(BaseModel):
    service_name: str = "all"
    action: Literal["start", "stop", "restart", "reload_config"]


class RelayIdRequest(BaseModel):
    id: str

class CircuitsRequest(BaseModel):
    id: Optional[str] = None


class ActionResponse(BaseModel):
    status: str
    message: Optional[str] = None






class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    max_devices: int = Field(default=1, ge=1, le=10)  # Add max_devices with default



class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    max_devices: Optional[int] = Field(None, ge=1, le=10)
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    is_active: bool
    max_devices: int  # ✅ ADD THIS FIELD
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserListItem(BaseModel):
    """Individual user in the list response"""
    id: UUID
    username: str
    email: str
    is_active: bool
    max_devices: int
    total_sessions: int
    total_bytes_tx: int
    total_bytes_rx: int
    created_at: datetime
    last_login_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PaginationInfo(BaseModel):
    """Pagination metadata"""
    limit: int
    offset: int
    total: int
    returned: int


class UsersListResponse(BaseModel):
    """Complete response for list_users endpoint"""
    status: str
    users: List[UserListItem]
    pagination: PaginationInfo


class SessionHistoryItem(BaseModel):
    """Individual session in history"""
    id: UUID
    session_key: str
    device_id: str
    public_key: Optional[str] = None
    vpn_ip: Optional[str] = None
    tor_ip: Optional[str] = None
    client_ip: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    bytes_tx: int
    bytes_rx: int
    total_bytes: int
    close_reason: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True


class UserBasicInfo(BaseModel):
    """Basic user info for session history"""
    id: UUID
    username: str
    email: str


class SessionStats(BaseModel):
    """Statistics for user sessions"""
    total_sessions: int
    active_sessions: int
    total_bytes_tx: int
    total_bytes_rx: int


class UserSessionsResponse(BaseModel):
    """Complete response for get_user_sessions"""
    status: str
    user: UserBasicInfo
    sessions: List[SessionHistoryItem]
    pagination: PaginationInfo  # Reuse from users list
    stats: SessionStats
