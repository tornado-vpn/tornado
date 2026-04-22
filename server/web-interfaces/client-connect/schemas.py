# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

from pydantic import BaseModel, EmailStr, Field, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional
from typing import Literal



class VPNConnectRequest(BaseModel):
    public_key: str





class UserResponse(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ReauthRequest(BaseModel):
    refresh_token: str


class ReauthResponse(BaseModel):
    status: str
    tokens: dict 

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    access_jti: str
    refresh_jti: str


class UserOut(BaseModel):
    id: UUID
    username: str
    email: str
    is_active: bool


class AuthResponse(BaseModel):
    status: Literal["ok"]
    user: UserOut
    tokens: TokenResponse
    device_id: UUID



class LogoutRequest(BaseModel):
    refresh_token: str

class LogoutResponse(BaseModel):
    status: str


class EncryptedLoginRequest(BaseModel):
    ephemeral_pubkey: str   # base64 raw X25519 public key (32 bytes)
    iv:               str   # base64 12-byte GCM nonce
    ciphertext:       str   # base64 AES-256-GCM ciphertext + 16-byte tag
