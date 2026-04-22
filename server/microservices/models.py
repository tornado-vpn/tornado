# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import uuid
from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, BigInteger,Integer
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base, relationship
Base = declarative_base()




class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    max_devices = Column(Integer, nullable=False, default=1)

    # ---- Aggregated usage stats (NEW) ----
    total_sessions = Column(BigInteger, nullable=False, default=0)
    total_bytes_tx = Column(BigInteger, nullable=False, default=0)
    total_bytes_rx = Column(BigInteger, nullable=False, default=0)

    last_seen_at = Column(DateTime(timezone=True))
    last_client_ip = Column(INET)
    last_device_id = Column(String(100),nullable=True)

    # ---- Audit timestamps ----
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True),nullable=False,server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime(timezone=True))
    deleted_at = Column(DateTime(timezone=True))

    # App-level sessions (if you still use them)
    sessions = relationship("Session", cascade="all, delete-orphan")



class Session(Base):
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))

    refresh_token_hash = Column(String, unique=True)
    user_agent = Column(String)
    ip_address = Column(INET)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class WGSession(Base):
    __tablename__ = "wg_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))

    public_key = Column(String, unique=True, nullable=False)
    assigned_ip = Column(INET, unique=True, nullable=False)

    bytes_transmitted = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_handshake_at = Column(DateTime(timezone=True))



class vpn_session_history(Base):
    __tablename__ = "vpn_session_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


    # Runtime / wire identifier (composite)
    session_key = Column(String, unique=True, nullable=False, index=True)

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String, nullable=False)

    public_key = Column(String)

    vpn_ip = Column(INET)
    tor_ip = Column(INET)
    client_ip = Column(INET)

    started_at = Column(DateTime(timezone=True), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)

    bytes_tx = Column(BigInteger, nullable=False, default=0)
    bytes_rx = Column(BigInteger, nullable=False, default=0)

    close_reason = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
