# Copyright (C) 2026 SRI DHARANIVEL A M
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv(dotenv_path="/opt/tornado/.env")

DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME")

DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=10,          # better for production
    max_overflow=20
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False
)
