-- ============================================================
-- Extensions
-- ============================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Utility functions
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

-- ============================================================
-- users
-- ============================================================
CREATE TABLE public.users (
    id                uuid        PRIMARY KEY DEFAULT uuid_generate_v4(),
    username          text        NOT NULL,
    email             text        NOT NULL,
    password_hash     text        NOT NULL,
    is_active         boolean     NOT NULL DEFAULT true,
    max_devices       integer     NOT NULL DEFAULT 1 CHECK (max_devices > 0),
    total_sessions    bigint      NOT NULL DEFAULT 0 CHECK (total_sessions >= 0),
    total_bytes_tx    bigint      NOT NULL DEFAULT 0 CHECK (total_bytes_tx >= 0),
    total_bytes_rx    bigint      NOT NULL DEFAULT 0 CHECK (total_bytes_rx >= 0),
    last_login_at     timestamptz,
    last_seen_at      timestamptz,
    last_client_ip    inet,
    last_device_id    varchar(100),
    deleted_at        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT NOW(),
    updated_at        timestamptz NOT NULL DEFAULT NOW()
);

-- Partial unique indexes — enforce uniqueness only among active (non-deleted) rows
CREATE UNIQUE INDEX uq_users_username_active ON public.users (username)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX uq_users_email_active ON public.users (email)
    WHERE deleted_at IS NULL;

-- Fast soft-delete lookups
CREATE INDEX idx_users_active ON public.users (id)
    WHERE deleted_at IS NULL;

-- Drop the old one first if it exists
DROP TRIGGER IF EXISTS update_users_modtime ON public.users;

-- Drop old trigger if exists
DROP TRIGGER IF EXISTS trg_users_set_updated_at ON public.users;

-- Create correct trigger
CREATE TRIGGER trg_users_set_updated_at
    BEFORE UPDATE ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE  public.users                IS 'User accounts. Soft-deleted via deleted_at.';
COMMENT ON COLUMN public.users.password_hash  IS 'Argon2id hash of the user password.';
COMMENT ON COLUMN public.users.max_devices    IS 'Maximum concurrent WireGuard devices allowed.';
COMMENT ON COLUMN public.users.total_bytes_tx IS 'Lifetime bytes transmitted (VPN → client).';
COMMENT ON COLUMN public.users.total_bytes_rx IS 'Lifetime bytes received (client → VPN).';

-- ============================================================
-- auth_sessions  (renamed from "sessions" for clarity)
-- ============================================================
CREATE TABLE public.auth_sessions (
    id                 uuid        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id            uuid        NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    refresh_token_hash text        UNIQUE,
    user_agent         text,
    ip_address         inet,
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_sessions_user_id   ON public.auth_sessions (user_id);
CREATE INDEX idx_auth_sessions_expires_at ON public.auth_sessions (expires_at);

COMMENT ON TABLE  public.auth_sessions                    IS 'HTTP auth sessions with refresh tokens.';
COMMENT ON COLUMN public.auth_sessions.refresh_token_hash IS 'bcrypt/Argon2 hash of the refresh token.';
COMMENT ON COLUMN public.auth_sessions.expires_at         IS 'Hard expiry; rows beyond this are purgeable.';

-- ============================================================
-- wg_sessions  (active WireGuard tunnels)
-- ============================================================
CREATE TABLE public.wg_sessions (
    id                uuid        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           uuid        NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    device_id         uuid        NOT NULL,
    public_key        text        NOT NULL,
    assigned_ip       inet        NOT NULL,
    client_ip         inet,
    user_agent        text,
    bytes_transmitted bigint      NOT NULL DEFAULT 0 CHECK (bytes_transmitted >= 0),
    bytes_received    bigint      NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
    started_at        timestamptz NOT NULL DEFAULT NOW(),
    ended_at          timestamptz,
    last_handshake_at timestamptz,
    termination_reason text,

    CONSTRAINT chk_wg_sessions_ended_after_started
        CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX idx_wg_sessions_user_id   ON public.wg_sessions (user_id);
CREATE INDEX idx_wg_sessions_device_id ON public.wg_sessions (device_id);
CREATE INDEX idx_wg_sessions_active    ON public.wg_sessions (user_id)
    WHERE ended_at IS NULL;

COMMENT ON TABLE  public.wg_sessions             IS 'Active and historical WireGuard tunnel sessions.';
COMMENT ON COLUMN public.wg_sessions.public_key  IS 'Client WireGuard public key (Base64).';
COMMENT ON COLUMN public.wg_sessions.assigned_ip IS 'VPN tunnel IP assigned to this device.';

-- ============================================================
-- vpn_session_history  (append-only audit log)
-- ============================================================
CREATE TABLE public.vpn_session_history (
    id           uuid        PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_key  text        NOT NULL UNIQUE,
    user_id      uuid        NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
    device_id    text        NOT NULL,
    public_key   text,
    vpn_ip       inet,
    tor_ip       inet,
    client_ip    inet,
    bytes_tx     bigint      NOT NULL DEFAULT 0 CHECK (bytes_tx >= 0),
    bytes_rx     bigint      NOT NULL DEFAULT 0 CHECK (bytes_rx >= 0),
    close_reason text,
    started_at   timestamptz NOT NULL,
    ended_at     timestamptz,
    created_at   timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_vpn_history_ended_after_started
        CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX idx_vpn_history_user_id    ON public.vpn_session_history (user_id);
CREATE INDEX idx_vpn_history_started_at ON public.vpn_session_history (started_at DESC);
CREATE INDEX idx_vpn_history_session_key ON public.vpn_session_history (session_key);

COMMENT ON TABLE  public.vpn_session_history             IS 'Immutable audit log of completed VPN sessions.';
COMMENT ON COLUMN public.vpn_session_history.session_key IS 'Opaque external key linking to the live session.';
COMMENT ON COLUMN public.vpn_session_history.tor_ip      IS 'Exit node IP when routing through Tor.';