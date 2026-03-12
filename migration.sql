-- ============================================================
-- DATABASE MIGRATION - Vumbua eFootball Tournament
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- PROFILES
-- ============================================================

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username TEXT UNIQUE NOT NULL,
    team_name TEXT,
    account_status TEXT DEFAULT 'active',
    id_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- WALLETS
-- ============================================================

CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    balance DECIMAL(15,2) DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- TRANSACTIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    type TEXT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'pending',
    reference TEXT,
    checkout_request_id TEXT,
    merchant_request_id TEXT,
    mpesa_receipt TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- ============================================================
-- WITHDRAWALS
-- ============================================================

CREATE TABLE IF NOT EXISTS withdrawals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    phone_number TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    mpesa_transaction_id TEXT,
    mpesa_receipt_number TEXT,
    mpesa_code TEXT,
    user_ip TEXT,
    user_agent TEXT,
    failure_reason TEXT,
    retry_count INTEGER DEFAULT 0,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    reject_reason TEXT,
    review_notes TEXT
);

-- ============================================================
-- TOURNAMENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS tournaments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    entry_fee DECIMAL(15,2) NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    max_players INTEGER NOT NULL,
    room_code TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

-- ============================================================
-- BOOKINGS
-- ============================================================

CREATE TABLE IF NOT EXISTS bookings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tournament_id UUID REFERENCES tournaments(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    room_code TEXT,
    status TEXT DEFAULT 'confirmed',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tournament_id, user_id)
);

-- ============================================================
-- FRIEND MATCHES
-- ============================================================

CREATE TABLE IF NOT EXISTS friend_matches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    match_code TEXT UNIQUE NOT NULL,
    efootball_room_code TEXT,

    creator_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    creator_team TEXT,
    joiner_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    joiner_team TEXT,

    wager_amount DECIMAL(15,2) NOT NULL,
    platform_fee DECIMAL(15,2) DEFAULT 0,
    winner_prize DECIMAL(15,2) NOT NULL,

    status TEXT DEFAULT 'pending',

    expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,

    declared_score_creator INTEGER,
    declared_score_joiner INTEGER,
    declared_score_by UUID,
    declared_at TIMESTAMPTZ,
    declared_winner_id UUID REFERENCES auth.users(id),
    declared_screenshot_url TEXT,
    score_confirm_deadline TIMESTAMPTZ,

    draw_score TEXT,
    draw_screenshot_url TEXT,
    draw_detected_at TIMESTAMPTZ,
    penalty_deadline TIMESTAMPTZ,
    penalty_score TEXT,
    penalty_screenshot_url TEXT,

    screenshot_url TEXT,
    screenshot_expires_at TIMESTAMPTZ,
    creator_screenshot_url TEXT,
    joiner_screenshot_url TEXT,
    creator_ocr_data JSONB,
    joiner_ocr_data JSONB,

    challenge_deadline TIMESTAMPTZ,
    challenge_uploaded BOOLEAN DEFAULT FALSE,
    challenge_screenshot_url TEXT,
    challenge_uploaded_at TIMESTAMPTZ,
    first_upload_winner_id UUID,
    first_upload_confidence INTEGER,
    first_upload_screenshot_url TEXT,

    winner_id UUID REFERENCES auth.users(id),
    loser_id UUID REFERENCES auth.users(id),

    creator_result TEXT,
    joiner_result TEXT,
    result_post_deadline TIMESTAMPTZ,

    settlement_method TEXT,
    settlement_confidence INTEGER,

    dispute_reason TEXT,
    disputed_at TIMESTAMPTZ,
    disputer_id UUID REFERENCES auth.users(id),
    disputer_screenshot_url TEXT,
    disputer_declared_creator INTEGER,
    disputer_declared_joiner INTEGER,

    forfeit_by UUID REFERENCES auth.users(id),

    confirmer_id UUID REFERENCES auth.users(id),
    confirmer_screenshot_url TEXT,
    confirmed_at TIMESTAMPTZ,

    reminder_sent BOOLEAN DEFAULT FALSE,
    screenshots_deleted_at TIMESTAMPTZ,

    verification_data JSONB,
    arbitration_data JSONB,

    resolved_by_admin BOOLEAN DEFAULT FALSE,
    admin_notes TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- MATCH NOTIFICATIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS match_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    match_id UUID REFERENCES friend_matches(id) ON DELETE CASCADE,
    recipient_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    type TEXT NOT NULL,
    payload JSONB,
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- SCREENSHOT SECURITY
-- ============================================================

CREATE TABLE IF NOT EXISTS screenshot_hashes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hash TEXT NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    match_id UUID REFERENCES friend_matches(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(hash)
);

CREATE TABLE IF NOT EXISTS user_screenshot_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    device TEXT,
    match_id UUID REFERENCES friend_matches(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS screenshot_review_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    match_id UUID REFERENCES friend_matches(id) ON DELETE CASCADE,
    uploader_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    screenshot_url TEXT NOT NULL,
    storage_key TEXT,
    ocr_confidence INTEGER DEFAULT 0,
    reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- ADMIN AUDIT LOG
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action TEXT NOT NULL,
    match_id UUID REFERENCES friend_matches(id) ON DELETE SET NULL,
    withdrawal_id UUID REFERENCES withdrawals(id) ON DELETE SET NULL,
    winner_id UUID,
    mpesa_code TEXT,
    admin_ip TEXT,
    admin_notes TEXT,
    prev_status TEXT,
    resolution TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_user_id ON withdrawals(user_id);
CREATE INDEX IF NOT EXISTS idx_tournaments_status ON tournaments(status);
CREATE INDEX IF NOT EXISTS idx_friend_matches_creator ON friend_matches(creator_id);
CREATE INDEX IF NOT EXISTS idx_friend_matches_joiner ON friend_matches(joiner_id);
CREATE INDEX IF NOT EXISTS idx_friend_matches_status ON friend_matches(status);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON match_notifications(recipient_id);

-- ============================================================
-- WALLET FUNCTIONS
-- ============================================================

CREATE OR REPLACE FUNCTION credit_wallet(p_user_id UUID, p_amount DECIMAL)
RETURNS VOID AS $$
BEGIN
    UPDATE wallets
    SET balance = balance + p_amount,
        updated_at = NOW()
    WHERE user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION deduct_wallet(p_user_id UUID, p_amount DECIMAL)
RETURNS VOID AS $$
BEGIN
    UPDATE wallets
    SET balance = balance - p_amount,
        updated_at = NOW()
    WHERE user_id = p_user_id
    AND balance >= p_amount;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Insufficient balance';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- AUTO CREATE WALLET
-- ============================================================

CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO wallets (user_id, balance)
    VALUES (NEW.id, 0);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION handle_new_user();