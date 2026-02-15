// ============================================================
// STEP 1: Boot diagnostics — VERY FIRST LINES, before anything
// ============================================================
console.log("========================================");
console.log("🚀 BOOT START:", new Date().toISOString());
console.log("   Node:", process.version);
console.log("   Platform:", process.platform);
console.log("   Memory at boot:", Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + "MB used");
console.log("========================================");

// Catch any unhandled crashes and log them BEFORE process exits
process.on('uncaughtException', (err) => {
    console.error("💥 UNCAUGHT EXCEPTION:", err.message);
    console.error(err.stack);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    console.error("💥 UNHANDLED REJECTION:", reason);
});

// ============================================================
// STEP 2: Load lightweight modules first
// ============================================================
console.log("📦 Loading express, cors, dotenv...");
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
console.log("✅ Core modules loaded.");

// ============================================================
// STEP 3: Validate ALL env vars before touching Supabase
// ============================================================
console.log("🔑 Checking environment variables...");
const REQUIRED_VARS = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'MPESA_SERVER_URL'
];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error("❌ FATAL: Missing required env vars:", missing.join(', '));
    console.error("   Present vars:", Object.keys(process.env).filter(k =>
        ['SUPABASE_URL','SUPABASE_ANON_KEY','SUPABASE_SERVICE_ROLE_KEY',
         'MPESA_SERVER_URL','ADMIN_KEY','FRONTEND_URL','PORT','STORAGE_DOMAIN'].includes(k)
    ).join(', ') || "NONE");
    process.exit(1);
}
console.log("✅ Required env vars present.");
console.log("   APP_SERVER_URL:", process.env.APP_SERVER_URL || "⚠️  NOT SET");
console.log("   FRONTEND_URL:", process.env.FRONTEND_URL || "⚠️  NOT SET (CORS may block frontend)");
console.log("   ADMIN_KEY:", process.env.ADMIN_KEY ? "✅ set" : "⚠️  NOT SET (admin routes disabled)");
console.log("   STORAGE_DOMAIN:", process.env.STORAGE_DOMAIN || "⚠️  NOT SET (using default: *.supabase.co)");
console.log("   PORT:", process.env.PORT || "3000 (default)");

// ============================================================
// STEP 4: Load Supabase (network client, usually safe)
// ============================================================
console.log("📦 Loading Supabase client...");
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
console.log("✅ Supabase clients created.");

// ============================================================
// STEP 5: LAZY-LOAD ScreenshotVerifier (heavy: tesseract + sharp)
// DO NOT require() at startup — it can OOM on free instances
// ============================================================
let _verifier = null;
function getVerifier() {
    if (!_verifier) {
        console.log("📦 Lazy-loading ScreenshotVerifier (first use)...");
        try {
            const ScreenshotVerifier = require('./screenshot-verifier');
            _verifier = new ScreenshotVerifier(supabaseAdmin);
            console.log("✅ ScreenshotVerifier loaded.");
        } catch (err) {
            console.error("❌ CRITICAL: Failed to load ScreenshotVerifier:", err.message);
            console.error("   Screenshot verification will be DISABLED - all submissions require manual review!");
            return null;
        }
    }
    return _verifier;
}

// ============================================================
// STEP 6: Build the Express app
// ============================================================
console.log("🏗️  Configuring Express app...");
const app = express();
const port = process.env.PORT || 3000;

// Rate limiters
const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many requests. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
const depositLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many deposit attempts. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Helpers
function normalizePhone(phone) {
    if (!phone) return null;
    phone = phone.toString().replace(/\D/g, '');
    if (phone.startsWith('0')) phone = '254' + phone.slice(1);
    else if (phone.startsWith('7') && phone.length === 9) phone = '254' + phone;
    else if (phone.startsWith('1') && phone.length === 9) phone = '254' + phone;
    if (phone.startsWith('254') && phone.length === 12) return '+' + phone;
    return null;
}

function isAdmin(req) {
    if (!process.env.ADMIN_KEY) return false;
    return req.headers['x-admin-key'] === process.env.ADMIN_KEY;
}

function generateMatchCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = 'VUM-';
    for (let i = 0; i < 4; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// Generic error response - prevents leaking internal errors
function sendGenericError(res, statusCode, message, internalError) {
    console.error('Error:', message, '|', internalError?.message || internalError);
    res.status(statusCode).json({ error: message });
}

// Validate screenshot URL to prevent SSRF
function isValidScreenshotUrl(url) {
    try {
        const parsed = new URL(url);
        const storageDomain = process.env.STORAGE_DOMAIN || 'supabase.co';

        // Must be HTTPS
        if (parsed.protocol !== 'https:') {
            console.warn('❌ Screenshot URL must use HTTPS:', url);
            return false;
        }

        // Must be from allowed storage domain
        if (!parsed.hostname.endsWith(storageDomain)) {
            console.warn('❌ Screenshot URL from unauthorized domain:', parsed.hostname);
            return false;
        }

        return true;
    } catch (err) {
        console.warn('❌ Invalid screenshot URL:', url);
        return false;
    }
}

// ============================================================
// STEP 7: Middleware
// ============================================================
app.set('trust proxy', 1);

const allowedOrigins = [
    process.env.FRONTEND_URL,
    process.env.APP_SERVER_URL,
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000'
].filter(Boolean);

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.warn("⚠️  CORS blocked origin:", origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));

app.use(express.json());
app.use((req, res, next) => {
    const koyebUrl = process.env.APP_SERVER_URL || '';
    const frontendUrl = process.env.FRONTEND_URL || '';
    const connectSrc = [
        "'self'",
        koyebUrl,
        frontendUrl
    ].filter(Boolean).join(' ');
    res.setHeader("Content-Security-Policy",
        `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src ${connectSrc}`
    );
    next();
});
app.use(express.static('public'));

console.log("✅ Middleware configured.");

// ============================================================
// PAGE ROUTES
// ============================================================
app.get('/health', (req, res) => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'vumbua-backend',
        memory_mb: memMB,
        uptime_seconds: Math.round(process.uptime())
    });
});

// Diagnostic endpoint - check all configurations
app.get('/debug/config', (req, res) => {
    res.json({
        environment: {
            NODE_ENV: process.env.NODE_ENV || 'not set',
            PORT: process.env.PORT || 'not set',
            APP_SERVER_URL: process.env.APP_SERVER_URL ? '✅ set' : '❌ NOT SET',
            FRONTEND_URL: process.env.FRONTEND_URL ? '✅ set' : '❌ NOT SET',
            SUPABASE_URL: process.env.SUPABASE_URL ? '✅ set' : '❌ NOT SET',
            SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY ? '✅ set (length: ' + process.env.SUPABASE_ANON_KEY.length + ')' : '❌ NOT SET',
            SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ set (length: ' + process.env.SUPABASE_SERVICE_ROLE_KEY.length + ')' : '❌ NOT SET',
            MPESA_SERVER_URL: process.env.MPESA_SERVER_URL ? '✅ set' : '❌ NOT SET',
            ADMIN_KEY: process.env.ADMIN_KEY ? '✅ set' : '❌ NOT SET',
            STORAGE_DOMAIN: process.env.STORAGE_DOMAIN ? '✅ set' : '⚠️  using default: *.supabase.co'
        },
        supabase: {
            client_initialized: !!supabase,
            admin_initialized: !!supabaseAdmin,
            url: process.env.SUPABASE_URL || 'NOT SET'
        },
        server: {
            uptime_seconds: Math.round(process.uptime()),
            memory_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
            node_version: process.version,
            platform: process.platform
        }
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/auth/signup', async (req, res) => {
    try {
        // Mask phone number in logs to avoid leaking PII
        console.log('📝 Signup request received:', { phone: req.body.phone?.slice(0, 8) + '***', username: req.body.username });

        let { phone, password, username } = req.body;
        if (!phone || !password || !username) {
            console.log('❌ Missing fields');
            return res.status(400).json({ error: 'Missing fields.' });
        }
        if (password.length < 6) {
            console.log('❌ Password too short');
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        phone = normalizePhone(phone);
        if (!phone) {
            console.log('❌ Invalid phone format');
            return res.status(400).json({ error: 'Invalid phone number.' });
        }
        console.log('✅ Phone normalized');

        console.log('🔐 Attempting Supabase auth signup...');
        const { data, error } = await supabase.auth.signUp({
            phone, password, options: { data: { username } }
        });

        if (error) {
            console.error('❌ Supabase auth error:', error.message);
            // Don't leak internal error details
            return sendGenericError(res, 400, 'Signup failed. Please try again.', error);
        }
        console.log('✅ User created:', data.user?.id);

        if (data.user) {
            try {
                console.log('💾 Creating profile...');
                const { error: profileError } = await supabaseAdmin
                    .from('profiles')
                    .upsert([{ id: data.user.id, username }]);

                if (profileError) throw profileError;
                console.log('✅ Profile created');

                console.log('💰 Creating wallet...');
                const { error: walletError } = await supabaseAdmin
                    .from('wallets')
                    .upsert([{ user_id: data.user.id, balance: 0 }]);

                if (walletError) throw walletError;
                console.log('✅ Wallet created');
            } catch (dbErr) {
                console.error('❌ Failed to create profile/wallet:', dbErr.message, dbErr.code);
                // Rollback user creation
                await supabaseAdmin.auth.admin.deleteUser(data.user.id).catch((delErr) => {
                    console.error('❌ Failed to rollback user:', delErr);
                });
                return sendGenericError(res, 500, 'Account creation failed. Please try again.', dbErr);
            }
        }

        console.log('🎉 Signup successful!');
        res.status(200).json({ message: "Signup successful!", user: data.user });
    } catch (err) {
        console.error('💥 Signup error:', err);
        return sendGenericError(res, 500, 'Internal server error', err);
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        let { phone, password } = req.body;
        phone = normalizePhone(phone);
        if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

        const { data, error } = await supabase.auth.signInWithPassword({ phone, password });
        if (error) return sendGenericError(res, 400, 'Invalid phone number or password', error);

        res.status(200).json({ message: "Login successful!", session: data.session });
    } catch (err) {
        console.error('Login error:', err);
        return sendGenericError(res, 500, 'Internal server error', err);
    }
});

// ============================================================
// WALLET ROUTES
// ============================================================
app.get('/wallet/balance', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error } = await supabase.auth.getUser(jwt);
        if (error || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data } = await supabase.from('wallets').select('balance').eq('user_id', user.id).single();
        res.json({ balance: data ? data.balance : 0 });
    } catch (err) {
        console.error('Balance error:', err);
        return sendGenericError(res, 500, 'Failed to fetch balance', err);
    }
});

// ============================================================
// TOURNAMENT JOIN
// ============================================================
app.post('/tournament/join', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { tournamentId, entryFee, paymentMethod, checkoutId } = req.body;

        let roomCode = null;

        if (paymentMethod === 'wallet') {
            const { data: rpcRoomCode, error: rpcErr } = await supabase.rpc('join_tournament_wallet', {
                p_user_id: user.id,
                p_tournament_id: tournamentId,
                p_entry_fee: entryFee
            });
            if (rpcErr) {
                if (rpcErr.message.includes('double-join') || rpcErr.code === '23505') {
                    return res.status(400).json({ error: "Umeshajiunga tournament hii!" });
                }
                return res.status(400).json({ error: rpcErr.message });
            }
            roomCode = rpcRoomCode;

        } else if (paymentMethod === 'mpesa') {
            const { data: rpcRoomCode, error: rpcErr } = await supabase.rpc('join_tournament_mpesa', {
                p_user_id: user.id,
                p_tournament_id: tournamentId,
                p_checkout_id: checkoutId
            });
            if (rpcErr) {
                if (rpcErr.message.includes('double-join') || rpcErr.code === '23505') {
                    return res.status(400).json({ error: "Umeshajiunga tournament hii!" });
                }
                return res.status(400).json({ error: rpcErr.message });
            }
            roomCode = rpcRoomCode;
        }

        res.status(200).json({ message: 'Umejiunga!', roomCode });
    } catch (err) {
        console.error('Join error:', err);
        res.status(500).json({ error: 'Imeshindwa kujiunga. Jaribu tena.' });
    }
});

// ============================================================
// PLAY WITH FRIENDS ROUTES
// ============================================================
app.post('/friends/create-match', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { wagerAmount } = req.body;
        if (!wagerAmount || isNaN(wagerAmount) || wagerAmount < 50) {
            return res.status(400).json({ error: 'Minimum wager is KES 50' });
        }

        const { data: wallet } = await supabase
            .from('wallets').select('balance').eq('user_id', user.id).single();

        if (!wallet || wallet.balance < wagerAmount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        let matchCode, attempts = 0, unique = false;
        while (!unique && attempts < 10) {
            matchCode = generateMatchCode();
            attempts++;
            const { data: existing } = await supabaseAdmin
                .from('friend_matches').select('id')
                .eq('match_code', matchCode).eq('status', 'pending')
                .gte('expires_at', new Date().toISOString()).maybeSingle();
            if (!existing) unique = true;
        }
        if (!unique) return res.status(500).json({ error: 'Failed to generate unique code' });

        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const platformFee = Math.floor(wagerAmount * 0.10);
        const winnerPrize = (wagerAmount * 2) - platformFee;

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .insert([{
                match_code: matchCode,
                creator_id: user.id,
                wager_amount: wagerAmount,
                platform_fee: platformFee,
                winner_prize: winnerPrize,
                expires_at: expiresAt,
                status: 'pending'
            }]).select().single();

        if (matchErr) {
            console.error('Match creation error:', matchErr);
            return res.status(500).json({ error: 'Failed to create match' });
        }

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id, p_amount: wagerAmount
        });

        if (deductErr) {
            await supabaseAdmin.from('friend_matches').delete().eq('id', match.id);
            return res.status(400).json({ error: 'Failed to deduct wager from wallet' });
        }

        res.status(201).json({
            matchId: match.id, matchCode, wagerAmount, winnerPrize, platformFee, expiresAt,
            message: 'Match created! Share this code with your friend.'
        });
    } catch (err) {
        console.error('Create match error:', err);
        res.status(500).json({ error: 'Failed to create match' });
    }
});

app.post('/friends/join-match', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchCode } = req.body;
        if (!matchCode) return res.status(400).json({ error: 'Match code is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*')
            .eq('match_code', matchCode.toUpperCase()).single();

        if (matchErr || !match) return res.status(404).json({ error: 'Invalid match code' });
        if (match.status !== 'pending') return res.status(400).json({ error: 'Match already started or completed' });

        if (new Date(match.expires_at) < new Date()) {
            await supabaseAdmin.from('friend_matches').update({ status: 'expired' }).eq('id', match.id);
            return res.status(400).json({ error: 'Match code has expired' });
        }

        if (match.creator_id === user.id) return res.status(400).json({ error: 'You cannot join your own match' });
        if (match.joiner_id) return res.status(400).json({ error: 'Match already has two players' });

        const { data: wallet } = await supabase
            .from('wallets').select('balance').eq('user_id', user.id).single();

        if (!wallet || wallet.balance < match.wager_amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id, p_amount: match.wager_amount
        });

        if (deductErr) return res.status(400).json({ error: 'Failed to deduct wager from wallet' });

        const { data: updatedMatch, error: updateErr } = await supabaseAdmin
            .from('friend_matches')
            .update({ joiner_id: user.id, status: 'active', started_at: new Date().toISOString() })
            .eq('id', match.id).select().single();

        if (updateErr) {
            await supabaseAdmin.rpc('credit_wallet', { p_user_id: user.id, p_amount: match.wager_amount });
            return res.status(500).json({ error: 'Failed to join match' });
        }

        res.status(200).json({
            message: 'Successfully joined match!',
            matchId: updatedMatch.id,
            wagerAmount: match.wager_amount,
            winnerPrize: match.winner_prize,
            opponentId: match.creator_id
        });
    } catch (err) {
        console.error('Join match error:', err);
        res.status(500).json({ error: 'Failed to join match' });
    }
});

app.post('/friends/submit-result', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, winnerId, screenshotUrl } = req.body;
        if (!matchId || !winnerId) return res.status(400).json({ error: 'Match ID and winner ID are required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (winnerId !== match.creator_id && winnerId !== match.joiner_id)
            return res.status(400).json({ error: 'Invalid winner ID' });

        // Prevent same user from reporting twice
        if (match.reported_by_id === user.id) {
            return res.status(400).json({ error: 'You have already reported this match' });
        }

        // Lazy-load verifier only when actually needed
        let verificationResult = null;
        if (screenshotUrl) {
            // Validate screenshot URL to prevent SSRF using isValidScreenshotUrl()
            if (!isValidScreenshotUrl(screenshotUrl)) {
                return res.status(400).json({ error: 'Invalid screenshot URL' });
            }

            const verifier = getVerifier();
            if (verifier) {
                try {
                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 10000); // 10 second timeout
                    const response = await fetch(screenshotUrl, { signal: controller.signal });
                    clearTimeout(timeout);
                    if (!response.ok) throw new Error('Failed to fetch screenshot');
                    const buffer = Buffer.from(await response.arrayBuffer());
                    verificationResult = await verifier.verifyScreenshot(buffer, {
                        userId: user.id, matchId, startedAt: match.started_at
                    });

                    if (!verificationResult.isValid || verificationResult.fraudScore >= 50) {
                        await supabaseAdmin.from('friend_matches').update({
                            status: 'disputed',
                            disputed_at: new Date().toISOString(),
                            dispute_reason: 'Suspicious screenshot',
                            verification_data: verificationResult
                        }).eq('id', matchId);
                        return res.status(409).json({
                            error: 'Screenshot verification failed. Match marked for admin review.',
                            verification: verificationResult
                        });
                    }
                } catch (fetchErr) {
                    console.error('Screenshot verify error:', fetchErr.message);
                }
            }
        }

        if (!match.reported_winner_id) {
            await supabaseAdmin.from('friend_matches').update({
                reported_winner_id: winnerId,
                reported_by_id: user.id,
                screenshot_url: screenshotUrl,
                verification_data: verificationResult,
                reported_at: new Date().toISOString()
            }).eq('id', matchId);

            return res.status(200).json({
                message: 'Result submitted. Waiting for opponent confirmation.',
                requiresConfirmation: true,
                verification: verificationResult
            });
        }

        if (match.reported_winner_id !== winnerId) {
            await supabaseAdmin.from('friend_matches').update({
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: 'Reported winners do not match'
            }).eq('id', matchId);
            return res.status(409).json({
                error: 'Results do not match. Match marked for admin review.',
                requiresAdminReview: true
            });
        }

        // Both reports match – payout winner
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: winnerId, p_amount: match.winner_prize
        });
        if (payoutErr) {
            console.error('Payout error:', payoutErr);
            return res.status(500).json({ error: 'Failed to process payout' });
        }

        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId,
            status: 'completed',
            completed_at: new Date().toISOString()
        }).eq('id', matchId);

        if (verificationResult?.checks?.duplicate?.details?.hash) {
            await supabaseAdmin.from('screenshot_hashes')
                .insert([{ hash: verificationResult.checks.duplicate.details.hash, user_id: winnerId, match_id: matchId }])
                .onConflict('hash').ignore();
        }
        if (verificationResult?.checks?.device?.details?.device) {
            await supabaseAdmin.from('user_screenshot_history')
                .insert([{ user_id: winnerId, device: verificationResult.checks.device.details.device, match_id: matchId }]);
        }

        res.status(200).json({
            message: 'Match completed! Winner has been paid.',
            winnerId, prizePaid: match.winner_prize, verification: verificationResult
        });
    } catch (err) {
        console.error('Submit result error:', err);
        res.status(500).json({ error: 'Failed to submit result' });
    }
});

// ============================================================
// MY MATCHES ENDPOINT (FIXED)
// ============================================================
app.get('/friends/my-matches', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

        const { data: matches, error } = await supabaseAdmin
            .from('matches')
            .select(`
                *,
                creator:profiles!matches_creator_id_fkey(username),
                opponent:profiles!matches_opponent_id_fkey(username)
            `)
            .or(`creator_id.eq.${user.id},opponent_id.eq.${user.id}`)
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) {
            console.error('Fetch matches error:', error);
            return res.json([]); // Return empty array instead of error
        }

        res.json(matches || []);
    } catch (err) {
        console.error('Fetch matches error:', err);
        res.json([]); // Return empty array on exception
    }
});

app.post('/friends/cancel-match', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        
        if (!matchId) {
            return res.status(400).json({ error: 'Match ID is required' });
        }

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();

        if (matchErr || !match) {
            console.error('Match not found:', matchId, matchErr);
            return res.status(404).json({ error: 'Match not found' });
        }
        
        if (match.creator_id !== user.id) {
            return res.status(403).json({ error: 'Only match creator can cancel' });
        }
        
        // Better status checking with specific error messages
        if (match.status === 'cancelled') {
            return res.status(400).json({ error: 'Match already cancelled' });
        }
        if (match.status === 'active') {
            return res.status(400).json({ error: 'Cannot cancel - someone already joined this match' });
        }
        if (match.status === 'completed') {
            return res.status(400).json({ error: 'Cannot cancel completed match' });
        }
        if (match.status === 'disputed') {
            return res.status(400).json({ error: 'Cannot cancel disputed match - awaiting admin review' });
        }
        
        // Allow cancelling both pending and expired matches
        if (match.status !== 'pending' && match.status !== 'expired') {
            return res.status(400).json({ error: `Cannot cancel ${match.status} match` });
        }

        // Refund the wager
        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', { 
            p_user_id: user.id, 
            p_amount: match.wager_amount 
        });
        
        if (refundErr) {
            console.error('Refund error:', refundErr);
            return res.status(500).json({ error: 'Failed to refund wager' });
        }
        
        // Update match status
        await supabaseAdmin.from('friend_matches').update({
            status: 'cancelled', 
            cancelled_at: new Date().toISOString()
        }).eq('id', matchId);

        res.status(200).json({ 
            message: 'Match cancelled and wager refunded', 
            refundedAmount: match.wager_amount 
        });
    } catch (err) {
        console.error('Cancel match error:', err);
        res.status(500).json({ error: 'Failed to cancel match' });
    }
});

// ============================================================
// WALLET DEPOSIT / WITHDRAW
// ============================================================
async function handleDeposit(req, res) {
    try {
        let { phone, amount, description } = req.body;
        if (!phone || !amount || isNaN(amount) || amount < 10)
            return res.status(400).json({ error: 'Invalid request. Min deposit KES 10.' });

        phone = normalizePhone(phone);
        if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

        const jwt = req.headers['authorization']?.replace('Bearer ', '');
        const { data: { user } } = await supabase.auth.getUser(jwt);
        if (!user) return res.status(401).json({ error: 'Unauthorized.' });

        const mpesaRes = await fetch(`${process.env.MPESA_SERVER_URL}/pay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: phone.replace('+', ''),
                amount: String(Math.floor(Number(amount))),
                description: description || 'Vumbua Deposit'
            })
        });

        if (!mpesaRes.ok) {
            const errData = await mpesaRes.json().catch(() => ({}));
            throw new Error(errData.error || 'STK request failed');
        }
        const mpesaData = await mpesaRes.json();
        const checkoutRequestId = mpesaData.CheckoutRequestID || mpesaData.checkoutId || mpesaData.data?.CheckoutRequestID;
        const merchantRequestId = mpesaData.MerchantRequestID || mpesaData.data?.MerchantRequestID || 'N/A';

        if (!checkoutRequestId) throw new Error('STK push did not return a CheckoutRequestID');

        await supabaseAdmin.from('transactions').insert([{
            checkout_request_id: checkoutRequestId,
            merchant_request_id: merchantRequestId,
            amount: Number(amount),
            phone, user_id: user.id, status: 'pending'
        }]);

        res.status(200).json({ message: 'STK push sent!', checkoutId: checkoutRequestId, checkoutRequestId });
    } catch (err) {
        console.error('Deposit error:', err.message);
        res.status(500).json({ error: err.message || 'Failed to initiate deposit.' });
    }
}

app.post('/wallet/deposit', depositLimiter, handleDeposit);
app.post('/mpesa/deposit', depositLimiter, handleDeposit);

app.get('/wallet/deposit/status', async (req, res) => {
    try {
        const { checkoutId } = req.query;
        if (!checkoutId) return res.status(400).json({ error: 'checkoutId is required' });
        const { data } = await supabaseAdmin
            .from('transactions').select('status, mpesa_receipt')
            .eq('checkout_request_id', checkoutId).single();
        res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt || null });
    } catch (err) {
        console.error('Deposit status error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/mpesa/callback', async (req, res) => {
    try {
        const { Body } = req.body;
        const { stkCallback } = Body || {};
        const { CheckoutRequestID, ResultCode, CallbackMetadata } = stkCallback || {};

        if (ResultCode === 0 && CallbackMetadata) {
            const items = CallbackMetadata.Item || [];
            const amount = items.find(i => i.Name === 'Amount')?.Value || 0;
            const receipt = items.find(i => i.Name === 'MpesaReceiptNumber')?.Value || 'N/A';

            const { data: txn } = await supabaseAdmin
                .from('transactions').select('user_id')
                .eq('checkout_request_id', CheckoutRequestID).single();

            if (txn?.user_id) {
                await supabaseAdmin.rpc('credit_wallet', { p_user_id: txn.user_id, p_amount: amount });
                await supabaseAdmin.from('transactions').update({
                    status: 'completed', mpesa_receipt: receipt, completed_at: new Date().toISOString()
                }).eq('checkout_request_id', CheckoutRequestID);
            } else {
                console.error('No user_id found for transaction:', CheckoutRequestID);
            }
        } else {
            await supabaseAdmin.from('transactions').update({
                status: 'failed', completed_at: new Date().toISOString()
            }).eq('checkout_request_id', CheckoutRequestID);
        }

        res.status(200).json({ ResultCode: 0, ResultDesc: 'Success' });
    } catch (err) {
        console.error('Callback error:', err);
        res.status(500).json({ error: 'Callback failed' });
    }
});

app.get('/mpesa/status', async (req, res) => {
    try {
        const { checkoutId } = req.query;
        const { data } = await supabase.from('transactions').select('status, mpesa_receipt')
            .eq('checkout_request_id', checkoutId).single();
        res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt });
    } catch (err) {
        console.error('Mpesa status error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/wallet/withdraw', sensitiveLimiter, async (req, res) => {
    try {
        const jwt = req.headers['authorization']?.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

        let { amount, phone, name } = req.body;
        if (!amount || !phone || !name || isNaN(amount) || amount < 100)
            return res.status(400).json({ error: 'Invalid details.' });
        phone = normalizePhone(phone);

        const referenceId = 'WD-' + Date.now().toString(36).toUpperCase();
        const { error: rpcErr } = await supabase.rpc('request_withdrawal', {
            p_user_id: user.id, p_amount: Math.floor(Number(amount)),
            p_phone: phone, p_name: name, p_ref_id: referenceId
        });
        if (rpcErr) return res.status(400).json({ error: rpcErr.message });
        res.status(200).json({ message: 'Request received.', referenceId, amount });
    } catch (err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ error: 'System error. Try again.' });
    }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.get('/admin/withdrawals', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { status } = req.query;
        let query = supabaseAdmin.from('withdrawals').select('*').order('created_at', { ascending: true });
        if (status) query = query.eq('status', status);
        const { data, error } = await query;
        if (error) return res.status(500).json({ error: error.message });
        res.json(data || []);
    } catch (err) {
        console.error('Admin withdrawals error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.patch('/admin/withdrawals/:id/paid', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const withdrawal = await supabaseAdmin.from('withdrawals').select('status').eq('id', req.params.id).single();
        if (withdrawal.error || withdrawal.data.status !== 'pending') {
            return res.status(400).json({ error: 'Invalid withdrawal state' });
        }
        const { data, error } = await supabaseAdmin.from('withdrawals')
            .update({ status: 'paid', mpesa_code: req.body.mpesaCode, paid_at: new Date().toISOString() })
            .eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.json({ message: 'Paid.', withdrawal: data });
    } catch (err) {
        console.error('Admin paid error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.patch('/admin/withdrawals/:id/reject', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data: wd, error: fetchErr } = await supabaseAdmin.from('withdrawals').select('*').eq('id', req.params.id).single();
        if (fetchErr || !wd || wd.status !== 'pending') return res.status(400).json({ error: 'Invalid state' });
        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: wd.user_id, p_amount: wd.amount });
        if (refundErr) return res.status(500).json({ error: refundErr.message });
        const { data, error } = await supabaseAdmin.from('withdrawals')
            .update({ status: 'rejected', reject_reason: req.body.reason, rejected_at: new Date().toISOString() })
            .eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.json({ message: 'Rejected and refunded.', withdrawal: data });
    } catch (err) {
        console.error('Admin reject error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/tournaments', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data, error } = await supabaseAdmin.from('tournaments').select('*').order('created_at', { ascending: false });
        if (error) return res.status(500).json({ error: error.message });
        res.json(data || []);
    } catch (err) {
        console.error('Admin tournaments error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/tournaments/:id', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data, error } = await supabaseAdmin.from('tournaments').select('*').eq('id', req.params.id).single();
        if (error) return res.status(404).json({ error: 'Tournament not found' });
        res.json(data);
    } catch (err) {
        console.error('Admin tournament detail error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/admin/tournaments', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        if (!name || !entry_fee || !start_time || !max_players)
            return res.status(400).json({ error: 'Missing required fields' });
        const { data, error } = await supabaseAdmin.from('tournaments')
            .insert([{ name, entry_fee, start_time, max_players, room_code: room_code || null, status: status || 'open' }])
            .select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.status(201).json(data);
    } catch (err) {
        console.error('Admin create tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.patch('/admin/tournaments/:id', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        const { data, error } = await supabaseAdmin.from('tournaments')
            .update({ name, entry_fee, start_time, max_players, room_code, status, updated_at: new Date().toISOString() })
            .eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.json(data);
    } catch (err) {
        console.error('Admin update tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/admin/tournaments/:id', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { error } = await supabaseAdmin.from('tournaments').delete().eq('id', req.params.id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ message: 'Tournament deleted' });
    } catch (err) {
        console.error('Admin delete tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/admin/friend-matches', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { status } = req.query;
        let query = supabaseAdmin.from('friend_matches')
            .select(`*, creator:profiles!friend_matches_creator_id_fkey(username), joiner:profiles!friend_matches_joiner_id_fkey(username), winner:profiles!friend_matches_winner_id_fkey(username)`)
            .order('created_at', { ascending: false });
        if (status && status !== 'all') query = query.eq('status', status);
        const { data, error } = await query;
        if (error) return res.status(500).json({ error: error.message });
        res.json(data || []);
    } catch (err) {
        console.error('Admin friend matches error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/admin/resolve-dispute/:matchId', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { winnerId } = req.body;
        const { matchId } = req.params;
        if (!winnerId) return res.status(400).json({ error: 'Winner ID is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'disputed') return res.status(400).json({ error: 'Match is not disputed' });
        if (winnerId !== match.creator_id && winnerId !== match.joiner_id) {
            return res.status(400).json({ error: 'Winner must be one of the players' });
        }

        await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId, status: 'completed',
            completed_at: new Date().toISOString(), resolved_by_admin: true
        }).eq('id', matchId);
        res.json({ message: 'Dispute resolved and winner paid' });
    } catch (err) {
        console.error('Resolve dispute error:', err);
        res.status(500).json({ error: 'Failed to resolve dispute' });
    }
});

// ============================================================
// PUBLIC TOURNAMENT ROUTES
// ============================================================
app.get('/tournaments', async (req, res) => {
    try {
        const { data: tournaments, error } = await supabaseAdmin
            .from('tournaments')
            .select(`*, bookings:bookings(count)`)
            .in('status', ['open', 'live'])
            .order('start_time', { ascending: true });

        if (error) throw error;

        const result = tournaments.map(t => ({
            ...t,
            current_players: t.bookings?.[0]?.count || 0,
            prize_pool: t.entry_fee * t.max_players
        }));

        res.json(result);
    } catch (err) {
        console.error('Error fetching tournaments:', err);
        res.status(500).json({ error: 'Failed to fetch tournaments' });
    }
});

// ============================================================
// SERVER START
// ============================================================
app.listen(port, '0.0.0.0', () => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log("========================================");
    console.log(`✅ Vumbua Game running on port ${port}`);
    console.log(`   Memory after start: ${memMB}MB`);
    console.log(`   Uptime: ${Math.round(process.uptime())}s`);
    console.log(`   Health check: http://localhost:${port}/health`);
    console.log("========================================");
});