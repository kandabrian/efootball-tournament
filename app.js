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
const { createClient } = require('@supabase/supabase-js');
console.log("✅ Core modules loaded.");

// Multer — lazy-loaded only when screenshot route is first hit
let _multer = null;
function getMulter() {
    if (!_multer) {
        _multer = require('multer');
    }
    return _multer;
}

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
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
console.log("✅ Supabase clients created.");

// ============================================================
// STEP 5: LAZY-LOAD ScreenshotVerifier (heavy: tesseract + sharp)
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

// Middleware to attach Supabase clients to request
app.use((req, res, next) => {
    req.supabase = supabase;
    req.supabaseAdmin = supabaseAdmin;
    next();
});

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
                // Check if wallet already exists first
                const { data: existingWallet } = await supabaseAdmin
                    .from('wallets')
                    .select('user_id')
                    .eq('user_id', data.user.id)
                    .maybeSingle();

                let walletError = null;
                if (!existingWallet) {
                    const { error } = await supabaseAdmin
                        .from('wallets')
                        .insert([{ user_id: data.user.id, balance: 0 }]);
                    walletError = error;
                }

                if (walletError) throw walletError;
                console.log('✅ Wallet created');
            } catch (dbErr) {
                console.error('❌ Failed to create profile/wallet:', dbErr.message, dbErr.code);
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

        const { data, error: dbErr } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .maybeSingle();

        if (dbErr) throw dbErr;
        res.json({ balance: data ? data.balance : 0 });
    } catch (err) {
        console.error('Balance error:', err);
        return sendGenericError(res, 500, 'Failed to fetch balance', err);
    }
});

// ============================================================
// WITHDRAWAL ROUTES (Enhanced)
// ============================================================
const { router: withdrawalRouter, processMpesaWithdrawal } = require('./routes/withdrawals');
app.use('/wallet/withdrawals', withdrawalRouter); // For history and cancellation
app.post('/wallet/withdraw', sensitiveLimiter, async (req, res) => {
    // This endpoint now calls the enhanced withdrawal logic via the withdrawals module
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { amount, phone } = req.body;
        if (!amount || !phone) {
            return res.status(400).json({ error: 'Amount and phone are required' });
        }

        const { WITHDRAWAL_CONFIG } = require('./routes/withdrawals');
        const withdrawAmount = parseFloat(amount);
        if (isNaN(withdrawAmount) || withdrawAmount < WITHDRAWAL_CONFIG.MIN_AMOUNT) {
            return res.status(400).json({ error: 'Minimum withdrawal is KES ' + WITHDRAWAL_CONFIG.MIN_AMOUNT });
        }
        if (withdrawAmount > WITHDRAWAL_CONFIG.MAX_AMOUNT) {
            return res.status(400).json({ error: 'Maximum withdrawal is KES ' + WITHDRAWAL_CONFIG.MAX_AMOUNT });
        }

        let cleanPhone = phone.replace(/\D/g, '');
        if (cleanPhone.startsWith('0')) cleanPhone = '254' + cleanPhone.substring(1);
        else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) cleanPhone = '254' + cleanPhone;
        if (!/^254[17]\d{8}$/.test(cleanPhone)) {
            return res.status(400).json({ error: 'Invalid phone number format' });
        }
        cleanPhone = '+' + cleanPhone;

        // ── Atomic deduction via RPC — prevents race condition ──────────────
        // deduct_wallet checks balance and deducts in a single DB transaction,
        // so two simultaneous requests cannot both pass the balance check.
        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: withdrawAmount
        });
        if (deductErr) {
            // RPC raises an exception if balance is insufficient
            const msg = deductErr.message?.toLowerCase().includes('insufficient')
                ? 'Insufficient balance'
                : 'Failed to process withdrawal';
            return res.status(400).json({ error: msg });
        }

        // Balance deducted — now record the withdrawal request
        const { data: profileData } = await supabaseAdmin
            .from('profiles').select('username').eq('id', user.id).single();

        const { data: withdrawal, error: insertError } = await supabaseAdmin
            .from('withdrawals').insert([{
                user_id: user.id,
                amount: withdrawAmount,
                phone: cleanPhone,
                name: profileData?.username || 'User',
                reference_id: 'WD-' + Date.now(),
                status: 'pending'
            }]).select().single();

        if (insertError) {
            // Refund if insert fails
            await supabaseAdmin.rpc('credit_wallet', { p_user_id: user.id, p_amount: withdrawAmount });
            throw insertError;
        }

        await supabaseAdmin.from('transactions').insert([{
            user_id: user.id, type: 'withdrawal', amount: -withdrawAmount,
            description: 'Withdrawal request: KES ' + withdrawAmount.toFixed(2),
            status: 'completed', reference: 'WD-' + withdrawal.id.substring(0, 8)
        }]);

        console.log('💸 Withdrawal requested: user=' + user.id + ', amount=' + withdrawAmount);

        return res.status(201).json({
            message: 'Withdrawal request submitted for review',
            withdrawal: {
                id: withdrawal.id,
                amount: withdrawAmount,
                status: withdrawal.status,
                phone: cleanPhone,
                estimatedTime: '1-2 hours'
            }
        });
    } catch (err) {
        console.error('Withdrawal error:', err);
        res.status(500).json({ error: 'Failed to process withdrawal' });
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
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .maybeSingle();

        if (!wallet || wallet.balance < wagerAmount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        let matchCode, attempts = 0, unique = false;
        while (!unique && attempts < 10) {
            matchCode = generateMatchCode();
            attempts++;
            const { data: existing } = await supabaseAdmin
                .from('friend_matches')
                .select('id')
                .eq('match_code', matchCode)
                .eq('status', 'pending')
                .gte('expires_at', new Date().toISOString())
                .maybeSingle();
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
            }])
            .select()
            .single();

        if (matchErr) {
            console.error('Match creation error:', matchErr);
            return res.status(500).json({ error: 'Failed to create match' });
        }

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: wagerAmount
        });

        if (deductErr) {
            await supabaseAdmin.from('friend_matches').delete().eq('id', match.id);
            return res.status(400).json({ error: 'Failed to deduct wager from wallet' });
        }

        res.status(201).json({
            matchId: match.id,
            matchCode,
            wagerAmount,
            winnerPrize,
            platformFee,
            expiresAt,
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
            .from('friend_matches')
            .select('*')
            .eq('match_code', matchCode.toUpperCase())
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Invalid match code' });
        if (match.status !== 'pending') return res.status(400).json({ error: 'Match already started or completed' });

        if (new Date(match.expires_at) < new Date()) {
            await supabaseAdmin.from('friend_matches').update({ status: 'expired' }).eq('id', match.id);
            return res.status(400).json({ error: 'Match code has expired' });
        }

        if (match.creator_id === user.id) return res.status(400).json({ error: 'You cannot join your own match' });
        if (match.joiner_id) return res.status(400).json({ error: 'Match already has two players' });

        const { data: wallet } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .maybeSingle();

        if (!wallet || wallet.balance < match.wager_amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: match.wager_amount
        });

        if (deductErr) return res.status(400).json({ error: 'Failed to deduct wager from wallet' });

        const { data: updatedMatch, error: updateErr } = await supabaseAdmin
            .from('friend_matches')
            .update({ joiner_id: user.id, status: 'active', started_at: new Date().toISOString() })
            .eq('id', match.id)
            .select()
            .single();

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
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (winnerId !== match.creator_id && winnerId !== match.joiner_id)
            return res.status(400).json({ error: 'Invalid winner ID' });

        if (match.reported_by_id === user.id) {
            return res.status(400).json({ error: 'You have already reported this match' });
        }

        let verificationResult = null;
        if (screenshotUrl) {
            if (!isValidScreenshotUrl(screenshotUrl)) {
                return res.status(400).json({ error: 'Invalid screenshot URL' });
            }

            const verifier = getVerifier();
            if (verifier) {
                try {
                    // Fetch opponent username for match-context check
                    const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
                    let opponentUsername = null;
                    if (opponentId) {
                        const { data: oppProfile } = await supabaseAdmin.from('profiles').select('username').eq('id', opponentId).maybeSingle();
                        opponentUsername = oppProfile?.username || null;
                    }

                    const controller = new AbortController();
                    const timeout = setTimeout(() => controller.abort(), 10000);
                    const response = await fetch(screenshotUrl, { signal: controller.signal });
                    clearTimeout(timeout);
                    if (!response.ok) throw new Error('Failed to fetch screenshot');
                    const buffer = Buffer.from(await response.arrayBuffer());
                    let selfUsername = null;
                    {
                        const { data: sp } = await supabaseAdmin.from('profiles').select('username').eq('id', user.id).maybeSingle();
                        selfUsername = sp?.username || null;
                    }
                    verificationResult = await verifier.verifyScreenshot(buffer, {
                        userId: user.id,
                        matchId,
                        startedAt: match.started_at,
                        opponentUsername,
                        uploaderUsername: selfUsername,
                        matchCode: match.match_code
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

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: winnerId,
            p_amount: match.winner_prize
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
            try {
                await supabaseAdmin.from('screenshot_hashes')
                    .insert([{ hash: verificationResult.checks.duplicate.details.hash, user_id: winnerId, match_id: matchId }]);
            } catch (err) {
                // Ignore duplicate hash errors (hash is unique constraint)
                if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) {
                    console.error('Error storing hash:', err);
                }
            }
        }
        if (verificationResult?.checks?.device?.details?.device) {
            await supabaseAdmin.from('user_screenshot_history')
                .insert([{ user_id: winnerId, device: verificationResult.checks.device.details.device, match_id: matchId }]);
        }

        res.status(200).json({
            message: 'Match completed! Winner has been paid.',
            winnerId,
            prizePaid: match.winner_prize,
            verification: verificationResult
        });
    } catch (err) {
        console.error('Submit result error:', err);
        res.status(500).json({ error: 'Failed to submit result' });
    }
});

// ============================================================
// OCR AUTO-SETTLE: Requires BOTH players to upload screenshots
// with matching scores before paying out.
// Flow:
//   Player A uploads → score stored as "first_ocr" on match
//   Player B uploads → scores compared → if they match, pay winner
// This prevents any single player from faking a result.
// POST /friends/submit-ocr-result
// ============================================================
app.post('/friends/submit-ocr-result', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl, ocrResult, verificationResult } = req.body;
        if (!matchId || !screenshotUrl) return res.status(400).json({ error: 'matchId and screenshotUrl are required' });
        if (!isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (!match.creator_id || !match.joiner_id)
            return res.status(400).json({ error: 'Match does not have two players yet' });

        const confidence = ocrResult?.confidence ?? 0;
        const fraudScore = verificationResult?.fraudScore ?? 999;
        const score1 = ocrResult?.score1;
        const score2 = ocrResult?.score2;
        const autoWinnerReason = ocrResult?.autoWinnerReason;

        // Server-side re-validation of OCR quality
        if (confidence < 80) {
            return res.status(422).json({ error: `OCR confidence too low (${confidence}%) — please report manually.`, confidence });
        }
        if (fraudScore >= 30) {
            return res.status(422).json({ error: 'Screenshot has suspicious flags. Both players need to upload for corroboration.', fraudScore, warnings: verificationResult?.warnings });
        }
        if (!autoWinnerReason || autoWinnerReason === 'draw') {
            return res.status(422).json({
                error: score1 === score2
                    ? 'It\'s a draw — no payout. Contact admin if this is wrong.'
                    : 'Could not determine winner from screenshot. Please report manually.',
                score1, score2
            });
        }

        // Check that the uploading user's context check didn't fail
        const contextCheck = verificationResult?.checks?.matchContext;
        if (contextCheck && !contextCheck.passed) {
            return res.status(422).json({
                error: contextCheck.warning || 'Screenshot does not appear to be from this match.',
                warnings: verificationResult?.warnings
            });
        }

        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const uploaderWins = autoWinnerReason === 'home_wins';
        const claimedWinnerId = uploaderWins ? user.id : opponentId;
        const claimedScore = `${score1}-${score2}`;

        // ── Two-upload corroboration ──────────────────────────────────────────
        // If the opponent already submitted their OCR result, compare scores.
        // If this is the first submission, store it and wait.
        const existingOcr = match.first_ocr_data;

        if (!existingOcr) {
            // First upload — store the claimed result, wait for opponent
            await supabaseAdmin.from('friend_matches').update({
                first_ocr_data: {
                    submitterId: user.id,
                    claimedWinnerId,
                    score: claimedScore,
                    screenshotUrl,
                    confidence,
                    fraudScore,
                    submittedAt: new Date().toISOString()
                },
                screenshot_url: screenshotUrl,
                reported_winner_id: claimedWinnerId,
                reported_by_id: user.id,
                reported_at: new Date().toISOString()
            }).eq('id', matchId);

            console.log(`📸 OCR first submission: match=${matchId}, user=${user.id}, score=${claimedScore}, claimed winner=${claimedWinnerId}`);

            return res.status(200).json({
                message: 'Score recorded! Waiting for your opponent to upload their screenshot to confirm.',
                waitingForOpponent: true,
                claimedScore,
                youWon: uploaderWins
            });
        }

        // Prevent same user submitting twice
        if (existingOcr.submitterId === user.id) {
            return res.status(400).json({ error: 'You already submitted your screenshot. Waiting for opponent.' });
        }

        // ── Both uploaded — compare scores ────────────────────────────────────
        const scoresMatch = existingOcr.score === claimedScore;
        const winnersMatch = existingOcr.claimedWinnerId === claimedWinnerId;

        if (!scoresMatch || !winnersMatch) {
            // Scores don't agree — flag for admin
            await supabaseAdmin.from('friend_matches').update({
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: `OCR score mismatch: P1 claimed ${existingOcr.score} (winner: ${existingOcr.claimedWinnerId}), P2 claimed ${claimedScore} (winner: ${claimedWinnerId})`,
                verification_data: { firstOcr: existingOcr, secondOcr: { submitterId: user.id, score: claimedScore, claimedWinnerId } }
            }).eq('id', matchId);

            return res.status(409).json({
                error: 'Your screenshot shows a different score than your opponent\'s. Match sent for admin review.',
                p1Score: existingOcr.score,
                p2Score: claimedScore,
                requiresAdminReview: true
            });
        }

        // Scores match — pay out
        const winnerId = claimedWinnerId;
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) {
            console.error('OCR payout error:', payoutErr);
            return res.status(500).json({ error: 'Failed to process payout. Contact support.' });
        }

        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId,
            status: 'completed',
            completed_at: new Date().toISOString(),
            resolution_reason: `OCR corroborated: both players reported ${claimedScore} (confidence avg: ${Math.round((confidence + existingOcr.confidence) / 2)}%)`,
            verification_data: { firstOcr: existingOcr, secondOcr: { submitterId: user.id, score: claimedScore, confidence, fraudScore } }
        }).eq('id', matchId);

        // Store hash and device for future checks
        if (verificationResult?.checks?.duplicate?.details?.hash) {
            try {
                await supabaseAdmin.from('screenshot_hashes')
                    .insert([{ hash: verificationResult.checks.duplicate.details.hash, user_id: user.id, match_id: matchId }]);
            } catch (err) {
                // Ignore duplicate hash errors (hash is unique constraint)
                if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) {
                    console.error('Error storing hash:', err);
                }
            }
        }
        if (verificationResult?.checks?.device?.details?.device) {
            await supabaseAdmin.from('user_screenshot_history')
                .insert([{ user_id: user.id, device: verificationResult.checks.device.details.device, match_id: matchId }]);
        }

        console.log(`✅ OCR corroborated & settled: match=${matchId}, winner=${winnerId}, score=${claimedScore}`);

        res.status(200).json({
            message: 'Match settled! Both screenshots confirmed the same score.',
            winnerId,
            score: claimedScore.replace('-', ' – '),
            prizePaid: match.winner_prize,
            youWon: winnerId === user.id,
            autoSettled: true,
            corroborated: true
        });
    } catch (err) {
        console.error('OCR auto-settle error:', err);
        return sendGenericError(res, 500, 'Failed to process result', err);
    }
});

// ============================================================
// MY MATCHES ENDPOINT (FIXED - NO JOIN SYNTAX)
// ============================================================
app.get('/friends/my-matches', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

        // Fetch matches where user is creator or joiner
        const { data: matches, error } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .or(`creator_id.eq.${user.id},joiner_id.eq.${user.id}`)
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) {
            console.error('Fetch matches error:', error);
            return res.json([]);
        }

        // Fetch usernames for all unique user IDs in the matches
        const userIds = new Set();
        matches?.forEach(m => {
            if (m.creator_id) userIds.add(m.creator_id);
            if (m.joiner_id) userIds.add(m.joiner_id);
        });
        const userIdArray = Array.from(userIds);

        let profileMap = {};
        if (userIdArray.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles')
                .select('id, username')
                .in('id', userIdArray);
            if (profiles) {
                profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
            }
        }

        // Attach usernames to matches
        const enrichedMatches = matches?.map(m => ({
            ...m,
            creator: m.creator_id ? { username: profileMap[m.creator_id] || null } : null,
            joiner: m.joiner_id ? { username: profileMap[m.joiner_id] || null } : null
        })) || [];

        res.json(enrichedMatches);
    } catch (err) {
        console.error('Fetch matches error:', err);
        res.json([]);
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
        if (!matchId) return res.status(400).json({ error: 'Match ID is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) {
            console.error('Match not found:', matchId, matchErr);
            return res.status(404).json({ error: 'Match not found' });
        }

        if (match.creator_id !== user.id) {
            return res.status(403).json({ error: 'Only match creator can cancel' });
        }

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
        if (match.status !== 'pending' && match.status !== 'expired') {
            return res.status(400).json({ error: `Cannot cancel ${match.status} match` });
        }

        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: user.id,
            p_amount: match.wager_amount
        });

        if (refundErr) {
            console.error('Refund error:', refundErr);
            return res.status(500).json({ error: 'Failed to refund wager' });
        }

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
// FRIEND MATCH STATUS CHECK (for real-time polling)
// ============================================================
app.get('/friends/match-status/:matchId', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.params;
        // Validate UUID format
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(matchId)) {
            return res.status(400).json({ error: 'Invalid match ID format' });
        }

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) {
            return res.status(404).json({ error: 'Match not found' });
        }

        if (match.creator_id !== user.id && match.joiner_id !== user.id) {
            return res.status(403).json({ error: 'Not authorized to view this match' });
        }

        // Fetch joiner username if exists
        let joinerUsername = null;
        if (match.joiner_id) {
            const { data: profile } = await supabaseAdmin
                .from('profiles')
                .select('username')
                .eq('id', match.joiner_id)
                .maybeSingle();
            joinerUsername = profile?.username;
        }

        res.json({
            matchId: match.id,
            matchCode: match.match_code,
            status: match.status,
            joinerUsername,
            wagerAmount: match.wager_amount,
            winnerPrize: match.winner_prize,
            expiresAt: match.expires_at,
            startedAt: match.started_at
        });
    } catch (err) {
        console.error('Match status error:', err);
        res.status(500).json({ error: 'Failed to get match status' });
    }
});

// ============================================================
// AUTO-RESOLVE ABANDONED MATCHES (Background Task)
// ============================================================
async function autoResolveAbandonedMatches() {
    try {
        console.log('🔍 Checking for abandoned matches...');
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();

        const { data: abandonedMatches, error } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('status', 'active')
            .not('reported_by_id', 'is', null)
            .lt('reported_at', twoHoursAgo);  // Fixed: use reported_at

        if (error) {
            console.error('Error fetching abandoned matches:', error);
            return;
        }

        if (!abandonedMatches || abandonedMatches.length === 0) {
            console.log('✅ No abandoned matches found');
            return;
        }

        console.log(`⚠️  Found ${abandonedMatches.length} abandoned matches`);

        for (const match of abandonedMatches) {
            const winnerId = match.reported_winner_id;
            await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: winnerId,
                p_amount: match.winner_prize
            });
            await supabaseAdmin.from('friend_matches').update({
                winner_id: winnerId,
                status: 'completed',
                completed_at: new Date().toISOString(),
                auto_resolved: true,
                resolution_reason: 'Opponent failed to report within 2 hours'
            }).eq('id', match.id);
            console.log(`✅ Auto-resolved match ${match.match_code} - Winner: ${winnerId}`);
        }
    } catch (err) {
        console.error('Auto-resolve error:', err);
    }
}

setInterval(autoResolveAbandonedMatches, 30 * 60 * 1000);
setTimeout(autoResolveAbandonedMatches, 10000);

// ============================================================
// WALLET DEPOSIT
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
            .from('transactions')
            .select('status, mpesa_receipt')
            .eq('checkout_request_id', checkoutId)
            .maybeSingle();
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
                .from('transactions')
                .select('user_id')
                .eq('checkout_request_id', CheckoutRequestID)
                .maybeSingle();

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
            .eq('checkout_request_id', checkoutId)
            .maybeSingle();
        res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt });
    } catch (err) {
        console.error('Mpesa status error:', err);
        res.status(500).json({ error: 'Internal server error' });
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

// FIXED: admin friend matches using separate profile fetch
app.get('/admin/friend-matches', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { status } = req.query;
        let query = supabaseAdmin.from('friend_matches')
            .select('*')
            .order('created_at', { ascending: false });
        if (status && status !== 'all') query = query.eq('status', status);
        const { data, error } = await query;
        if (error) return res.status(500).json({ error: error.message });

        // Fetch profiles for all users involved
        const userIds = new Set();
        data?.forEach(m => {
            if (m.creator_id) userIds.add(m.creator_id);
            if (m.joiner_id) userIds.add(m.joiner_id);
            if (m.winner_id) userIds.add(m.winner_id);
        });
        const userIdArray = Array.from(userIds);
        let profileMap = {};
        if (userIdArray.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles')
                .select('id, username')
                .in('id', userIdArray);
            if (profiles) {
                profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
            }
        }

        const enriched = data?.map(m => ({
            ...m,
            creator: m.creator_id ? { username: profileMap[m.creator_id] } : null,
            joiner: m.joiner_id ? { username: profileMap[m.joiner_id] } : null,
            winner: m.winner_id ? { username: profileMap[m.winner_id] } : null
        })) || [];

        res.json(enriched);
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
// SCREENSHOT UPLOAD + OCR VERIFICATION
// POST /screenshots/upload-and-verify
// ============================================================
const screenshotUploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { error: 'Too many screenshot uploads. Try again later.' }
});

app.post('/screenshots/upload-and-verify', screenshotUploadLimiter, async (req, res) => {
    const multer = getMulter();
    const upload = multer({
        storage: multer.memoryStorage(),
        limits: { fileSize: 10 * 1024 * 1024 },
        fileFilter: (req, file, cb) => {
            const allowed = ['image/jpeg', 'image/png', 'image/webp'];
            if (allowed.includes(file.mimetype)) cb(null, true);
            else cb(new Error('Only JPEG, PNG, and WebP images are allowed'));
        }
    }).single('screenshot');

    await new Promise((resolve, reject) => {
        upload(req, res, (err) => {
            if (err) reject(err);
            else resolve();
        });
    }).catch((err) => {
        return res.status(400).json({ error: err.message || 'Invalid file upload' });
    });

    if (res.headersSent) return;

    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        if (!req.file) return res.status(400).json({ error: 'No screenshot file provided' });

        const { matchId } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) {
            return res.status(403).json({ error: 'You are not part of this match' });
        }
        if (match.status !== 'active') {
            return res.status(400).json({ error: 'Match is not active' });
        }

        const imageBuffer = req.file.buffer;

        // ── Run fraud checks and OCR BEFORE storing ──────────────────────────
        // We refuse to store obvious fakes — no point cluttering storage.
        const verifier = getVerifier();
        let verificationResult = null;
        let ocrResult = null;

        if (verifier) {
            try {
                // Fetch opponent's username so verifier can check it appears on screen
                const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
                let opponentUsername = null;
                if (opponentId) {
                    const { data: oppProfile } = await supabaseAdmin
                        .from('profiles')
                        .select('username')
                        .eq('id', opponentId)
                        .maybeSingle();
                    opponentUsername = oppProfile?.username || null;
                }

                // Fetch uploader's own username for self-presence check
                let uploaderUsername = null;
                {
                    const { data: uploaderProfile } = await supabaseAdmin
                        .from('profiles').select('username').eq('id', user.id).maybeSingle();
                    uploaderUsername = uploaderProfile?.username || null;
                }

                [verificationResult, ocrResult] = await Promise.all([
                    verifier.verifyScreenshot(imageBuffer, {
                        userId: user.id,
                        matchId,
                        startedAt: match.started_at,
                        opponentUsername,
                        uploaderUsername,           // NEW: uploader's own name checked too
                        matchCode: match.match_code
                    }),
                    verifier.extractScoreWithConfidence(imageBuffer)
                ]);
            } catch (verifyErr) {
                console.error('Verification error:', verifyErr.message);
            }
        }

        // Hard reject: duplicate screenshot (someone already used this exact image)
        const isDuplicate = verificationResult?.checks?.duplicate?.passed === false &&
            verificationResult.checks.duplicate.details?.originalMatch;
        if (isDuplicate) {
            console.warn(`🚫 Duplicate screenshot rejected: match=${matchId}, user=${user.id}`);
            return res.status(409).json({
                error: verificationResult.checks.duplicate.warning || 'This screenshot has already been used in another match.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

        // Hard reject: taken before match started (impossible screenshot)
        const takenBeforeMatch = verificationResult?.checks?.metadata?.details?.timeDiffMinutes < -5;
        if (takenBeforeMatch) {
            console.warn(`🚫 Pre-match screenshot rejected: match=${matchId}, user=${user.id}`);
            return res.status(422).json({
                error: verificationResult.checks.metadata.warning || 'Screenshot was taken before the match started.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

        // Hard reject: uploaded too early (impossible — match can't be over yet)
        const tooEarly = verificationResult?.checks?.timestamp?.passed === false &&
            verificationResult.checks.timestamp.details?.delayMinutes < 1;
        if (tooEarly) {
            console.warn(`🚫 Too-early upload rejected: match=${matchId}, user=${user.id}`);
            return res.status(422).json({
                error: 'Match cannot have finished yet — wait until the game ends.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

        // Hard reject: image contains no numbers at all — cannot be a game screenshot
        const noNumbers = verificationResult?.checks?.ocrSanity?.passed === false &&
            verificationResult.checks.ocrSanity.details?.hasNumbers === false;
        if (noNumbers) {
            console.warn(`🚫 Non-game image rejected (no numbers): match=${matchId}, user=${user.id}`);
            return res.status(422).json({
                error: 'This doesn\'t look like a game screenshot — no scores or numbers were found. Please upload the end-of-match result screen.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

        // Hard reject: opponent's username not found in image AND OCR confidence is low
        // Both failing together = almost certainly not this match's screenshot.
        // (We allow one to fail alone — OCR isn't perfect — but both together is a strong signal.)
        const contextFailed = verificationResult?.checks?.matchContext?.passed === false &&
            !verificationResult.checks.matchContext.details?.foundPartialUsername;
        const ocrWeak = (ocrResult?.confidence ?? 0) < 40;
        if (contextFailed && ocrWeak) {
            console.warn(`🚫 Wrong-match screenshot rejected: match=${matchId}, user=${user.id}, ocr=${ocrResult?.confidence?.toFixed(0)}%`);
            return res.status(422).json({
                error: 'This screenshot doesn\'t appear to be from this match — your opponent\'s name wasn\'t found and the score couldn\'t be read. Please upload the final score screen from eFootball.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

        // ── Now store the screenshot (passed basic checks) ────────────────────
        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = `match-screenshots/${matchId}/${user.id}-${Date.now()}.${ext}`;

        const { error: uploadErr } = await supabaseAdmin
            .storage
            .from('screenshots')
            .upload(storageKey, imageBuffer, { contentType: req.file.mimetype, upsert: false });

        if (uploadErr) {
            console.error('Storage upload error:', uploadErr);
            return res.status(500).json({ error: 'Failed to store screenshot' });
        }

        const { data: { publicUrl } } = supabaseAdmin
            .storage
            .from('screenshots')
            .getPublicUrl(storageKey);

        // Determine auto-settle eligibility
        let autoWinnerReason = null;
        if (ocrResult?.isValid && ocrResult.confidence >= 80) {
            const s1 = ocrResult.score1;
            const s2 = ocrResult.score2;
            if (s1 !== null && s2 !== null) {
                autoWinnerReason = s1 > s2 ? 'home_wins' : s2 > s1 ? 'away_wins' : 'draw';
            }
        }

        const fraudScore = verificationResult?.fraudScore ?? 0;
        console.log(`📸 Screenshot accepted: match=${matchId}, user=${user.id}, fraud=${fraudScore}, ocr=${ocrResult?.confidence?.toFixed(0) ?? 'n/a'}%, autoSettle=${autoWinnerReason ?? 'no'}`);

        // Store hash at upload time so near-duplicate checks on subsequent uploads work
        // immediately — not just after match completion
        const uploadHash = verificationResult?.checks?.duplicate?.details?.hash;
        if (uploadHash) {
            try {
                await supabaseAdmin.from('screenshot_hashes')
                    .insert([{ hash: uploadHash, user_id: user.id, match_id: matchId }]);
            } catch (err) {
                // Ignore duplicate hash errors (hash is unique constraint)
                if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) {
                    console.error('Error storing hash:', err);
                }
            }
        }

        res.status(200).json({
            screenshotUrl: publicUrl,
            ocrResult: ocrResult ? {
                score1: ocrResult.score1,
                score2: ocrResult.score2,
                confidence: Math.round(ocrResult.confidence),
                isValid: ocrResult.isValid,
                rawText: ocrResult.rawText,
                autoWinnerReason
            } : null,
            verificationResult: verificationResult ? {
                fraudScore,
                recommendation: verificationResult.recommendation,
                warnings: verificationResult.warnings,
                isValid: verificationResult.isValid,
                checks: {
                    metadata: verificationResult.checks.metadata?.passed,
                    timestamp: verificationResult.checks.timestamp?.passed,
                    manipulation: verificationResult.checks.manipulation?.passed,
                    duplicate: verificationResult.checks.duplicate?.passed,
                    ocrSanity: verificationResult.checks.ocrSanity?.passed,
                }
            } : null
        });

    } catch (err) {
        console.error('Screenshot upload/verify error:', err);
        return sendGenericError(res, 500, 'Screenshot processing failed', err);
    }
});

// ============================================================
// OCR-ONLY ENDPOINT (quick re-scan)
// ============================================================
app.post('/screenshots/extract-score', screenshotUploadLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { screenshotUrl } = req.body;
        if (!screenshotUrl) return res.status(400).json({ error: 'screenshotUrl required' });
        if (!isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL' });

        const verifier = getVerifier();
        if (!verifier) return res.status(503).json({ error: 'OCR service unavailable' });

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        const response = await fetch(screenshotUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) return res.status(502).json({ error: 'Failed to fetch screenshot' });

        const buffer = Buffer.from(await response.arrayBuffer());
        const ocrResult = await verifier.extractScoreWithConfidence(buffer);

        res.json({
            score1: ocrResult.score1,
            score2: ocrResult.score2,
            confidence: Math.round(ocrResult.confidence),
            isValid: ocrResult.isValid,
            rawText: ocrResult.rawText
        });
    } catch (err) {
        console.error('Extract score error:', err);
        return sendGenericError(res, 500, 'OCR extraction failed', err);
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