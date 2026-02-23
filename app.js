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

const screenshotUploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { error: 'Too many screenshot uploads. Try again later.' }
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
    const supabaseUrl = process.env.SUPABASE_URL || 'https://wqnnuqudxsnxldlgxhwr.supabase.co';
    const supabaseWss = supabaseUrl.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
    const connectSrc = [
        "'self'",
        koyebUrl,
        frontendUrl,
        supabaseUrl,
        supabaseWss,
    ].filter(Boolean).join(' ');
    res.setHeader("Content-Security-Policy",
        `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src ${connectSrc}`
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
        console.log('📝 Signup request received:', { phone: req.body.phone?.slice(0, 8) + '***', username: req.body.username, teamName: req.body.teamName });

        let { phone, password, username, teamName } = req.body;
        if (!phone || !password || !username || !teamName) {
            console.log('❌ Missing fields');
            return res.status(400).json({ error: 'Missing fields. Phone, password, username, and team name are required.' });
        }
        if (password.length < 6) {
            console.log('❌ Password too short');
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }
        if (teamName.length < 3) {
            return res.status(400).json({ error: 'Team name must be at least 3 characters.' });
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
                console.log('💾 Creating profile with team name...');
                const { error: profileError } = await supabaseAdmin
                    .from('profiles')
                    .upsert([{ id: data.user.id, username, team_name: teamName }]);

                if (profileError) throw profileError;
                console.log('✅ Profile created');

                console.log('💰 Creating wallet...');
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

        // Use a fresh per-request client so signInWithPassword does NOT pollute
        // the shared `supabase` singleton's session. If the singleton's session
        // gets overwritten, every RLS-gated query on it will run as the last
        // logged-in user, causing wrong balances across accounts.
        const loginClient = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_ANON_KEY,
            { auth: { persistSession: false, autoRefreshToken: false } }
        );
        const { data, error } = await loginClient.auth.signInWithPassword({ phone, password });
        if (error) return sendGenericError(res, 400, 'Invalid phone number or password', error);

        res.status(200).json({ message: "Login successful!", session: data.session });
    } catch (err) {
        console.error('Login error:', err);
        return sendGenericError(res, 500, 'Internal server error', err);
    }
});

// ============================================================
// PROFILE ROUTES
// ============================================================
app.post('/profile/team', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { teamName } = req.body;
        if (!teamName || typeof teamName !== 'string' || teamName.length < 3) {
            return res.status(400).json({ error: 'Valid team name required (min 3 characters)' });
        }

        const { error } = await supabaseAdmin
            .from('profiles')
            .update({ team_name: teamName })
            .eq('id', user.id);

        if (error) throw error;
        res.json({ message: 'Team name updated', teamName });
    } catch (err) {
        console.error('Profile team update error:', err);
        res.status(500).json({ error: 'Failed to update team name' });
    }
});

app.get('/profile', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data: profile, error } = await supabaseAdmin
            .from('profiles')
            .select('username, team_name')
            .eq('id', user.id)
            .single();

        if (error) throw error;
        res.json(profile);
    } catch (err) {
        console.error('Profile fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch profile' });
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

        const { data, error: dbErr } = await supabaseAdmin
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
        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: withdrawAmount
        });
        if (deductErr) {
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
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin.rpc('join_tournament_wallet', {
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
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin.rpc('join_tournament_mpesa', {
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

        const { data: wallet } = await supabaseAdmin
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .maybeSingle();

        if (!wallet || wallet.balance < wagerAmount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Get creator's team name
        const { data: creatorProfile } = await supabaseAdmin
            .from('profiles')
            .select('team_name')
            .eq('id', user.id)
            .single();
        const creatorTeam = creatorProfile?.team_name || null;
        if (!creatorTeam) {
            return res.status(400).json({ error: 'Please set your team name in profile before creating a match.' });
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
                creator_team: creatorTeam,
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

        // Get joiner's team name
        const { data: joinerProfile } = await supabaseAdmin
            .from('profiles')
            .select('team_name')
            .eq('id', user.id)
            .single();
        const joinerTeam = joinerProfile?.team_name || null;
        if (!joinerTeam) {
            return res.status(400).json({ error: 'Please set your team name in profile before joining a match.' });
        }

        const { data: wallet } = await supabaseAdmin
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
            .update({
                joiner_id: user.id,
                joiner_team: joinerTeam,
                status: 'active',
                started_at: new Date().toISOString()
            })
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

// ============================================================
// DEPRECATED: Old result submission endpoint (kept for compatibility)
// ============================================================
app.post('/friends/submit-result', sensitiveLimiter, async (req, res) => {
    console.warn('⚠️ Deprecated endpoint /friends/submit-result called. Use /friends/submit-ocr-result instead.');
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
// OCR AUTO-SETTLE: Single-player upload with confidence-based resolution
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

        const confidence = verificationResult?.confidence ?? 0;
        const fraudScore = verificationResult?.fraudScore ?? 999;
        const score1 = ocrResult?.score1;
        const score2 = ocrResult?.score2;
        const teamMatch = verificationResult?.teamMatch;

        // Server-side re-validation of confidence
        if (confidence < 50) {
            return res.status(422).json({ error: `Confidence too low (${confidence}%) — please upload a clearer screenshot or contact admin.`, confidence });
        }
        if (fraudScore >= 50) {
            return res.status(422).json({ error: 'Screenshot has suspicious flags. Match sent for admin review.', fraudScore, warnings: verificationResult?.warnings });
        }

        // Determine winner based on team mapping and score
        let winnerId = null;
        let draw = false;
        if (teamMatch && teamMatch.bestMapping !== 'ambiguous') {
            // Determine which player corresponds to home/away
            const isCreatorHome = (teamMatch.bestHome === match.creator_team);
            const homeId = isCreatorHome ? match.creator_id : match.joiner_id;
            const awayId = isCreatorHome ? match.joiner_id : match.creator_id;
            if (score1 > score2) winnerId = homeId;
            else if (score2 > score1) winnerId = awayId;
            else draw = true;
        } else {
            // Team matching failed – cannot auto-settle
            return res.status(422).json({ error: 'Could not reliably match team names. Please report manually.' });
        }

        if (draw) {
            // Draw – no payout, just mark completed
            await supabaseAdmin.from('friend_matches').update({
                status: 'completed',
                completed_at: new Date().toISOString(),
                settlement_method: 'draw',
                settlement_confidence: confidence,
                verification_data: verificationResult
            }).eq('id', matchId);
            return res.status(200).json({ message: 'Match ended in a draw. No payout.', draw: true });
        }

        // Auto-settle if confidence is high enough
        if (confidence >= 85) {
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: winnerId,
                p_amount: match.winner_prize
            });
            if (payoutErr) throw payoutErr;

            await supabaseAdmin.from('friend_matches').update({
                winner_id: winnerId,
                status: 'completed',
                completed_at: new Date().toISOString(),
                settlement_confidence: confidence,
                settlement_method: 'auto',
                verification_data: verificationResult
            }).eq('id', matchId);

            console.log(`✅ Auto-settled match ${matchId} – winner ${winnerId}, prize ${match.winner_prize}`);

            return res.status(200).json({
                message: 'Match auto-settled! Winner paid.',
                winnerId,
                prizePaid: match.winner_prize,
                confidence,
                youWon: winnerId === user.id
            });
        }

        // Medium confidence – open challenge window
        const challengeDeadline = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
        await supabaseAdmin.from('friend_matches').update({
            challenge_deadline: challengeDeadline,
            challenge_uploaded: false,
            first_upload_winner_id: winnerId,
            first_upload_confidence: confidence,
            first_upload_screenshot_url: screenshotUrl,
            settlement_confidence: confidence,
            verification_data: verificationResult
        }).eq('id', matchId);

        return res.status(200).json({
            message: 'Result recorded. Your opponent has 2 hours to challenge.',
            challengeDeadline,
            confidence
        });

    } catch (err) {
        console.error('OCR auto-settle error:', err);
        return sendGenericError(res, 500, 'Failed to process result', err);
    }
});

// ============================================================
// OPPONENT CHALLENGE: second player uploads screenshot
// POST /friends/challenge/:matchId
// ============================================================
app.post('/friends/challenge/:matchId', screenshotUploadLimiter, async (req, res) => {
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

        const { matchId } = req.params;
        if (!req.file) return res.status(400).json({ error: 'No screenshot provided' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });

        // Verify user is part of match and match is in challenge window
        if (match.creator_id !== user.id && match.joiner_id !== user.id) {
            return res.status(403).json({ error: 'Not your match' });
        }
        if (match.status !== 'active' || !match.challenge_deadline) {
            return res.status(400).json({ error: 'No active challenge window for this match' });
        }
        if (new Date() > new Date(match.challenge_deadline)) {
            return res.status(400).json({ error: 'Challenge window expired' });
        }
        if (match.challenge_uploaded) {
            return res.status(400).json({ error: 'Opponent already uploaded a challenge screenshot' });
        }

        // Upload to storage
        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = `match-challenges/${matchId}/${user.id}-${Date.now()}.${ext}`;
        const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, req.file.buffer, { contentType: req.file.mimetype });
        if (uploadErr) throw uploadErr;
        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        // Mark challenge as uploaded and set match to disputed
        await supabaseAdmin
            .from('friend_matches')
            .update({
                challenge_uploaded: true,
                challenge_screenshot_url: publicUrl,
                challenge_uploaded_at: new Date().toISOString(),
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: 'Opponent challenged result'
            })
            .eq('id', matchId);

        res.json({ message: 'Challenge screenshot uploaded. Match sent for admin review.' });
    } catch (err) {
        console.error('Challenge upload error:', err);
        res.status(500).json({ error: 'Failed to process challenge' });
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
            startedAt: match.started_at,
            challengeDeadline: match.challenge_deadline
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
            .lt('reported_at', twoHoursAgo);

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
            // Instead of auto-paying, mark as disputed for admin review
            await supabaseAdmin.from('friend_matches').update({
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: 'Only one player reported within time limit'
            }).eq('id', match.id);
            console.log(`⚠️  Match ${match.match_code} disputed due to missing opponent report.`);
        }
    } catch (err) {
        console.error('Auto-resolve error:', err);
    }
}

setInterval(autoResolveAbandonedMatches, 30 * 60 * 1000);
setTimeout(autoResolveAbandonedMatches, 10000);

// ============================================================
// AUTO-RESOLVE CHALLENGE WINDOWS (Background Task)
// ============================================================
async function resolveChallengeWindows() {
    try {
        const now = new Date().toISOString();
        const { data: matches, error } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('status', 'active')
            .not('challenge_deadline', 'is', null)
            .lt('challenge_deadline', now)
            .eq('challenge_uploaded', false);

        if (error) throw error;
        if (!matches || matches.length === 0) return;

        console.log(`⏰ Resolving ${matches.length} expired challenge windows`);

        for (const match of matches) {
            if (match.first_upload_winner_id) {
                // Pay the original reporter
                const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
                    p_user_id: match.first_upload_winner_id,
                    p_amount: match.winner_prize
                });
                if (payoutErr) {
                    console.error(`Payout failed for match ${match.id}:`, payoutErr);
                    continue;
                }
                await supabaseAdmin.from('friend_matches').update({
                    winner_id: match.first_upload_winner_id,
                    status: 'completed',
                    completed_at: new Date().toISOString(),
                    settlement_method: 'challenge_timeout',
                    settlement_confidence: match.first_upload_confidence
                }).eq('id', match.id);
                console.log(`💰 Challenge window expired – paid ${match.first_upload_winner_id} for match ${match.id}`);
            } else {
                // No winner recorded – mark disputed
                await supabaseAdmin.from('friend_matches').update({
                    status: 'disputed',
                    disputed_at: new Date().toISOString(),
                    dispute_reason: 'Challenge window expired but no winner recorded'
                }).eq('id', match.id);
            }
        }
    } catch (err) {
        console.error('Resolve challenge windows error:', err);
    }
}

setInterval(resolveChallengeWindows, 10 * 60 * 1000);
setTimeout(resolveChallengeWindows, 20000);

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
        const { data } = await supabaseAdmin.from('transactions').select('status, mpesa_receipt')
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
        const verifier = getVerifier();
        if (!verifier) {
            return res.status(503).json({ error: 'Verification service unavailable' });
        }

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

        let uploaderUsername = null;
        {
            const { data: uploaderProfile } = await supabaseAdmin
                .from('profiles').select('username').eq('id', user.id).maybeSingle();
            uploaderUsername = uploaderProfile?.username || null;
        }

        const verificationResult = await verifier.verifyScreenshot(imageBuffer, {
            userId: user.id,
            matchId,
            startedAt: match.started_at,
            opponentUsername,
            uploaderUsername,
            matchCode: match.match_code,
            creatorTeam: match.creator_team,
            joinerTeam: match.joiner_team
        });

        const ocrResult = await verifier.extractScoreWithConfidence(imageBuffer);

        // Fraud checks (duplicate, pre-match, too early, etc.)
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

        const takenBeforeMatch = verificationResult?.checks?.metadata?.details?.timeDiffMinutes < -5;
        if (takenBeforeMatch) {
            console.warn(`🚫 Pre-match screenshot rejected: match=${matchId}, user=${user.id}`);
            return res.status(422).json({
                error: verificationResult.checks.metadata.warning || 'Screenshot was taken before the match started.',
                fraudScore: verificationResult.fraudScore,
                warnings: verificationResult.warnings
            });
        }

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

        // Store screenshot
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

        const uploadHash = verificationResult?.checks?.duplicate?.details?.hash;
        if (uploadHash) {
            try {
                await supabaseAdmin.from('screenshot_hashes')
                    .insert([{ hash: uploadHash, user_id: user.id, match_id: matchId }]);
            } catch (err) {
                if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) {
                    console.error('Error storing hash:', err);
                }
            }
        }

        console.log(`📸 Screenshot accepted: match=${matchId}, user=${user.id}, confidence=${verificationResult.confidence}%, recommendation=${verificationResult.recommendation}`);

        res.status(200).json({
            screenshotUrl: publicUrl,
            ocrResult: ocrResult ? {
                score1: ocrResult.score1,
                score2: ocrResult.score2,
                confidence: Math.round(ocrResult.confidence),
                isValid: ocrResult.isValid,
                rawText: ocrResult.rawText
            } : null,
            verificationResult: {
                fraudScore: verificationResult.fraudScore,
                recommendation: verificationResult.recommendation,
                confidence: verificationResult.confidence,
                teamMatch: verificationResult.teamMatch,
                warnings: verificationResult.warnings,
                isValid: verificationResult.isValid,
                checks: {
                    metadata: verificationResult.checks.metadata?.passed,
                    timestamp: verificationResult.checks.timestamp?.passed,
                    manipulation: verificationResult.checks.manipulation?.passed,
                    duplicate: verificationResult.checks.duplicate?.passed,
                    ocrSanity: verificationResult.checks.ocrSanity?.passed,
                    teamNames: verificationResult.checks.teamNames?.passed,
                    finalWord: verificationResult.checks.finalWord?.passed
                }
            }
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