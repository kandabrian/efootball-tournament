// ============================================================
// STEP 1: Boot diagnostics — VERY FIRST LINES, before anything
// ============================================================
console.log("========================================");
console.log("🚀 BOOT START:", new Date().toISOString());
console.log("   Node:", process.version);
console.log("   Platform:", process.platform);
console.log("   Memory at boot:", Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + "MB used");
console.log("========================================");

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

let _multer = null;
function getMulter() {
    if (!_multer) _multer = require('multer');
    return _multer;
}

// ============================================================
// STEP 3: Validate env vars
// ============================================================
console.log("🔑 Checking environment variables...");
const REQUIRED_VARS = ['SUPABASE_URL','SUPABASE_ANON_KEY','SUPABASE_SERVICE_ROLE_KEY','MPESA_SERVER_URL'];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error("❌ FATAL: Missing required env vars:", missing.join(', '));
    process.exit(1);
}
console.log("✅ Required env vars present.");
console.log("   APP_SERVER_URL:", process.env.APP_SERVER_URL || "⚠️  NOT SET");
console.log("   FRONTEND_URL:", process.env.FRONTEND_URL || "⚠️  NOT SET (CORS may block frontend)");
console.log("   ADMIN_KEY:", process.env.ADMIN_KEY ? "✅ set" : "⚠️  NOT SET (admin routes disabled)");
console.log("   STORAGE_DOMAIN:", process.env.STORAGE_DOMAIN || "⚠️  NOT SET (using default: *.supabase.co)");
console.log("   PORT:", process.env.PORT || "3000 (default)");

// ============================================================
// STEP 4: Load Supabase
// ============================================================
console.log("📦 Loading Supabase client...");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
console.log("✅ Supabase clients created.");

// ============================================================
// STEP 5: LAZY-LOAD ScreenshotVerifier
// FIX: Unwrap .default for ESM-compiled modules; validate constructor
// ============================================================
let ScreenshotVerifier = null;
let _geminiArbitrate   = null;

async function getVerifierClass() {
    if (ScreenshotVerifier) return ScreenshotVerifier;
    console.log('📦 Loading ScreenshotVerifier module...');
    const loaded = require('./screenshot-verifier');
    // Handle both `module.exports = Class` and `module.exports = { ScreenshotVerifier, geminiArbitrate }`
    ScreenshotVerifier = loaded?.ScreenshotVerifier || loaded?.default || loaded;
    _geminiArbitrate   = loaded?.geminiArbitrate   || null;
    if (typeof ScreenshotVerifier !== 'function') {
        throw new Error(
            `ScreenshotVerifier is not a constructor. Got: ${typeof ScreenshotVerifier}. ` +
            `Check that screenshot-verifier.js ends with: module.exports = { ScreenshotVerifier, geminiArbitrate }`
        );
    }
    return ScreenshotVerifier;
}

async function geminiArbitrate(type, payload) {
    await getVerifierClass(); // ensure module is loaded
    if (!_geminiArbitrate) { console.warn('⚠️ geminiArbitrate not available'); return { resolved: false, reason: 'not_loaded' }; }
    return _geminiArbitrate(type, payload);
}

// ============================================================
// STEP 6: Build Express app
// ============================================================
console.log("🏗️  Configuring Express app...");
const app = express();
const port = process.env.PORT || 3000;

const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    message: { error: 'Too many requests. Try again later.' },
    standardHeaders: true, legacyHeaders: false
});

const depositLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 5,
    message: { error: 'Too many deposit attempts. Try again later.' },
    standardHeaders: true, legacyHeaders: false
});

const screenshotUploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 15,
    message: { error: 'Too many screenshot uploads. Try again later.' }
});

const adminLimiter = rateLimit({
    windowMs: 60 * 1000, max: 5,
    message: { error: 'Admin rate limit exceeded. Try again later.' },
    keyGenerator: (req) => req.ip,
    skip: (req) => !req.headers['x-admin-key']
});

function normalizePhone(phone) {
    if (!phone || typeof phone !== 'string') { console.warn('⚠️ Invalid phone type:', typeof phone); return null; }
    if (phone.length > 30) { console.warn('⚠️ Phone number too long'); return null; }
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 0) { console.warn('⚠️ Phone number has no digits'); return null; }
    if (cleaned.startsWith('254') && cleaned.length === 12) {
        const prefix = cleaned.substring(3, 4);
        if (!['1', '7'].includes(prefix)) { console.warn('⚠️ Invalid Kenya number prefix:', prefix); return null; }
        return '+' + cleaned;
    } else if (cleaned.startsWith('0') && cleaned.length === 10) {
        const prefix = cleaned.substring(1, 2);
        if (!['1', '7'].includes(prefix)) { console.warn('⚠️ Invalid Kenya number prefix:', prefix); return null; }
        return '+254' + cleaned.slice(1);
    } else if (cleaned.length === 9) {
        const prefix = cleaned.substring(0, 1);
        if (!['1', '7'].includes(prefix)) { console.warn('⚠️ Invalid Kenya number prefix:', prefix); return null; }
        return '+254' + cleaned;
    } else {
        console.warn('⚠️ Invalid phone format:', cleaned.slice(0, 4) + '...');
        return null;
    }
}

function isAdmin(req) {
    if (!process.env.ADMIN_KEY) return false;
    return req.headers['x-admin-key'] === process.env.ADMIN_KEY;
}

const EFOOTBALL_TEAMS = [
    'Arsenal', 'Aston Villa', 'Bournemouth', 'Brentford', 'Brighton', 'Chelsea', 'Crystal Palace',
    'Everton', 'Fulham', 'Ipswich Town', 'Leicester City', 'Liverpool', 'Manchester City',
    'Manchester United', 'Newcastle United', 'Nottingham Forest', 'Southampton', 'Tottenham',
    'West Ham', 'Wolverhampton',
    'Real Madrid', 'Barcelona', 'Atletico Madrid', 'Sevilla', 'Real Sociedad', 'Villarreal',
    'Betis', 'Getafe', 'Rayo Vallecano', 'Osasuna', 'Celta Vigo', 'Athletic Bilbao',
    'Real Valladolid', 'Almeria', 'Girona', 'Las Palmas', 'Valencia', 'Mallorca',
    'Juventus', 'Inter Milan', 'AC Milan', 'Roma', 'Lazio', 'Napoli', 'Atalanta',
    'Fiorentina', 'Torino', 'Monza', 'Bologna', 'Sassuolo', 'Sampdoria', 'Lecce',
    'Verona', 'Salernitana', 'Frosinone', 'Cagliari', 'Empoli', 'Genoa',
    'Bayern Munich', 'Borussia Dortmund', 'RB Leipzig', 'Bayer Leverkusen', 'VfB Stuttgart',
    'Hamburg', 'Mainz', 'Cologne', 'Union Berlin', 'Hoffenheim', 'Freiburg', 'Wolfsburg',
    'Eintracht Frankfurt', 'Schalke 04', 'Borussia Monchengladbach', 'Augsburg', 'Hertha Berlin',
    'Paris Saint-Germain', 'Marseille', 'Lyon', 'AS Monaco', 'Lille', 'Nice', 'Rennes',
    'Lens', 'Toulouse', 'Montpellier', 'Nantes', 'Strasbourg', 'Brest', 'Reims',
    'PSV Eindhoven', 'Ajax', 'Feyenoord', 'Porto', 'Benfica', 'Sporting CP', 'Celtic',
    'Rangers', 'RB Salzburg', 'Galatasaray', 'Fenerbahçe', 'Santos', 'Flamengo', 'Corinthians',
    'Palmeiras', 'Al Ahly', 'Al Nassr', 'Al Hilal', 'River Plate', 'Boca Juniors'
];

function validateEFootballCode(code) {
    if (!code || typeof code !== 'string') return false;
    return /^[A-Z0-9]{4,8}$/.test(code.toUpperCase());
}

function extractTeamNames(ocrText) {
    if (!ocrText || typeof ocrText !== 'string') return { home: null, away: null };
    const textUpper = ocrText.toUpperCase();
    const foundTeams = [];
    for (const team of EFOOTBALL_TEAMS) {
        const teamUpper = team.toUpperCase();
        if (textUpper.includes(teamUpper)) {
            foundTeams.push({ name: team, position: ocrText.toUpperCase().indexOf(teamUpper) });
        }
    }
    foundTeams.sort((a, b) => a.position - b.position);
    return {
        home: foundTeams.length > 0 ? foundTeams[0].name : null,
        away: foundTeams.length > 1 ? foundTeams[1].name : null,
        allFound: foundTeams.map(t => t.name)
    };
}

function sendGenericError(res, statusCode, message, internalError) {
    console.error('Error:', message, '|', internalError?.message || internalError);
    res.status(statusCode).json({ error: message });
}

async function getAuthUser(jwt) {
    const { data: { user }, error } = await supabase.auth.getUser(jwt);
    return { user: user || null, error: error || null };
}

function isValidScreenshotUrl(url) {
    try {
        const parsed = new URL(url);
        const storageDomain = process.env.STORAGE_DOMAIN || 'supabase.co';
        if (parsed.protocol !== 'https:') { console.warn('❌ Screenshot URL must use HTTPS:', url); return false; }
        if (!parsed.hostname.endsWith(storageDomain)) { console.warn('❌ Screenshot URL from unauthorized domain:', parsed.hostname); return false; }
        return true;
    } catch (err) { console.warn('❌ Invalid screenshot URL:', url); return false; }
}

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
    process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null,
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000'
].filter(Boolean);

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        // Allow same-origin Vercel requests (no origin header) and listed origins
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development' || (process.env.VERCEL_URL && origin.includes('vercel.app'))) {
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

const MULTIPART_ROUTES = ["/screenshots/upload-and-verify", "/friends/submit-penalty-result", "/friends/challenge"];
app.use((req, res, next) => {
    const isMultipart = MULTIPART_ROUTES.some(r => req.path.startsWith(r));
    if (isMultipart) return next();
    express.json()(req, res, next);
});

app.use((req, res, next) => {
    const koyebUrl = process.env.APP_SERVER_URL || '';
    const frontendUrl = process.env.FRONTEND_URL || '';
    const supabaseUrl = process.env.SUPABASE_URL || 'https://wqnnuqudxsnxldlgxhwr.supabase.co';
    const supabaseWss = supabaseUrl.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
    const connectSrc = ["'self'", koyebUrl, frontendUrl, supabaseUrl, supabaseWss].filter(Boolean).join(' ');
    res.setHeader("Content-Security-Policy",
        `default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src ${connectSrc}`
    );
    next();
});
app.use(express.static(__dirname));
console.log("✅ Middleware configured.");

// ============================================================
// PAGE ROUTES
// ============================================================
app.get('/health', (req, res) => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString(), service: 'vumbua-backend', memory_mb: memMB, uptime_seconds: Math.round(process.uptime()) });
});

app.get('/debug/config', adminLimiter, (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    res.json({
        environment: {
            NODE_ENV: process.env.NODE_ENV || 'not set', PORT: process.env.PORT || 'not set',
            APP_SERVER_URL: process.env.APP_SERVER_URL ? '✅ set' : '❌ NOT SET',
            FRONTEND_URL: process.env.FRONTEND_URL ? '✅ set' : '❌ NOT SET',
            SUPABASE_URL: process.env.SUPABASE_URL ? '✅ set' : '❌ NOT SET',
            SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY ? '✅ set (length: ' + process.env.SUPABASE_ANON_KEY.length + ')' : '❌ NOT SET',
            SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ set (length: ' + process.env.SUPABASE_SERVICE_ROLE_KEY.length + ')' : '❌ NOT SET',
            MPESA_SERVER_URL: process.env.MPESA_SERVER_URL ? '✅ set' : '❌ NOT SET',
            ADMIN_KEY: process.env.ADMIN_KEY ? '✅ set' : '❌ NOT SET',
            STORAGE_DOMAIN: process.env.STORAGE_DOMAIN ? '✅ set' : '⚠️  using default: *.supabase.co'
        },
        supabase: { client_initialized: !!supabase, admin_initialized: !!supabaseAdmin, url: process.env.SUPABASE_URL || 'NOT SET' },
        server: { uptime_seconds: Math.round(process.uptime()), memory_mb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024), node_version: process.version, platform: process.platform }
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/war-room', (req, res) => res.sendFile(path.join(__dirname, 'war-room.html')));

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/auth/signup', async (req, res) => {
    try {
        console.log('📝 Signup request received:', { phone: req.body.phone?.slice(0, 8) + '***', username: req.body.username, teamName: req.body.teamName });
        let { phone, password, username, teamName } = req.body;
        if (!phone || !password || !username || !teamName) return res.status(400).json({ error: 'Missing fields. Phone, password, username, and team name are required.' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        if (teamName.length < 3) return res.status(400).json({ error: 'Team name must be at least 3 characters.' });

        phone = normalizePhone(phone);
        if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

        console.log('🔐 Attempting Supabase auth signup...');
        const { data, error } = await supabase.auth.signUp({ phone, password, options: { data: { username } } });
        if (error) return sendGenericError(res, 400, 'Signup failed. Please try again.', error);
        console.log('✅ User created:', data.user?.id);

        if (data.user) {
            try {
                const { error: profileError } = await supabaseAdmin.from('profiles').upsert([{ id: data.user.id, username, team_name: teamName }]);
                if (profileError) throw profileError;
                const { data: existingWallet } = await supabaseAdmin.from('wallets').select('user_id').eq('user_id', data.user.id).maybeSingle();
                let walletError = null;
                if (!existingWallet) {
                    const { error } = await supabaseAdmin.from('wallets').insert([{ user_id: data.user.id, balance: 0 }]);
                    walletError = error;
                }
                if (walletError) throw walletError;
            } catch (dbErr) {
                console.error('❌ Failed to create profile/wallet:', dbErr.message, dbErr.code);
                await supabaseAdmin.auth.admin.deleteUser(data.user.id).catch((delErr) => console.error('❌ Failed to rollback user:', delErr));
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
        const loginClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
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
        if (!teamName || typeof teamName !== 'string' || teamName.length < 3) return res.status(400).json({ error: 'Valid team name required (min 3 characters)' });
        const { error } = await supabaseAdmin.from('profiles').update({ team_name: teamName }).eq('id', user.id);
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
        const { data: profile, error } = await supabaseAdmin.from('profiles').select('username, team_name').eq('id', user.id).single();
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
        const { data, error: dbErr } = await supabaseAdmin.from('wallets').select('balance').eq('user_id', user.id).maybeSingle();
        if (dbErr) throw dbErr;
        res.json({ balance: data ? data.balance : 0 });
    } catch (err) {
        console.error('Balance error:', err);
        return sendGenericError(res, 500, 'Failed to fetch balance', err);
    }
});

// ============================================================
// WITHDRAWAL ROUTES
// ============================================================
const { router: withdrawalRouter, processMpesaWithdrawal } = require('./routes/withdrawals');

app.use('/wallet/withdrawals', (req, res, next) => {
    req.processMpesaWithdrawal = (withdrawalId) => processMpesaWithdrawal(supabaseAdmin, withdrawalId);
    next();
}, withdrawalRouter);

app.post('/wallet/withdraw', sensitiveLimiter, (req, res, next) => {
    if (req.body.phone && !req.body.phoneNumber) req.body.phoneNumber = req.body.phone;
    req.processMpesaWithdrawal = (withdrawalId) => processMpesaWithdrawal(supabaseAdmin, withdrawalId);
    req.url = '/request';
    withdrawalRouter.handle(req, res, next);
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
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin.rpc('join_tournament_wallet', { p_user_id: user.id, p_tournament_id: tournamentId, p_entry_fee: entryFee });
            if (rpcErr) {
                if (rpcErr.message.includes('double-join') || rpcErr.code === '23505') return res.status(400).json({ error: "Umeshajiunga tournament hii!" });
                return res.status(400).json({ error: rpcErr.message });
            }
            roomCode = rpcRoomCode;
        } else if (paymentMethod === 'mpesa') {
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin.rpc('join_tournament_mpesa', { p_user_id: user.id, p_tournament_id: tournamentId, p_checkout_id: checkoutId });
            if (rpcErr) {
                if (rpcErr.message.includes('double-join') || rpcErr.code === '23505') return res.status(400).json({ error: "Umeshajiunga tournament hii!" });
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

        const { wagerAmount, efootballCode } = req.body;
        if (!wagerAmount || isNaN(wagerAmount) || wagerAmount < 50) return res.status(400).json({ error: 'Minimum wager is KES 50' });
        if (!efootballCode) return res.status(400).json({ error: 'eFootball room code is required. Create a Friends Match room in eFootball first, then enter the code here.' });
        if (!validateEFootballCode(efootballCode)) return res.status(400).json({ error: 'Invalid eFootball code format. Codes should be 4-8 alphanumeric characters (e.g., ABC123).' });

        const { data: wallet } = await supabaseAdmin.from('wallets').select('balance').eq('user_id', user.id).maybeSingle();
        if (!wallet || wallet.balance < wagerAmount) return res.status(400).json({ error: 'Insufficient balance' });

        const { data: creatorProfile } = await supabaseAdmin.from('profiles').select('team_name').eq('id', user.id).single();
        const creatorTeam = creatorProfile?.team_name || null;
        if (!creatorTeam) return res.status(400).json({ error: 'Please set your team name in profile before creating a match.' });

        const { data: existing } = await supabaseAdmin.from('friend_matches').select('id').eq('match_code', `VUM-${efootballCode.toUpperCase()}`).eq('status', 'pending').gte('expires_at', new Date().toISOString()).maybeSingle();
        if (existing) return res.status(400).json({ error: 'This eFootball code is already in use. Create a new Friends Match room in eFootball.' });

        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const platformFee = Math.floor(wagerAmount * 0.10);
        const winnerPrize = (wagerAmount * 2) - platformFee;

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').insert([{
            match_code: `VUM-${efootballCode.toUpperCase()}`,
            efootball_room_code: efootballCode.toUpperCase(),
            creator_id: user.id, creator_team: creatorTeam,
            wager_amount: wagerAmount, platform_fee: platformFee, winner_prize: winnerPrize,
            expires_at: expiresAt, status: 'pending'
        }]).select().single();

        if (matchErr) {
            console.error('Match creation DB error:', matchErr);
            return res.status(500).json({ error: 'Failed to create match in database', details: matchErr.message, code: matchErr.code });
        }

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', { p_user_id: user.id, p_amount: wagerAmount });
        if (deductErr) {
            await supabaseAdmin.from('friend_matches').delete().eq('id', match.id);
            return res.status(400).json({ error: 'Failed to deduct wager from wallet' });
        }

        res.status(201).json({
            matchId: match.id, efootballCode: efootballCode.toUpperCase(),
            wagerAmount, winnerPrize, platformFee, expiresAt,
            message: 'Match created! Share the eFootball room code with your friend to join.',
            guidelines: {
                step1: 'You created this match with eFootball room code: ' + efootballCode.toUpperCase(),
                step2: 'Share this code with your friend on eFootball',
                step3: 'You both play the match in eFootball',
                step4: 'After the match, upload the final result screenshot to settle the wager'
            }
        });
    } catch (err) {
        console.error('Create match error:', err);
        res.status(500).json({ error: 'Failed to create match', details: err.message });
    }
});

app.post('/friends/join-match', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { efootballCode } = req.body;
        if (!efootballCode) return res.status(400).json({ error: 'eFootball room code is required' });
        if (!validateEFootballCode(efootballCode)) return res.status(400).json({ error: 'Invalid eFootball code format. Codes should be 4-8 alphanumeric characters.' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('match_code', `VUM-${efootballCode.toUpperCase()}`).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Invalid eFootball code. No active match found.' });
        if (match.status !== 'pending') return res.status(400).json({ error: 'Match already started or completed' });
        if (new Date(match.expires_at) < new Date()) {
            await supabaseAdmin.from('friend_matches').update({ status: 'expired' }).eq('id', match.id);
            return res.status(400).json({ error: 'Match code has expired' });
        }
        if (match.creator_id === user.id) return res.status(400).json({ error: 'You cannot join your own match' });
        if (match.joiner_id) return res.status(400).json({ error: 'Match already has two players' });

        const { data: joinerProfile } = await supabaseAdmin.from('profiles').select('team_name').eq('id', user.id).single();
        const joinerTeam = joinerProfile?.team_name || null;
        if (!joinerTeam) return res.status(400).json({ error: 'Please set your team name in profile before joining a match.' });

        const { data: wallet } = await supabaseAdmin.from('wallets').select('balance').eq('user_id', user.id).maybeSingle();
        if (!wallet || wallet.balance < match.wager_amount) return res.status(400).json({ error: 'Insufficient balance' });

        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', { p_user_id: user.id, p_amount: match.wager_amount });
        if (deductErr) return res.status(400).json({ error: 'Failed to deduct wager from wallet' });

        const { data: updatedMatch, error: updateErr } = await supabaseAdmin.from('friend_matches').update({
            joiner_id: user.id, joiner_team: joinerTeam, status: 'active', started_at: new Date().toISOString()
        }).eq('id', match.id).select().single();

        if (updateErr) {
            await supabaseAdmin.rpc('credit_wallet', { p_user_id: user.id, p_amount: match.wager_amount });
            return res.status(500).json({ error: 'Failed to join match' });
        }

        res.status(200).json({ message: 'Successfully joined match!', matchId: updatedMatch.id, wagerAmount: match.wager_amount, winnerPrize: match.winner_prize, opponentId: match.creator_id });
    } catch (err) {
        console.error('Join match error:', err);
        res.status(500).json({ error: 'Failed to join match' });
    }
});

// ============================================================
// DEPRECATED: Old result submission endpoint
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

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (winnerId !== match.creator_id && winnerId !== match.joiner_id) return res.status(400).json({ error: 'Invalid winner ID' });
        if (match.reported_by_id === user.id) return res.status(400).json({ error: 'You have already reported this match' });

        let verificationResult = null;
        if (screenshotUrl) {
            if (!isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL' });
            const VerifierClass = await getVerifierClass();
            const verifier = new VerifierClass(supabaseAdmin, { teams: EFOOTBALL_TEAMS, extractTeamNames });
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
                const { data: sp } = await supabaseAdmin.from('profiles').select('username').eq('id', user.id).maybeSingle();
                selfUsername = sp?.username || null;
                verificationResult = await verifier.verifyScreenshot(buffer, {
                    userId: user.id, matchId, startedAt: match.started_at,
                    opponentUsername, uploaderUsername: selfUsername, matchCode: match.match_code
                });
                if (!verificationResult.isValid || verificationResult.fraudScore >= 50) {
                    await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Suspicious screenshot', verification_data: verificationResult }).eq('id', matchId);
                    return res.status(409).json({ error: 'Screenshot verification failed. Match marked for admin review.', verification: verificationResult });
                }
            } catch (fetchErr) { console.error('Screenshot verify error:', fetchErr.message); }
        }

        if (!match.reported_winner_id) {
            await supabaseAdmin.from('friend_matches').update({ reported_winner_id: winnerId, reported_by_id: user.id, screenshot_url: screenshotUrl, verification_data: verificationResult, reported_at: new Date().toISOString() }).eq('id', matchId);
            return res.status(200).json({ message: 'Result submitted. Waiting for opponent confirmation.', requiresConfirmation: true, verification: verificationResult });
        }

        if (match.reported_winner_id !== winnerId) {
            await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Reported winners do not match' }).eq('id', matchId);
            return res.status(409).json({ error: 'Results do not match. Match marked for admin review.', requiresAdminReview: true });
        }

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) { console.error('Payout error:', payoutErr); return res.status(500).json({ error: 'Failed to process payout' }); }

        await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString() }).eq('id', matchId);

        if (verificationResult?.checks?.duplicate?.details?.hash) {
            try { await supabaseAdmin.from('screenshot_hashes').insert([{ hash: verificationResult.checks.duplicate.details.hash, user_id: winnerId, match_id: matchId }]); }
            catch (err) { if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) console.error('Error storing hash:', err); }
        }
        if (verificationResult?.checks?.device?.details?.device) {
            await supabaseAdmin.from('user_screenshot_history').insert([{ user_id: winnerId, device: verificationResult.checks.device.details.device, match_id: matchId }]);
        }

        res.status(200).json({ message: 'Match completed! Winner has been paid.', winnerId, prizePaid: match.winner_prize, verification: verificationResult });
    } catch (err) {
        console.error('Submit result error:', err);
        res.status(500).json({ error: 'Failed to submit result' });
    }
});

// ============================================================
// NOTIFICATION HELPER — writes to match_notifications table
// which the frontend polls / subscribes to via Supabase Realtime
// ============================================================
async function sendMatchNotification(matchId, recipientId, type, payload = {}) {
    try {
        await supabaseAdmin.from('match_notifications').insert([{
            match_id:     matchId,
            recipient_id: recipientId,
            type,          // e.g. 'result_pending','match_settled','challenge_received','admin_approved','draw_detected'
            payload:       JSON.stringify(payload),
            read:          false,
            created_at:    new Date().toISOString()
        }]);
    } catch (e) {
        console.error(`sendMatchNotification error [${matchId}/${type}]:`, e.message);
    }
}

// ============================================================
// OCR AUTO-SETTLE  ← RE-VERIFIES SERVER-SIDE; NEVER TRUSTS CLIENT SCORES
// ============================================================
app.post('/friends/submit-ocr-result', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl } = req.body;
        // NOTE: ocrResult / verificationResult from the client body are intentionally IGNORED.
        // All verification is performed server-side from the stored screenshot URL.
        if (!matchId || !screenshotUrl) return res.status(400).json({ error: 'matchId and screenshotUrl are required' });
        if (!isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (!match.creator_id || !match.joiner_id) return res.status(400).json({ error: 'Match does not have two players yet' });

        // ── SERVER-SIDE RE-VERIFICATION ──────────────────────────────────────────
        // Download the already-stored screenshot and run Gemini + fraud checks fresh.
        // The client has NO ability to influence scores, confidence, or teamMatch.
        console.log(`🔒 [submit-ocr-result] Server-side re-verification for match ${matchId}`);
        let imageBuffer;
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 20000);
            const imgRes = await fetch(screenshotUrl, { signal: controller.signal });
            clearTimeout(timeout);
            if (!imgRes.ok) throw new Error(`Failed to fetch screenshot: ${imgRes.status}`);
            imageBuffer = Buffer.from(await imgRes.arrayBuffer());
        } catch (fetchErr) {
            console.error('submit-ocr-result fetch error:', fetchErr.message);
            return res.status(502).json({ error: 'Could not retrieve screenshot for verification. Try again.' });
        }

        const VerifierClass = await getVerifierClass();
        const verifier = new VerifierClass(supabaseAdmin, { teams: EFOOTBALL_TEAMS, extractTeamNames });

        let verificationResult;
        try {
            verificationResult = await Promise.race([
                verifier.verifyScreenshot(imageBuffer, {
                    userId:     user.id,
                    matchId,
                    startedAt:  match.started_at,
                    matchCode:  match.match_code,
                    creatorTeam: match.creator_team,
                    joinerTeam:  match.joiner_team,
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error('OCR timeout')), 120000))
            ]);
        } catch (verifyErr) {
            console.error('submit-ocr-result verify error:', verifyErr.message);
            await supabaseAdmin.from('friend_matches').update({ status: 'pending_review', screenshot_url: screenshotUrl }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'admin_review_needed', { reason: 'ocr_timeout' });
            await sendMatchNotification(matchId, match.joiner_id, 'admin_review_needed', { reason: 'ocr_timeout' });
            return res.status(422).json({ adminReview: true, error: 'AI verification timed out — match sent to admin for manual review. Do not resubmit.' });
        }

        const confidence = verificationResult.confidence ?? 0;
        const fraudScore = verificationResult.fraudScore ?? 999;
        const score1     = verificationResult.extractedScores?.score1;
        const score2     = verificationResult.extractedScores?.score2;
        const winner     = verificationResult.winner; // computed entirely server-side by determineWinner()

        console.log(`🔒 [submit-ocr-result] Server result: score=${score1}-${score2} conf=${confidence}% fraud=${fraudScore} winner=${winner?.winner}`);

        if (fraudScore >= 80) {
            await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Fraud score too high on server re-verify', verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'dispute_opened', { reason: 'fraud_detected' });
            await sendMatchNotification(matchId, match.joiner_id, 'dispute_opened', { reason: 'fraud_detected' });
            return res.status(422).json({ error: 'Screenshot failed fraud checks. Match sent for admin review.', fraudScore, warnings: verificationResult.warnings });
        }

        if (confidence < 50 || score1 == null || score2 == null) {
            // Low confidence — ask Gemini to retry with a score-focused prompt before giving up
            console.log(`🤖 [arbitrate] Low confidence (${confidence}%) — retrying with Gemini score focus...`);
            const retryResult = await geminiArbitrate('low_score', { imageBuffer });
            if (retryResult.resolved) {
                // Gemini got a clearer read on retry — continue with new score
                console.log(`✅ [arbitrate] Retry succeeded: ${retryResult.score1}-${retryResult.score2} conf=${retryResult.confidence}%`);
                // Re-run determineWinner with the new score data
                const { determineWinner: dw } = require('./screenshot-verifier');
                // fallback: use original verificationResult.winner if already set, else route to team_side arbitration
                const retryWinner = verificationResult.winner?.winner ? verificationResult.winner
                    : { winner: null, reason: 'team_side_unknown' };
                // Override score on verificationResult and proceed
                verificationResult.extractedScores = { score1: retryResult.score1, score2: retryResult.score2 };
                verificationResult.confidence = retryResult.confidence;
                // fall through to winner logic below with updated values
                Object.assign(winner, retryWinner);
                Object.assign(verificationResult.winner, retryWinner);
            } else {
                console.log(`🚫 [arbitrate] Retry also failed (${retryResult.reason}) — routing to admin`);
                await supabaseAdmin.from('friend_matches').update({ status: 'pending_review', screenshot_url: screenshotUrl, verification_data: verificationResult }).eq('id', matchId);
                await sendMatchNotification(matchId, match.creator_id, 'admin_review_needed', { reason: 'low_confidence', confidence });
                await sendMatchNotification(matchId, match.joiner_id, 'admin_review_needed', { reason: 'low_confidence', confidence });
                return res.status(422).json({ adminReview: true, error: `Could not read score clearly — match sent to admin for review.` });
            }
        }

        // winner.winner is: 'creator' | 'joiner' | 'draw' | null (team_side_unknown)
        if (!winner || winner.winner === null) {
            // Team side unknown — ask Gemini to look at both team names and decide
            console.log(`🤖 [arbitrate] Team side unknown — asking Gemini to identify sides...`);
            const arbResult = await geminiArbitrate('team_side', {
                imageBuffer,
                score1: verificationResult.extractedScores?.score1,
                score2: verificationResult.extractedScores?.score2,
                creatorTeam: match.creator_team,
                joinerTeam:  match.joiner_team,
            });
            if (arbResult.resolved) {
                console.log(`✅ [arbitrate] Team side resolved: winner=${arbResult.winner} conf=${arbResult.confidence}% — ${arbResult.reasoning}`);
                winner = arbResult;
                // Store arbitration reasoning in verification data
                verificationResult.arbitration = { type: 'team_side', ...arbResult };
            } else {
                console.log(`🚫 [arbitrate] Team side unresolved (${arbResult.reason}) — routing to admin`);
                await supabaseAdmin.from('friend_matches').update({ status: 'pending_review', screenshot_url: screenshotUrl, verification_data: verificationResult }).eq('id', matchId);
                await sendMatchNotification(matchId, match.creator_id, 'admin_review_needed', { reason: 'team_side_unknown' });
                await sendMatchNotification(matchId, match.joiner_id, 'admin_review_needed', { reason: 'team_side_unknown' });
                return res.status(422).json({ adminReview: true, error: 'Could not identify team sides — match sent for admin review.' });
            }
        }

        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;

        if (winner.winner === 'draw') {
            const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            await supabaseAdmin.from('friend_matches').update({ status: 'penalty_shootout', penalty_deadline: penaltyDeadline, draw_screenshot_url: screenshotUrl, draw_score: `${score1}-${score2}`, draw_detected_at: new Date().toISOString(), verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'draw_detected', { score: `${score1}-${score2}`, penaltyDeadline });
            await sendMatchNotification(matchId, match.joiner_id, 'draw_detected', { score: `${score1}-${score2}`, penaltyDeadline });
            return res.status(200).json({ draw: true, penaltyShootout: true, penaltyDeadline, message: 'Match ended in a draw! Go back to eFootball, create a new Friends Match room with your opponent and play a Penalty Shootout. Either player can then upload the result screenshot here.', instructions: ['1. One player creates a new Friends Match room in eFootball', '2. Share the room code with your opponent', '3. Play the Penalty Shootout match', '4. Either player uploads the result screenshot to settle the wager'] });
        }

        // Map 'creator'/'joiner' label to actual user IDs
        const winnerId = winner.winner === 'creator' ? match.creator_id : match.joiner_id;
        const loserId  = winner.winner === 'creator' ? match.joiner_id  : match.creator_id;

        if (confidence >= 85 && fraudScore < 30) {
            // High confidence + clean screenshot → auto-settle immediately
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
            if (payoutErr) throw payoutErr;
            await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_confidence: confidence, settlement_method: 'auto', screenshot_url: screenshotUrl, verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, winnerId, 'match_settled', { youWon: true, score: `${winner.creatorScore}-${winner.joinerScore}`, prize: match.winner_prize, method: 'auto' });
            await sendMatchNotification(matchId, loserId,  'match_settled', { youWon: false, score: `${winner.creatorScore}-${winner.joinerScore}`, method: 'auto' });
            console.log(`✅ Auto-settled match ${matchId} – winner ${winnerId}, prize ${match.winner_prize}`);
            return res.status(200).json({ message: 'Match auto-settled! Winner paid.', winnerId, prizePaid: match.winner_prize, confidence, youWon: winnerId === user.id });
        }

        // Medium confidence → open challenge window; opponent can dispute within 2h
        const challengeDeadline = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
        await supabaseAdmin.from('friend_matches').update({ challenge_deadline: challengeDeadline, challenge_uploaded: false, first_upload_winner_id: winnerId, first_upload_confidence: confidence, first_upload_screenshot_url: screenshotUrl, settlement_confidence: confidence, screenshot_url: screenshotUrl, verification_data: verificationResult }).eq('id', matchId);
        await sendMatchNotification(matchId, winnerId, 'result_pending', { youWon: true, score: `${winner.creatorScore}-${winner.joinerScore}`, challengeDeadline, confidence });
        await sendMatchNotification(matchId, loserId,  'challenge_received', { youLost: true, score: `${winner.creatorScore}-${winner.joinerScore}`, challengeDeadline, message: 'Your opponent uploaded a result. You have 2 hours to challenge it.' });
        return res.status(200).json({ message: 'Result recorded. Your opponent has 2 hours to challenge.', challengeDeadline, confidence });
    } catch (err) {
        console.error('OCR auto-settle error:', err);
        return sendGenericError(res, 500, 'Failed to process result', err);
    }
});

// ============================================================
// PENALTY SHOOTOUT RESULT
// ============================================================
app.post('/friends/submit-penalty-result', screenshotUploadLimiter, async (req, res) => {
    const multer = getMulter();
    const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/webp']; if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Only JPEG, PNG, and WebP images are allowed')); } }).single('screenshot');
    await new Promise((resolve, reject) => { upload(req, res, (err) => { if (err) reject(err); else resolve(); }); }).catch((err) => { return res.status(400).json({ error: err.message || 'Invalid file upload' }); });
    if (res.headersSent) return;

    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });
        if (!req.file) return res.status(400).json({ error: 'No screenshot provided' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'penalty_shootout') return res.status(400).json({ error: 'This match is not awaiting penalties. Only drawn matches go to a penalty shootout.' });

        if (match.penalty_deadline && new Date() > new Date(match.penalty_deadline)) {
            await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Penalty shootout deadline passed — no result submitted' }).eq('id', matchId);
            return res.status(400).json({ error: 'Penalty shootout deadline has passed. Match sent for admin review.' });
        }

        const imageBuffer = req.file.buffer;
        const VerifierClass = await getVerifierClass();
        const verifier = new VerifierClass(supabaseAdmin, { teams: EFOOTBALL_TEAMS, extractTeamNames });

        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const [uploaderRes, opponentRes] = await Promise.all([
            supabaseAdmin.from('profiles').select('username').eq('id', user.id).maybeSingle(),
            supabaseAdmin.from('profiles').select('username').eq('id', opponentId).maybeSingle()
        ]);
        const uploaderUsername = uploaderRes.data?.username || null;
        const opponentUsername = opponentRes.data?.username || null;

        const [verificationResult, ocrResult] = await Promise.all([
            verifier.verifyScreenshot(imageBuffer, { userId: user.id, matchId, startedAt: match.draw_detected_at || match.started_at, opponentUsername, uploaderUsername, matchCode: match.match_code, creatorTeam: match.creator_team, joinerTeam: match.joiner_team, isPenaltyShootout: true }),
            verifier.extractScoreWithConfidence(imageBuffer)
        ]);

        const confidence = verificationResult?.confidence ?? 0;
        const fraudScore = verificationResult?.fraudScore ?? 999;
        const score1 = ocrResult?.score1;
        const score2 = ocrResult?.score2;

        if (fraudScore >= 50) {
            await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Suspicious penalty screenshot — fraud score: ' + fraudScore, verification_data: verificationResult }).eq('id', matchId);
            return res.status(422).json({ error: 'Screenshot flagged as suspicious. Match sent for admin review.', fraudScore, warnings: verificationResult?.warnings });
        }
        if (confidence < 50) return res.status(422).json({ error: `Screenshot confidence too low (${confidence}%) — upload a clearer penalty result screen.`, confidence });
        if (score1 === null || score1 === undefined || score2 === null || score2 === undefined) return res.status(422).json({ error: 'Could not read the score. Make sure you upload the final penalty result screen from eFootball.' });
        if (score1 === score2) return res.status(422).json({ error: 'Penalty shootouts cannot end in a draw. Please upload the correct final penalty result screenshot.', detectedScore: score1 + '-' + score2, hint: 'Make sure this is the penalty shootout result screen, not the regular match result.' });

        const teamMatch = verificationResult?.teamMatch;
        let winnerId = null;
        if (teamMatch && teamMatch.bestMapping !== 'ambiguous') {
            const isCreatorHome = (teamMatch.bestHome === match.creator_team);
            const homeId = isCreatorHome ? match.creator_id : match.joiner_id;
            const awayId = isCreatorHome ? match.joiner_id : match.creator_id;
            winnerId = score1 > score2 ? homeId : awayId;
        } else {
            return res.status(422).json({ error: 'Could not reliably identify which team belongs to which player. Match sent for admin review.', hint: 'Make sure both team names are visible in the screenshot.' });
        }

        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = 'match-screenshots/' + matchId + '/penalty-' + user.id + '-' + Date.now() + '.' + ext;
        const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, imageBuffer, { contentType: req.file.mimetype, upsert: false });
        if (uploadErr) throw uploadErr;
        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        if (confidence >= 85) {
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
            if (payoutErr) throw payoutErr;
            await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'penalty_shootout', settlement_confidence: confidence, penalty_screenshot_url: publicUrl, penalty_score: score1 + '-' + score2, verification_data: verificationResult }).eq('id', matchId);
            console.log('\u26bd Penalty auto-settled: match=' + matchId + ', winner=' + winnerId + ', prize=' + match.winner_prize);
            return res.status(200).json({ message: 'Penalty shootout settled! Winner has been paid.', winnerId, prizePaid: match.winner_prize, penaltyScore: score1 + '-' + score2, confidence, youWon: winnerId === user.id, settlementMethod: 'penalty_shootout' });
        }

        const challengeDeadline = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
        await supabaseAdmin.from('friend_matches').update({ challenge_deadline: challengeDeadline, challenge_uploaded: false, first_upload_winner_id: winnerId, first_upload_confidence: confidence, first_upload_screenshot_url: publicUrl, penalty_screenshot_url: publicUrl, penalty_score: score1 + '-' + score2, settlement_confidence: confidence, verification_data: verificationResult }).eq('id', matchId);
        return res.status(200).json({ message: 'Penalty result recorded. Your opponent has 2 hours to challenge.', challengeDeadline, confidence, penaltyScore: score1 + '-' + score2 });
    } catch (err) {
        console.error('Penalty result error:', err);
        return sendGenericError(res, 500, 'Failed to process penalty result', err);
    }
});

// ============================================================
// OPPONENT CHALLENGE
// ============================================================
app.post('/friends/challenge/:matchId', screenshotUploadLimiter, async (req, res) => {
    const multer = getMulter();
    const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/webp']; if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Only JPEG, PNG, and WebP images are allowed')); } }).single('screenshot');
    await new Promise((resolve, reject) => { upload(req, res, (err) => { if (err) reject(err); else resolve(); }); }).catch((err) => { return res.status(400).json({ error: err.message || 'Invalid file upload' }); });
    if (res.headersSent) return;

    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.params;
        if (!req.file) return res.status(400).json({ error: 'No screenshot provided' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'Not your match' });
        if (match.status !== 'active' || !match.challenge_deadline) return res.status(400).json({ error: 'No active challenge window for this match' });
        if (new Date() > new Date(match.challenge_deadline)) return res.status(400).json({ error: 'Challenge window expired' });
        if (match.challenge_uploaded) return res.status(400).json({ error: 'Opponent already uploaded a challenge screenshot' });

        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = `match-challenges/${matchId}/${user.id}-${Date.now()}.${ext}`;
        const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, req.file.buffer, { contentType: req.file.mimetype });
        if (uploadErr) throw uploadErr;
        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        await supabaseAdmin.from('friend_matches').update({ challenge_uploaded: true, challenge_screenshot_url: publicUrl, challenge_uploaded_at: new Date().toISOString(), status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Opponent challenged result' }).eq('id', matchId);
        const challengeOpponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        await sendMatchNotification(matchId, challengeOpponentId, 'challenge_received', { message: 'Your opponent has disputed the result. An admin will review both screenshots.' });
        await sendMatchNotification(matchId, user.id, 'challenge_received', { message: 'Your challenge has been submitted. An admin will review the screenshots.' });
        res.json({ message: 'Challenge screenshot uploaded. Match sent for admin review.' });
    } catch (err) {
        console.error('Challenge upload error:', err);
        res.status(500).json({ error: 'Failed to process challenge' });
    }
});

// ============================================================
// MY MATCHES
// ============================================================
app.get('/friends/my-matches', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

        const { data: matches, error } = await supabaseAdmin.from('friend_matches').select('*').or(`creator_id.eq.${user.id},joiner_id.eq.${user.id}`).order('created_at', { ascending: false }).limit(50);
        if (error) { console.error('Fetch matches error:', error); return res.json([]); }

        const userIds = new Set();
        matches?.forEach(m => { if (m.creator_id) userIds.add(m.creator_id); if (m.joiner_id) userIds.add(m.joiner_id); });
        const userIdArray = Array.from(userIds);
        let profileMap = {};
        if (userIdArray.length > 0) {
            const { data: profiles } = await supabaseAdmin.from('profiles').select('id, username').in('id', userIdArray);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }

        const enrichedMatches = matches?.map(m => ({ ...m, creator: m.creator_id ? { username: profileMap[m.creator_id] || null } : null, joiner: m.joiner_id ? { username: profileMap[m.joiner_id] || null } : null })) || [];
        res.json(enrichedMatches);
    } catch (err) {
        console.error('Fetch matches error:', err);
        res.json([]);
    }
});

// ============================================================
// SCORE DECLARATION SYSTEM
// ============================================================
app.post('/friends/declare-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, myScore, opponentScore, screenshotUrl } = req.body;
        if (!matchId || myScore === undefined || opponentScore === undefined) return res.status(400).json({ error: 'matchId, myScore and opponentScore are required' });
        if (!Number.isInteger(myScore) || !Number.isInteger(opponentScore) || myScore < 0 || opponentScore < 0 || myScore > 20 || opponentScore > 20) return res.status(400).json({ error: 'Invalid score values' });
        if (screenshotUrl && !isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL format' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('id, status, creator_id, joiner_id, winner_prize, wager_amount, declared_score_by, draw_score').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });
        if (match.declared_score_by) return res.status(400).json({ error: 'Score already declared for this match. Waiting for opponent confirmation.' });

        const isCreator = match.creator_id === user.id;
        const creatorScore = isCreator ? myScore : opponentScore;
        const joinerScore  = isCreator ? opponentScore : myScore;
        const isDraw = creatorScore === joinerScore;
        const declaringWinnerId = myScore > opponentScore ? user.id : opponentScore > myScore ? (isCreator ? match.joiner_id : match.creator_id) : null;
        const opponentId = isCreator ? match.joiner_id : match.creator_id;
        const confirmDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();

        if (isDraw) {
            await supabaseAdmin.from('friend_matches').update({ declared_score_creator: creatorScore, declared_score_joiner: joinerScore, declared_score_by: user.id, declared_at: new Date().toISOString(), draw_score: `${creatorScore}-${joinerScore}`, draw_screenshot_url: screenshotUrl, draw_detected_at: new Date().toISOString(), status: 'penalty_shootout', penalty_deadline: penaltyDeadline }).eq('id', matchId);
            console.log(`⚽ Draw declared for match ${matchId}: ${creatorScore}-${joinerScore} → penalty shootout`);
            return res.status(200).json({ success: true, isDraw: true, draw: true, penaltyShootout: true, penaltyDeadline, creatorScore, joinerScore, message: "It's a draw! Go to eFootball, create a new Friends Match room and play a Penalty Shootout with your opponent, then come back and upload the result.", instructions: ['1. One player creates a new Friends Match room in eFootball', '2. Share the room code with your opponent', '3. Play the Penalty Shootout match', '4. Either player uploads the result screenshot here'] });
        }

        await supabaseAdmin.from('friend_matches').update({ declared_score_creator: creatorScore, declared_score_joiner: joinerScore, declared_score_by: user.id, declared_winner_id: declaringWinnerId, declared_at: new Date().toISOString(), declared_screenshot_url: screenshotUrl, score_confirm_deadline: confirmDeadline, status: 'awaiting_confirmation' }).eq('id', matchId);
        console.log(`📋 Score declared for match ${matchId}: ${creatorScore}-${joinerScore} by ${user.id} | auto-payout at ${confirmDeadline}`);
        res.status(200).json({ success: true, isDraw: false, creatorScore, joinerScore, confirmDeadline, opponentId, message: "Score declared! Your opponent has 30 minutes to confirm or dispute. If they don't respond, you win automatically." });
    } catch (err) {
        console.error('Declare score error:', err);
        res.status(500).json({ error: 'Failed to declare score' });
    }
});

app.post('/friends/confirm-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });
        if (screenshotUrl && !isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL format' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('id, status, creator_id, joiner_id, declared_score_by, declared_winner_id, winner_prize, score_confirm_deadline, declared_score_creator, declared_score_joiner').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'awaiting_confirmation') return res.status(400).json({ error: 'Match is not awaiting confirmation' });
        if (match.declared_score_by === user.id) return res.status(400).json({ error: 'You declared the score — you cannot confirm your own declaration' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (new Date() > new Date(match.score_confirm_deadline)) return res.status(400).json({ error: 'Confirmation window has expired' });

        const winnerId = match.declared_winner_id;
        if (!winnerId) return res.status(400).json({ error: 'No winner declared — cannot confirm' });

        // ── Both players agreed — auto-pay immediately, no admin needed ──
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;
        const loserId = winnerId === match.creator_id ? match.joiner_id : match.creator_id;
        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId, status: 'completed',
            settlement_method: 'mutual_confirmation', confirmer_id: user.id,
            confirmed_at: new Date().toISOString(), completed_at: new Date().toISOString(),
            confirmer_screenshot_url: screenshotUrl || null,
            settlement_confidence: 100,
        }).eq('id', matchId);
        await sendMatchNotification(matchId, winnerId, 'match_settled', { youWon: true,  prize: match.winner_prize, score: `${match.declared_score_creator}-${match.declared_score_joiner}`, method: 'mutual_confirmation' });
        await sendMatchNotification(matchId, loserId,  'match_settled', { youWon: false, score: `${match.declared_score_creator}-${match.declared_score_joiner}`, method: 'mutual_confirmation' });
        console.log(`✅ Mutual confirmation auto-settled match ${matchId} – winner ${winnerId}, prize ${match.winner_prize}`);
        res.status(200).json({
            success: true, winnerId, settled: true,
            youWon: winnerId === user.id,
            score: `${match.declared_score_creator}-${match.declared_score_joiner}`,
            message: winnerId === user.id
                ? `✅ Result confirmed! You've been paid ${match.winner_prize}.`
                : '✅ Result confirmed. Match settled.'
        });
    } catch (err) {
        console.error('Confirm score error:', err);
        res.status(500).json({ error: 'Failed to confirm score' });
    }
});

app.post('/friends/dispute-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl, myScore, opponentScore } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });
        if (myScore !== undefined || opponentScore !== undefined) {
            if (!Number.isInteger(myScore) || !Number.isInteger(opponentScore) || myScore < 0 || opponentScore < 0 || myScore > 20 || opponentScore > 20) return res.status(400).json({ error: 'Invalid score values — must be integers between 0 and 20' });
        }
        if (screenshotUrl && !isValidScreenshotUrl(screenshotUrl)) return res.status(400).json({ error: 'Invalid screenshot URL format' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('id, status, creator_id, joiner_id, declared_score_by, declared_score_creator, declared_score_joiner').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'awaiting_confirmation') return res.status(400).json({ error: 'Match is not awaiting confirmation' });
        if (match.declared_score_by === user.id) return res.status(400).json({ error: 'You cannot dispute your own declaration' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });

        const isCreator = match.creator_id === user.id;
        const disputerCreatorScore = isCreator ? myScore : opponentScore;
        const disputerJoinerScore  = isCreator ? opponentScore : myScore;

        await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Score disputed by opponent', disputer_id: user.id, disputer_screenshot_url: screenshotUrl || null, disputer_declared_creator: disputerCreatorScore ?? null, disputer_declared_joiner: disputerJoinerScore ?? null }).eq('id', matchId);
        console.log(`⚠️ Score disputed for match ${matchId} by ${user.id}`);
        res.status(200).json({ success: true, message: 'Dispute raised. An admin will review both screenshots and declared scores within 24 hours.' });
    } catch (err) {
        console.error('Dispute score error:', err);
        res.status(500).json({ error: 'Failed to raise dispute' });
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

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) { console.error('Match not found:', matchId, matchErr); return res.status(404).json({ error: 'Match not found' }); }
        if (match.creator_id !== user.id) return res.status(403).json({ error: 'Only match creator can cancel' });
        if (match.status === 'cancelled') return res.status(400).json({ error: 'Match already cancelled' });
        if (match.status === 'active') return res.status(400).json({ error: 'Cannot cancel - someone already joined this match' });
        if (match.status === 'completed') return res.status(400).json({ error: 'Cannot cancel completed match' });
        if (match.status === 'disputed') return res.status(400).json({ error: 'Cannot cancel disputed match - awaiting admin review' });
        if (match.status !== 'pending' && match.status !== 'expired') return res.status(400).json({ error: `Cannot cancel ${match.status} match` });

        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: user.id, p_amount: match.wager_amount });
        if (refundErr) { console.error('Refund error:', refundErr); return res.status(500).json({ error: 'Failed to refund wager' }); }

        await supabaseAdmin.from('friend_matches').update({ status: 'cancelled', cancelled_at: new Date().toISOString() }).eq('id', matchId);
        res.status(200).json({ message: 'Match cancelled and wager refunded', refundedAmount: match.wager_amount });
    } catch (err) {
        console.error('Cancel match error:', err);
        res.status(500).json({ error: 'Failed to cancel match' });
    }
});

app.post('/friends/forfeit', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active' && match.status !== 'penalty_shootout') return res.status(400).json({ error: 'Match is not active — cannot forfeit' });

        const winnerId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;

        await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'forfeit', forfeit_by: user.id }).eq('id', matchId);
        await supabaseAdmin.rpc('increment_forfeit_count', { p_user_id: user.id }).catch(() => {});
        console.log(`🏳️  Forfeit: match=${matchId}, forfeitedBy=${user.id}, winner=${winnerId}`);
        res.status(200).json({ message: 'Match forfeited. Opponent has been paid.', winnerId, prizePaid: match.winner_prize });
    } catch (err) {
        console.error('Forfeit error:', err);
        res.status(500).json({ error: 'Failed to process forfeit' });
    }
});

app.get('/friends/match-status/:matchId', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.params;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(matchId)) return res.status(400).json({ error: 'Invalid match ID format' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('id, match_code, status, creator_id, joiner_id, wager_amount, winner_prize, winner_id, expires_at, started_at, completed_at, challenge_deadline, penalty_deadline, draw_score, penalty_score, settlement_method, forfeit_by, efootball_room_code, declared_score_creator, declared_score_joiner, declared_score_by, declared_winner_id, score_confirm_deadline').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'Not authorized to view this match' });

        let joinerUsername = null;
        if (match.joiner_id) {
            const { data: profile } = await supabaseAdmin.from('profiles').select('username').eq('id', match.joiner_id).maybeSingle();
            joinerUsername = profile?.username;
        }

        let statusMessage = null;
        if (match.status === 'penalty_shootout') statusMessage = 'Match ended in a draw! Go to eFootball, play a Penalty Shootout match with your opponent, then upload the result here.';
        else if (match.status === 'disputed') statusMessage = 'Match is under admin review. Please wait.';
        else if (match.status === 'awaiting_confirmation') { const iDeclared = match.declared_score_by === user.id; statusMessage = iDeclared ? 'Score declared! Waiting for your opponent to confirm or dispute.' : 'Your opponent declared the score. Please confirm or dispute.'; }
        else if (match.status === 'completed' && match.settlement_method === 'forfeit') { const forfeitedByYou = match.forfeit_by === user.id; statusMessage = forfeitedByYou ? 'You forfeited this match.' : 'Your opponent forfeited. You won!'; }
        else if (match.status === 'pending_review') {
            const youAreWinner = match.winner_id === user.id;
            statusMessage = youAreWinner
                ? '⏳ Your win is confirmed and pending admin approval. Payout will be credited once approved.'
                : '⏳ Match result is confirmed and pending admin review before settlement.';
        }

        const iDeclared = match.declared_score_by === user.id;
        const isCreator = match.creator_id === user.id;
        const myDeclaredScore = isCreator ? match.declared_score_creator : match.declared_score_joiner;
        const opponentDeclaredScore = isCreator ? match.declared_score_joiner : match.declared_score_creator;

        res.json({ matchId: match.id, matchCode: match.match_code, status: match.status, statusMessage, joinerUsername, wagerAmount: match.wager_amount, winnerPrize: match.winner_prize, winnerId: match.winner_id, youWon: match.winner_id === user.id, expiresAt: match.expires_at, startedAt: match.started_at, challengeDeadline: match.challenge_deadline, penaltyDeadline: match.penalty_deadline || null, drawScore: match.draw_score || null, penaltyScore: match.penalty_score || null, settlementMethod: match.settlement_method || null, awaitingConfirmation: match.status === 'awaiting_confirmation', iDeclared, myDeclaredScore: myDeclaredScore ?? null, opponentDeclaredScore: opponentDeclaredScore ?? null, declaredWinnerId: match.declared_winner_id || null, youWonDeclaration: match.declared_winner_id === user.id, confirmDeadline: match.score_confirm_deadline || null, efootballRoomCode: match.efootball_room_code || null });
    } catch (err) {
        console.error('Match status error:', err);
        res.status(500).json({ error: 'Failed to get match status' });
    }
});

// ============================================================
// AUTO-RESOLVE ABANDONED MATCHES
// ============================================================
async function autoResolveAbandonedMatches() {
    try {
        console.log('🔍 Checking for abandoned/expired matches...');
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
        const now = new Date().toISOString();

        const { data: abandonedMatches, error } = await supabaseAdmin.from('friend_matches').select('id, match_code').eq('status', 'active').not('reported_by_id', 'is', null).lt('reported_at', twoHoursAgo);
        if (error) console.error('Error fetching abandoned matches:', error);
        else if (abandonedMatches && abandonedMatches.length > 0) {
            console.log(`⚠️  Found ${abandonedMatches.length} abandoned matches`);
            for (const match of abandonedMatches) {
                await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: now, dispute_reason: 'Only one player reported within time limit' }).eq('id', match.id);
            }
        }

        // ── GHOST FORFEIT: one player uploaded, opponent ignored the deadline ──────
        // If creator_screenshot_url is set but joiner_screenshot_url is not (or vice versa)
        // AND the upload deadline has passed → award the win to whoever uploaded.
        const { data: waitingMatches, error: waitErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, creator_id, joiner_id, winner_prize, creator_screenshot_url, joiner_screenshot_url, creator_ocr_data, joiner_ocr_data, opponent_upload_deadline, wager_amount')
            .eq('status', 'active')
            .not('opponent_upload_deadline', 'is', null)
            .lt('opponent_upload_deadline', now);

        if (waitErr) console.error('Error fetching waiting-for-opponent matches:', waitErr);
        else if (waitingMatches && waitingMatches.length > 0) {
            console.log(`👻 ${waitingMatches.length} match(es) where opponent ghosted upload deadline`);
            for (const match of waitingMatches) {
                const creatorUploaded = !!match.creator_screenshot_url;
                const joinerUploaded  = !!match.joiner_screenshot_url;

                if (creatorUploaded && !joinerUploaded) {
                    // Creator uploaded, joiner ghosted → creator wins by forfeit
                    let ocrData = null;
                    try { ocrData = JSON.parse(match.creator_ocr_data); } catch {}
                    const winnerId = match.creator_id;
                    const loserId  = match.joiner_id;
                    const { error: payErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
                    if (payErr) { console.error(`Ghost forfeit payout error match ${match.match_code}:`, payErr); continue; }
                    await supabaseAdmin.from('friend_matches').update({
                        winner_id: winnerId, status: 'completed', completed_at: now,
                        settlement_method: 'opponent_no_upload', settlement_confidence: ocrData?.confidence ?? 70,
                    }).eq('id', match.id);
                    await sendMatchNotification(match.id, winnerId, 'match_settled', { youWon: true,  prize: match.winner_prize, method: 'opponent_no_upload', message: 'Your opponent did not upload their screenshot. You win by forfeit!' });
                    await sendMatchNotification(match.id, loserId,  'match_settled', { youWon: false, method: 'opponent_no_upload', message: 'You did not upload a screenshot within the deadline. The match was awarded to your opponent.' });
                    console.log(`👻 Ghost forfeit match ${match.match_code} → auto-paid winner ${winnerId} (joiner ghosted)`);

                } else if (joinerUploaded && !creatorUploaded) {
                    // Joiner uploaded, creator ghosted → joiner wins by forfeit
                    let ocrData = null;
                    try { ocrData = JSON.parse(match.joiner_ocr_data); } catch {}
                    const winnerId = match.joiner_id;
                    const loserId  = match.creator_id;
                    const { error: payErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
                    if (payErr) { console.error(`Ghost forfeit payout error match ${match.match_code}:`, payErr); continue; }
                    await supabaseAdmin.from('friend_matches').update({
                        winner_id: winnerId, status: 'completed', completed_at: now,
                        settlement_method: 'opponent_no_upload', settlement_confidence: ocrData?.confidence ?? 70,
                    }).eq('id', match.id);
                    await sendMatchNotification(match.id, winnerId, 'match_settled', { youWon: true,  prize: match.winner_prize, method: 'opponent_no_upload', message: 'Your opponent did not upload their screenshot. You win by forfeit!' });
                    await sendMatchNotification(match.id, loserId,  'match_settled', { youWon: false, method: 'opponent_no_upload', message: 'You did not upload a screenshot within the deadline. The match was awarded to your opponent.' });
                    console.log(`👻 Ghost forfeit match ${match.match_code} → auto-paid winner ${winnerId} (creator ghosted)`);

                } else if (!creatorUploaded && !joinerUploaded) {
                    // Neither uploaded — refund both and cancel
                    const [r1, r2] = await Promise.all([
                        supabaseAdmin.rpc('credit_wallet', { p_user_id: match.creator_id, p_amount: match.wager_amount }),
                        supabaseAdmin.rpc('credit_wallet', { p_user_id: match.joiner_id,  p_amount: match.wager_amount }),
                    ]);
                    if (r1.error) console.error('Refund error creator:', r1.error);
                    if (r2.error) console.error('Refund error joiner:',  r2.error);
                    await supabaseAdmin.from('friend_matches').update({ status: 'cancelled', dispute_reason: 'Neither player uploaded a screenshot — wagers refunded' }).eq('id', match.id);
                    await sendMatchNotification(match.id, match.creator_id, 'match_cancelled', { message: 'Match cancelled — neither player uploaded a screenshot. Your wager has been refunded.' });
                    await sendMatchNotification(match.id, match.joiner_id,  'match_cancelled', { message: 'Match cancelled — neither player uploaded a screenshot. Your wager has been refunded.' });
                    console.log(`🚫 Both ghosted match ${match.match_code} → cancelled, both refunded`);
                }
            }
        }

        const { data: expiredDeclarations, error: declErr } = await supabaseAdmin.from('friend_matches').select('id, match_code, declared_winner_id, winner_prize, creator_id, joiner_id, declared_score_creator, declared_score_joiner').eq('status', 'awaiting_confirmation').lt('score_confirm_deadline', now);
        if (declErr) console.error('Error fetching expired declarations:', declErr);
        else if (expiredDeclarations && expiredDeclarations.length > 0) {
            console.log(`💰 Auto-paying ${expiredDeclarations.length} unconfirmed declarations`);
            for (const match of expiredDeclarations) {
                if (!match.declared_winner_id) {
                    await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: now, dispute_reason: 'Confirmation deadline expired — no winner declared' }).eq('id', match.id);
                    continue;
                }
                try {
                    // Opponent didn't dispute within the window — auto-pay the declarer's winner
                    const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: match.declared_winner_id, p_amount: match.winner_prize });
                    if (payoutErr) throw payoutErr;
                    const loserId = match.declared_winner_id === match.creator_id ? match.joiner_id : match.creator_id;
                    await supabaseAdmin.from('friend_matches').update({
                        winner_id: match.declared_winner_id, status: 'completed',
                        completed_at: now, settlement_method: 'auto_declaration', settlement_confidence: 80,
                    }).eq('id', match.id);
                    await sendMatchNotification(match.id, match.declared_winner_id, 'match_settled', { youWon: true,  prize: match.winner_prize, score: `${match.declared_score_creator}-${match.declared_score_joiner}`, method: 'auto_declaration' });
                    await sendMatchNotification(match.id, loserId,  'match_settled', { youWon: false, score: `${match.declared_score_creator}-${match.declared_score_joiner}`, method: 'auto_declaration' });
                    console.log(`✅ Auto-declaration settled match ${match.match_code} → paid winner ${match.declared_winner_id}`);
                } catch (payErr) {
                    console.error(`Payout failed for match ${match.match_code}:`, payErr);
                    await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: now, dispute_reason: 'Auto-payout failed after confirmation timeout' }).eq('id', match.id);
                }
            }
        } else {
            console.log('✅ No expired declarations');
        }

        const { data: expiredPenalties, error: penErr } = await supabaseAdmin.from('friend_matches').select('id, match_code').eq('status', 'penalty_shootout').lt('penalty_deadline', now);
        if (penErr) console.error('Error fetching expired penalty matches:', penErr);
        else if (expiredPenalties && expiredPenalties.length > 0) {
            for (const match of expiredPenalties) {
                await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: now, dispute_reason: 'Penalty shootout deadline passed — no result submitted' }).eq('id', match.id);
            }
        }
    } catch (err) { console.error('Auto-resolve error:', err); }
}

setInterval(autoResolveAbandonedMatches, 2 * 60 * 1000);
setTimeout(autoResolveAbandonedMatches, 10000);

// ============================================================
// AUTO-RESOLVE CHALLENGE WINDOWS
// ============================================================
async function resolveChallengeWindows() {
    try {
        const now = new Date().toISOString();
        const { data: matches, error } = await supabaseAdmin.from('friend_matches').select('*').in('status', ['active', 'awaiting_confirmation']).not('challenge_deadline', 'is', null).lt('challenge_deadline', now).eq('challenge_uploaded', false);
        if (error) throw error;
        if (!matches || matches.length === 0) return;
        console.log(`⏰ Resolving ${matches.length} expired challenge windows`);
        for (const match of matches) {
            if (match.first_upload_winner_id) {
                // Nobody challenged within the window — pay out automatically
                const { error: payErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: match.first_upload_winner_id, p_amount: match.winner_prize });
                if (payErr) { console.error(`Challenge timeout payout error match ${match.id}:`, payErr); continue; }
                const loserId = match.first_upload_winner_id === match.creator_id ? match.joiner_id : match.creator_id;
                await supabaseAdmin.from('friend_matches').update({
                    winner_id: match.first_upload_winner_id, status: 'completed',
                    completed_at: new Date().toISOString(),
                    settlement_method: 'challenge_timeout', settlement_confidence: match.first_upload_confidence,
                }).eq('id', match.id);
                await sendMatchNotification(match.id, match.first_upload_winner_id, 'match_settled', { youWon: true,  prize: match.winner_prize, method: 'challenge_timeout', message: 'Challenge window expired — you win!' });
                await sendMatchNotification(match.id, loserId, 'match_settled', { youWon: false, method: 'challenge_timeout', message: 'You did not challenge the result in time. Match settled.' });
                console.log(`✅ Challenge timeout match ${match.id} → auto-paid winner ${match.first_upload_winner_id}`);
            } else {
                await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: 'Challenge window expired but no winner recorded' }).eq('id', match.id);
            }
        }
    } catch (err) { console.error('Resolve challenge windows error:', err); }
}

setInterval(resolveChallengeWindows, 10 * 60 * 1000);
setTimeout(resolveChallengeWindows, 20000);

// ============================================================
// REMIND GHOSTING OPPONENTS — 30-min warning before forfeit
// ============================================================
async function remindGhostingOpponents() {
    try {
        const now = Date.now();
        // Find matches where the deadline is 20–40 minutes away (reminder window)
        const reminderFrom = new Date(now + 20 * 60 * 1000).toISOString();
        const reminderTo   = new Date(now + 40 * 60 * 1000).toISOString();

        const { data: matches } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, creator_id, joiner_id, creator_screenshot_url, joiner_screenshot_url, opponent_upload_deadline, reminder_sent')
            .eq('status', 'active')
            .not('opponent_upload_deadline', 'is', null)
            .gte('opponent_upload_deadline', reminderFrom)
            .lte('opponent_upload_deadline', reminderTo)
            .eq('reminder_sent', false);

        if (!matches || matches.length === 0) return;

        for (const match of matches) {
            const creatorUploaded = !!match.creator_screenshot_url;
            const joinerUploaded  = !!match.joiner_screenshot_url;
            const ghostId = creatorUploaded && !joinerUploaded ? match.joiner_id
                          : joinerUploaded  && !creatorUploaded ? match.creator_id
                          : null;

            if (ghostId) {
                const minutesLeft = Math.round((new Date(match.opponent_upload_deadline) - now) / 60000);
                await sendMatchNotification(match.id, ghostId, 'upload_reminder', {
                    urgency: 'critical',
                    message: `🚨 FINAL WARNING: You have ~${minutesLeft} minutes to upload your match screenshot. After that, your opponent wins automatically and you lose your wager.`,
                    deadline: match.opponent_upload_deadline,
                });
                await supabaseAdmin.from('friend_matches').update({ reminder_sent: true }).eq('id', match.id);
                console.log(`🔔 Sent ghost reminder for match ${match.match_code} → user ${ghostId} (~${minutesLeft}min left)`);
            }
        }
    } catch (err) { console.error('Ghost reminder error:', err); }
}

setInterval(remindGhostingOpponents, 5 * 60 * 1000);
setTimeout(remindGhostingOpponents, 30000);

// ============================================================
// WALLET DEPOSIT
// ============================================================
async function handleDeposit(req, res) {
    try {
        let { phone, amount, description } = req.body;
        if (!phone || !amount || isNaN(amount) || amount < 10) return res.status(400).json({ error: 'Invalid request. Min deposit KES 10.' });
        phone = normalizePhone(phone);
        if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });
        const jwt = req.headers['authorization']?.replace('Bearer ', '');
        const { data: { user } } = await supabase.auth.getUser(jwt);
        if (!user) return res.status(401).json({ error: 'Unauthorized.' });
        const mpesaRes = await fetch(`${process.env.MPESA_SERVER_URL}/pay`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone: phone.replace('+', ''), amount: String(Math.floor(Number(amount))), description: description || 'Vumbua Deposit' }) });
        if (!mpesaRes.ok) { const errData = await mpesaRes.json().catch(() => ({})); throw new Error(errData.error || 'STK request failed'); }
        const mpesaData = await mpesaRes.json();
        const checkoutRequestId = mpesaData.CheckoutRequestID || mpesaData.checkoutId || mpesaData.data?.CheckoutRequestID;
        const merchantRequestId = mpesaData.MerchantRequestID || mpesaData.data?.MerchantRequestID || 'N/A';
        if (!checkoutRequestId) throw new Error('STK push did not return a CheckoutRequestID');
        await supabaseAdmin.from('transactions').insert([{ checkout_request_id: checkoutRequestId, merchant_request_id: merchantRequestId, amount: Number(amount), phone, user_id: user.id, status: 'pending' }]);
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
        const { data } = await supabaseAdmin.from('transactions').select('status, mpesa_receipt').eq('checkout_request_id', checkoutId).maybeSingle();
        res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt || null });
    } catch (err) { console.error('Deposit status error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

// ============================================================
// M-PESA CALLBACK
// ============================================================
app.post('/mpesa/callback', async (req, res) => {
    try {
        if (process.env.MPESA_CALLBACK_SECRET) {
            const providedSecret = req.headers['x-mpesa-secret'];
            if (providedSecret !== process.env.MPESA_CALLBACK_SECRET) { console.warn('⚠️  M-Pesa callback received with invalid secret — rejecting.'); return res.status(401).json({ ResultCode: 1, ResultDesc: 'Unauthorized' }); }
        } else { console.warn('⚠️  MPESA_CALLBACK_SECRET not set — callback endpoint is unauthenticated!'); }

        const { Body } = req.body;
        const { stkCallback } = Body || {};
        const { CheckoutRequestID, ResultCode, CallbackMetadata } = stkCallback || {};

        if (ResultCode === 0 && CallbackMetadata) {
            const items = CallbackMetadata.Item || [];
            const amount = items.find(i => i.Name === 'Amount')?.Value || 0;
            const receipt = items.find(i => i.Name === 'MpesaReceiptNumber')?.Value || 'N/A';
            const { data: txn } = await supabaseAdmin.from('transactions').select('user_id, status').eq('checkout_request_id', CheckoutRequestID).maybeSingle();
            if (txn?.user_id) {
                if (txn.status === 'completed') { console.warn(`⚠️  Duplicate M-Pesa callback ignored for ${CheckoutRequestID} — already completed`); }
                else {
                    const { error: markErr } = await supabaseAdmin.from('transactions').update({ status: 'completed', mpesa_receipt: receipt, completed_at: new Date().toISOString() }).eq('checkout_request_id', CheckoutRequestID).eq('status', 'pending');
                    if (markErr) { console.error('Failed to mark transaction completed:', markErr); }
                    else {
                        const { error: creditErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: txn.user_id, p_amount: amount });
                        if (creditErr) { console.error('credit_wallet failed — rolling transaction back to pending:', creditErr); await supabaseAdmin.from('transactions').update({ status: 'pending' }).eq('checkout_request_id', CheckoutRequestID); }
                        else { console.log(`✅ M-Pesa deposit credited: user=${txn.user_id}, amount=${amount}, receipt=${receipt}`); }
                    }
                }
            } else { console.error('No user_id found for transaction:', CheckoutRequestID); }
        } else { await supabaseAdmin.from('transactions').update({ status: 'failed', completed_at: new Date().toISOString() }).eq('checkout_request_id', CheckoutRequestID); }
        res.status(200).json({ ResultCode: 0, ResultDesc: 'Success' });
    } catch (err) { console.error('Callback error:', err); res.status(500).json({ error: 'Callback failed' }); }
});

app.get('/mpesa/status', async (req, res) => {
    try {
        const { checkoutId } = req.query;
        const { data } = await supabaseAdmin.from('transactions').select('status, mpesa_receipt').eq('checkout_request_id', checkoutId).maybeSingle();
        res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt });
    } catch (err) { console.error('Mpesa status error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.get('/admin/withdrawals', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { status } = req.query;
        let query = supabaseAdmin.from('withdrawals').select('*').order('created_at', { ascending: true });
        if (status) query = query.eq('status', status);
        const { data, error } = await query;
        if (error) return res.status(500).json({ error: error.message });
        res.json(data || []);
    } catch (err) { console.error('Admin withdrawals error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.patch('/admin/withdrawals/:id/paid', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const withdrawal = await supabaseAdmin.from('withdrawals').select('status').eq('id', req.params.id).single();
        if (withdrawal.error || withdrawal.data.status !== 'pending') return res.status(400).json({ error: 'Invalid withdrawal state' });
        const { data, error } = await supabaseAdmin.from('withdrawals').update({ status: 'paid', mpesa_code: req.body.mpesaCode, paid_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        const { error: auditErr } = await supabaseAdmin.from('admin_audit_log').insert([{ action: 'withdrawal_paid', withdrawal_id: req.params.id, mpesa_code: req.body.mpesaCode || null, admin_ip: req.ip || req.headers['x-forwarded-for'], created_at: new Date().toISOString() }]);
        if (auditErr) console.error('⚠️  Audit log insert failed (withdrawal_paid):', auditErr.message);
        res.json({ message: 'Paid.', withdrawal: data });
    } catch (err) { console.error('Admin paid error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.patch('/admin/withdrawals/:id/reject', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data: wd, error: fetchErr } = await supabaseAdmin.from('withdrawals').select('*').eq('id', req.params.id).single();
        if (fetchErr || !wd || wd.status !== 'pending') return res.status(400).json({ error: 'Invalid state' });
        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: wd.user_id, p_amount: wd.amount });
        if (refundErr) return res.status(500).json({ error: refundErr.message });
        const { data, error } = await supabaseAdmin.from('withdrawals').update({ status: 'rejected', reject_reason: req.body.reason, rejected_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.json({ message: 'Rejected and refunded.', withdrawal: data });
    } catch (err) { console.error('Admin reject error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.get('/admin/tournaments', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data, error } = await supabaseAdmin.from('tournaments').select('*').order('created_at', { ascending: false });
        if (error) return res.status(500).json({ error: error.message });
        res.json(data || []);
    } catch (err) { console.error('Admin tournaments error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.get('/admin/tournaments/:id', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { data, error } = await supabaseAdmin.from('tournaments').select('*').eq('id', req.params.id).single();
        if (error) return res.status(404).json({ error: 'Tournament not found' });
        res.json(data);
    } catch (err) { console.error('Admin tournament detail error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/admin/tournaments', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        if (!name || !entry_fee || !start_time || !max_players) return res.status(400).json({ error: 'Missing required fields' });
        const { data, error } = await supabaseAdmin.from('tournaments').insert([{ name, entry_fee, start_time, max_players, room_code: room_code || null, status: status || 'open' }]).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.status(201).json(data);
    } catch (err) { console.error('Admin create tournament error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.patch('/admin/tournaments/:id', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        const { data, error } = await supabaseAdmin.from('tournaments').update({ name, entry_fee, start_time, max_players, room_code, status, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
        if (error) return res.status(500).json({ error: error.message });
        res.json(data);
    } catch (err) { console.error('Admin update tournament error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.delete('/admin/tournaments/:id', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { error } = await supabaseAdmin.from('tournaments').delete().eq('id', req.params.id);
        if (error) return res.status(500).json({ error: error.message });
        res.json({ message: 'Tournament deleted' });
    } catch (err) { console.error('Admin delete tournament error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.get('/admin/friend-matches', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { status } = req.query;
        let query = supabaseAdmin.from('friend_matches').select('*').order('created_at', { ascending: false });
        if (status && status !== 'all') query = query.eq('status', status);
        const { data, error } = await query;
        if (error) return res.status(500).json({ error: error.message });

        const userIds = new Set();
        data?.forEach(m => { if (m.creator_id) userIds.add(m.creator_id); if (m.joiner_id) userIds.add(m.joiner_id); if (m.winner_id) userIds.add(m.winner_id); });
        let profileMap = {};
        const userIdArray = Array.from(userIds);
        if (userIdArray.length > 0) {
            const { data: profiles } = await supabaseAdmin.from('profiles').select('id, username').in('id', userIdArray);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }
        const enriched = data?.map(m => ({ ...m, creator: m.creator_id ? { username: profileMap[m.creator_id] } : null, joiner: m.joiner_id ? { username: profileMap[m.joiner_id] } : null, winner: m.winner_id ? { username: profileMap[m.winner_id] } : null })) || [];
        res.json(enriched);
    } catch (err) { console.error('Admin friend matches error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.post('/admin/resolve-dispute/:matchId', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { winnerId, resolution } = req.body;
        const { matchId } = req.params;
        const isDraw = resolution === 'draw';
        if (!isDraw && !winnerId) return res.status(400).json({ error: 'Either winnerId or resolution="draw" is required' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'disputed' && match.status !== 'penalty_shootout' && match.status !== 'pending_review') return res.status(400).json({ error: 'Match is not in a resolvable state' });

        if (isDraw) {
            const [r1, r2] = await Promise.all([supabaseAdmin.rpc('credit_wallet', { p_user_id: match.creator_id, p_amount: match.wager_amount }), supabaseAdmin.rpc('credit_wallet', { p_user_id: match.joiner_id, p_amount: match.wager_amount })]);
            if (r1.error) throw r1.error;
            if (r2.error) throw r2.error;
            await supabaseAdmin.from('friend_matches').update({ status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'draw_refund', resolved_by_admin: true }).eq('id', matchId);
            return res.json({ message: 'Match declared a draw. Both players refunded their wager.', refundedAmount: match.wager_amount, resolution: 'draw' });
        }

        if (winnerId !== match.creator_id && winnerId !== match.joiner_id) return res.status(400).json({ error: 'Winner must be one of the players in this match' });
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;
        await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), resolved_by_admin: true }).eq('id', matchId);
        const { error: auditErr } = await supabaseAdmin.from('admin_audit_log').insert([{ action: 'resolve_dispute', match_id: matchId, winner_id: winnerId, admin_ip: req.ip || req.headers['x-forwarded-for'], created_at: new Date().toISOString() }]);
        if (auditErr) console.error('⚠️  Audit log insert failed (resolve_dispute):', auditErr.message);
        res.json({ message: 'Dispute resolved. Winner has been paid.', winnerId, prizePaid: match.winner_prize });
    } catch (err) { console.error('Resolve dispute error:', err); res.status(500).json({ error: 'Failed to resolve dispute' }); }
});

// ============================================================
// ADMIN: APPROVE PENDING RESULT (mutual confirmation)
// ============================================================
app.post('/admin/approve-result/:matchId', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { matchId } = req.params;

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'pending_review') return res.status(400).json({ error: `Match is not pending review — status is "${match.status}"` });
        if (!match.winner_id) return res.status(400).json({ error: 'No winner recorded on this match — cannot approve' });

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: match.winner_id, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;

        await supabaseAdmin.from('friend_matches').update({
            status: 'completed', completed_at: new Date().toISOString(), resolved_by_admin: true
        }).eq('id', matchId);

        // Delete stored screenshots immediately on approval — no need to keep them
        await deleteMatchScreenshots(matchId);

        await supabaseAdmin.from('admin_audit_log').insert([{
            action: 'approve_result', match_id: matchId, winner_id: match.winner_id,
            admin_ip: req.ip || req.headers['x-forwarded-for'], created_at: new Date().toISOString()
        }]).then(({ error: e }) => { if (e) console.error('Audit log error:', e.message); });

        // Notify both players
        const loserId = match.winner_id === match.creator_id ? match.joiner_id : match.creator_id;
        await sendMatchNotification(matchId, match.winner_id, 'match_settled', { youWon: true, prize: match.winner_prize, method: 'admin_approved' });
        await sendMatchNotification(matchId, loserId, 'match_settled', { youWon: false, method: 'admin_approved' });

        console.log(`✅ Admin approved result for match ${matchId} — winner ${match.winner_id}, prize KES ${match.winner_prize}`);
        res.json({ message: 'Result approved. Winner has been paid.', winnerId: match.winner_id, prizePaid: match.winner_prize });
    } catch (err) { console.error('Admin approve result error:', err); res.status(500).json({ error: 'Failed to approve result' }); }
});

app.post('/admin/force-winner/:matchId', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const { matchId } = req.params;
        const { winnerId, resolution, adminNotes } = req.body;
        const isDraw = resolution === 'draw';
        if (!isDraw && !winnerId) return res.status(400).json({ error: 'Provide either winnerId or resolution="draw"' });

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (['completed', 'cancelled', 'expired'].includes(match.status)) return res.status(400).json({ error: `Cannot override a match with status "${match.status}". Use this only on active or stuck matches.` });
        if (!isDraw && winnerId !== match.creator_id && winnerId !== match.joiner_id) return res.status(400).json({ error: 'Winner must be one of the two players in this match' });

        if (isDraw) {
            const [r1, r2] = await Promise.all([supabaseAdmin.rpc('credit_wallet', { p_user_id: match.creator_id, p_amount: match.wager_amount }), supabaseAdmin.rpc('credit_wallet', { p_user_id: match.joiner_id, p_amount: match.wager_amount })]);
            if (r1.error) throw r1.error;
            if (r2.error) throw r2.error;
            await supabaseAdmin.from('friend_matches').update({ status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'admin_override_draw', resolved_by_admin: true, admin_notes: adminNotes || null }).eq('id', matchId);
            await supabaseAdmin.from('admin_audit_log').insert([{ action: 'force_winner_draw', match_id: matchId, resolution: 'draw', prev_status: match.status, admin_notes: adminNotes || null, admin_ip: req.ip || req.headers['x-forwarded-for'], created_at: new Date().toISOString() }]).then(({ error: e }) => { if (e) console.error('Audit log error:', e.message); });
            await sendMatchNotification(matchId, match.creator_id, 'match_settled', { youWon: false, method: 'admin_draw', message: 'Admin declared the match a draw. Your wager has been refunded.' });
            await sendMatchNotification(matchId, match.joiner_id,  'match_settled', { youWon: false, method: 'admin_draw', message: 'Admin declared the match a draw. Your wager has been refunded.' });
            return res.json({ message: 'Draw declared. Both players refunded their wager.', resolution: 'draw', refundedAmount: match.wager_amount });
        }

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;
        await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'admin_override', resolved_by_admin: true, admin_notes: adminNotes || null }).eq('id', matchId);
        await supabaseAdmin.from('admin_audit_log').insert([{ action: 'force_winner', match_id: matchId, winner_id: winnerId, prev_status: match.status, admin_notes: adminNotes || null, admin_ip: req.ip || req.headers['x-forwarded-for'], created_at: new Date().toISOString() }]).then(({ error: e }) => { if (e) console.error('Audit log error:', e.message); });
        const forceloserId = winnerId === match.creator_id ? match.joiner_id : match.creator_id;
        await sendMatchNotification(matchId, winnerId,     'match_settled', { youWon: true, prize: match.winner_prize, method: 'admin_override', note: adminNotes || null });
        await sendMatchNotification(matchId, forceloserId, 'match_settled', { youWon: false, method: 'admin_override', note: adminNotes || null });
        res.json({ message: 'Winner forced. Prize credited to their wallet.', winnerId, prizePaid: match.winner_prize, prevStatus: match.status });
    } catch (err) { console.error('Force winner error:', err); res.status(500).json({ error: 'Failed to force winner' }); }
});

// ============================================================
// NOTIFICATIONS — GET unread + PATCH mark-read
// match_notifications table: id, match_id, recipient_id, type, payload, read, created_at
// ============================================================
app.get('/notifications', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data: notifs, error: notifErr } = await supabaseAdmin
            .from('match_notifications')
            .select('id, match_id, type, payload, read, created_at')
            .eq('recipient_id', user.id)
            .order('created_at', { ascending: false })
            .limit(50);

        if (notifErr) throw notifErr;

        res.json((notifs || []).map(n => ({
            ...n,
            payload: (() => { try { return JSON.parse(n.payload); } catch { return {}; } })()
        })));
    } catch (err) {
        console.error('GET /notifications error:', err);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

app.patch('/notifications/read', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { ids } = req.body; // optional array of notification IDs; omit to mark ALL read
        let query = supabaseAdmin.from('match_notifications').update({ read: true }).eq('recipient_id', user.id);
        if (Array.isArray(ids) && ids.length > 0) query = query.in('id', ids);
        const { error } = await query;
        if (error) throw error;
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /notifications/read error:', err);
        res.status(500).json({ error: 'Failed to update notifications' });
    }
});

// ============================================================
// ADMIN ANALYTICS
// ============================================================
app.get('/admin/analytics', adminLimiter, async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
        const now = new Date();
        const startOfToday     = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
        const startOfMonth     = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString();
        const endOfLastMonth   = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59).toISOString();
        const thirtyDaysAgo    = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        const sevenDaysAgo     = new Date(Date.now() -  7 * 24 * 60 * 60 * 1000).toISOString();

        const [allMatchesRes, mtdMatchesRes, lastMonthMatchesRes, allWithdrawalsRes, mtdWithdrawalsRes, pendingWithdrawalsRes, allUsersRes, newUsersTodayRes, newUsersMtdRes, walletTotalsRes, tournamentStatsRes, dailyVolumeRes] = await Promise.all([
            supabaseAdmin.from('friend_matches').select('wager_amount, winner_prize, platform_fee, completed_at, status, settlement_method, started_at, created_at').eq('status', 'completed'),
            supabaseAdmin.from('friend_matches').select('wager_amount, winner_prize, platform_fee, settlement_method').eq('status', 'completed').gte('completed_at', startOfMonth),
            supabaseAdmin.from('friend_matches').select('wager_amount, platform_fee').eq('status', 'completed').gte('completed_at', startOfLastMonth).lte('completed_at', endOfLastMonth),
            supabaseAdmin.from('withdrawals').select('amount, status, requested_at, processed_at, created_at'),
            supabaseAdmin.from('withdrawals').select('amount, status').gte('created_at', startOfMonth),
            supabaseAdmin.from('withdrawals').select('amount, id').eq('status', 'pending'),
            supabaseAdmin.from('profiles').select('id, created_at'),
            supabaseAdmin.from('profiles').select('id', { count: 'exact', head: true }).gte('created_at', startOfToday),
            supabaseAdmin.from('profiles').select('id', { count: 'exact', head: true }).gte('created_at', startOfMonth),
            supabaseAdmin.from('wallets').select('balance'),
            supabaseAdmin.from('tournaments').select('id, status, entry_fee, max_players'),
            supabaseAdmin.from('friend_matches').select('wager_amount, platform_fee, completed_at').eq('status', 'completed').gte('completed_at', thirtyDaysAgo).order('completed_at', { ascending: true }),
        ]);

        const allMatches = allMatchesRes.data || [];
        const completedMatches = allMatches.filter(m => m.status === 'completed');
        const allTimeVolume = completedMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const allTimeFees   = completedMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);
        const avgWager      = completedMatches.length > 0 ? completedMatches.reduce((s, m) => s + parseFloat(m.wager_amount), 0) / completedMatches.length : 0;
        const settlementBreakdown = completedMatches.reduce((acc, m) => { const method = m.settlement_method || 'manual'; acc[method] = (acc[method] || 0) + 1; return acc; }, {});

        const mtdMatches  = mtdMatchesRes.data || [];
        const mtdVolume   = mtdMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const mtdFees     = mtdMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);

        const lastMonthMatches = lastMonthMatchesRes.data || [];
        const lastMonthVolume  = lastMonthMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const lastMonthFees    = lastMonthMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);

        const volumeGrowth = lastMonthVolume > 0 ? (((mtdVolume - lastMonthVolume) / lastMonthVolume) * 100).toFixed(1) : null;
        const feesGrowth   = lastMonthFees   > 0 ? (((mtdFees   - lastMonthFees)   / lastMonthFees)   * 100).toFixed(1) : null;

        const allFriendMatchesForDisputeRes = await supabaseAdmin.from('friend_matches').select('status', { count: 'exact' }).in('status', ['disputed', 'completed', 'active', 'cancelled', 'expired', 'penalty_shootout']);
        const allFriendMatchesForDispute = allFriendMatchesForDisputeRes.data || [];
        const totalFinishedMatches = allFriendMatchesForDispute.length;
        const disputedCount = allFriendMatchesForDispute.filter(m => m.status === 'disputed').length;
        const disputeRate   = totalFinishedMatches > 0 ? ((disputedCount / totalFinishedMatches) * 100).toFixed(1) : 0;

        const allWithdrawals = allWithdrawalsRes.data || [];
        const completedWithdrawals = allWithdrawals.filter(w => ['paid', 'completed'].includes(w.status));
        const allTimeWithdrawalVolume = completedWithdrawals.reduce((s, w) => s + parseFloat(w.amount), 0);
        const mtdWithdrawals = mtdWithdrawalsRes.data || [];
        const mtdWithdrawalVolume = mtdWithdrawals.filter(w => ['paid', 'completed'].includes(w.status)).reduce((s, w) => s + parseFloat(w.amount), 0);
        const pendingWithdrawals = pendingWithdrawalsRes.data || [];
        const pendingWithdrawalCount  = pendingWithdrawals.length;
        const pendingWithdrawalVolume = pendingWithdrawals.reduce((s, w) => s + parseFloat(w.amount), 0);
        const processedWithdrawals = allWithdrawals.filter(w => ['paid', 'completed'].includes(w.status) && w.requested_at && w.processed_at);
        const avgProcessingHours = processedWithdrawals.length > 0 ? processedWithdrawals.reduce((s, w) => s + (new Date(w.processed_at) - new Date(w.requested_at)) / (1000 * 60 * 60), 0) / processedWithdrawals.length : null;

        const allUsers   = allUsersRes.data || [];
        const totalUsers = allUsers.length;
        const newToday   = newUsersTodayRes.count || 0;
        const newMtd     = newUsersMtdRes.count    || 0;

        const activeUserRes = await supabaseAdmin.from('friend_matches').select('creator_id, joiner_id').gte('created_at', sevenDaysAgo).not('joiner_id', 'is', null);
        const activeUserSet = new Set();
        (activeUserRes.data || []).forEach(m => { if (m.creator_id) activeUserSet.add(m.creator_id); if (m.joiner_id) activeUserSet.add(m.joiner_id); });
        const dau7 = activeUserSet.size;

        const wallets = walletTotalsRes.data || [];
        const totalFloat = wallets.reduce((s, w) => s + parseFloat(w.balance || 0), 0);
        const walletsWithBalance = wallets.filter(w => parseFloat(w.balance) > 0).length;

        const tournaments = tournamentStatsRes.data || [];
        const activeTournaments = tournaments.filter(t => ['open', 'live'].includes(t.status)).length;
        const tourEstimatedPool = tournaments.filter(t => t.status === 'live').reduce((s, t) => s + (parseFloat(t.entry_fee) * parseInt(t.max_players)), 0);

        const dailyVolumeData = dailyVolumeRes.data || [];
        const dailyMap = {};
        dailyVolumeData.forEach(m => { const day = m.completed_at.substring(0, 10); if (!dailyMap[day]) dailyMap[day] = { volume: 0, fees: 0, matches: 0 }; dailyMap[day].volume += parseFloat(m.wager_amount) * 2; dailyMap[day].fees += parseFloat(m.platform_fee || 0); dailyMap[day].matches += 1; });
        const dailyChart = [];
        for (let i = 29; i >= 0; i--) { const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000); const key = d.toISOString().substring(0, 10); dailyChart.push({ date: key, volume: Math.round((dailyMap[key]?.volume || 0) * 100) / 100, fees: Math.round((dailyMap[key]?.fees || 0) * 100) / 100, matches: dailyMap[key]?.matches || 0 }); }

        res.json({ generatedAt: now.toISOString(), revenue: { allTimeFees: Math.round(allTimeFees * 100) / 100, mtdFees: Math.round(mtdFees * 100) / 100, lastMonthFees: Math.round(lastMonthFees * 100) / 100, feesGrowthPct: feesGrowth, allTimeVolume: Math.round(allTimeVolume * 100) / 100, mtdVolume: Math.round(mtdVolume * 100) / 100, lastMonthVolume: Math.round(lastMonthVolume * 100) / 100, volumeGrowthPct: volumeGrowth }, matches: { totalCompleted: completedMatches.length, mtdCompleted: mtdMatches.length, avgWager: Math.round(avgWager * 100) / 100, disputeRate: parseFloat(disputeRate), disputedCount, totalMatches: totalFinishedMatches, settlementMethods: settlementBreakdown }, users: { total: totalUsers, newToday, newMtd, active7Days: dau7, walletsWithFunds: walletsWithBalance }, withdrawals: { allTimeVolume: Math.round(allTimeWithdrawalVolume * 100) / 100, mtdVolume: Math.round(mtdWithdrawalVolume * 100) / 100, pendingCount: pendingWithdrawalCount, pendingVolume: Math.round(pendingWithdrawalVolume * 100) / 100, avgProcessingHrs: avgProcessingHours !== null ? Math.round(avgProcessingHours * 10) / 10 : null }, platform: { totalFloat: Math.round(totalFloat * 100) / 100, activeTournaments, livePoolValue: Math.round(tourEstimatedPool * 100) / 100 }, dailyChart });
    } catch (err) { console.error('Analytics error:', err); res.status(500).json({ error: 'Failed to generate analytics' }); }
});

// ============================================================
// PUBLIC TOURNAMENT ROUTES
// ============================================================
app.get('/tournaments', async (req, res) => {
    try {
        const { data: tournaments, error } = await supabaseAdmin.from('tournaments').select(`*, bookings:bookings(count)`).in('status', ['open', 'live']).order('start_time', { ascending: true });
        if (error) throw error;
        const result = tournaments.map(t => ({ ...t, current_players: t.bookings?.[0]?.count || 0, prize_pool: t.entry_fee * t.max_players }));
        res.json(result);
    } catch (err) { console.error('Error fetching tournaments:', err); res.status(500).json({ error: 'Failed to fetch tournaments' }); }
});

// ============================================================
// SCREENSHOT UPLOAD + OCR VERIFICATION
// ============================================================
app.post('/screenshots/upload-and-verify', screenshotUploadLimiter, async (req, res) => {
    const multer = getMulter();
    const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/webp']; if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Only JPEG, PNG, and WebP images are allowed')); } }).single('screenshot');
    await new Promise((resolve, reject) => { upload(req, res, (err) => { if (err) reject(err); else resolve(); }); }).catch((err) => { return res.status(400).json({ error: err.message || 'Invalid file upload' }); });
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

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active') return res.status(400).json({ error: 'Match is not active' });

        // Prevent the same player uploading twice
        const isCreator = match.creator_id === user.id;
        const alreadyUploaded = isCreator ? !!match.creator_screenshot_url : !!match.joiner_screenshot_url;
        if (alreadyUploaded) return res.status(409).json({ error: 'You have already submitted a screenshot for this match.', instruction: 'Waiting for your opponent to upload their screenshot.' });

        const imageBuffer = req.file.buffer;
        const VerifierClass = await getVerifierClass();
        const verifier = new VerifierClass(supabaseAdmin, { teams: EFOOTBALL_TEAMS, extractTeamNames });

        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const [oppProfileResult, uploaderProfileResult] = await Promise.all([
            opponentId ? supabaseAdmin.from('profiles').select('username').eq('id', opponentId).maybeSingle() : Promise.resolve({ data: null }),
            supabaseAdmin.from('profiles').select('username').eq('id', user.id).maybeSingle()
        ]);
        const opponentUsername = oppProfileResult.data?.username || null;
        const uploaderUsername = uploaderProfileResult.data?.username || null;

        console.log('🔍 Running screenshot verification (OCR + fraud checks)...');
        const startVerification = Date.now();

        const verificationPromise = verifier.verifyScreenshot(imageBuffer, { userId: user.id, matchId, startedAt: match.started_at, opponentUsername, uploaderUsername, matchCode: match.match_code, creatorTeam: match.creator_team, joinerTeam: match.joiner_team });
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('OCR timeout')), 120000)); // 120s to allow Gemini 429 retries

        let verificationResult;
        try {
            verificationResult = await Promise.race([verificationPromise, timeoutPromise]);
        } catch (timeoutErr) {
            console.error('⏱️ Verification timeout:', timeoutErr.message);
            // Store the screenshot for admin review even on timeout
            let timeoutScreenshotUrl = null;
            try {
                const ext2 = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
                const sk2 = `match-screenshots/${matchId}/timeout-${user.id}-${Date.now()}.${ext2}`;
                const { error: upErr2 } = await supabaseAdmin.storage.from('screenshots').upload(sk2, imageBuffer, { contentType: req.file.mimetype, upsert: false });
                if (!upErr2) {
                    const { data: { publicUrl: pu2 } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(sk2);
                    timeoutScreenshotUrl = pu2;
                    const { error: qErr2 } = await supabaseAdmin.from('screenshot_review_queue').insert([{
                        match_id: matchId, uploader_id: user.id, screenshot_url: timeoutScreenshotUrl,
                        storage_key: sk2, ocr_confidence: 0, reason: 'gemini_timeout_or_quota',
                        expires_at: new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
                        created_at: new Date().toISOString()
                    }]);
                    if (qErr2) console.error('Queue insert (timeout):', qErr2.message);
                    // Also update the match row so admin can see screenshot
                    await supabaseAdmin.from('friend_matches').update({ screenshot_url: timeoutScreenshotUrl }).eq('id', matchId);
                }
            } catch (storeErr2) { console.error('Failed to store timeout screenshot:', storeErr2.message); }
            return res.status(422).json({
                adminReview: true,
                screenshotStored: !!timeoutScreenshotUrl,
                error: 'AI service is busy right now — your screenshot has been saved.',
                instruction: 'An admin will review your screenshot and settle the match manually. You do not need to upload again.'
            });
        }

        const verificationTime = Date.now() - startVerification;
        console.log(`✅ Verification complete in ${verificationTime}ms`);

        const ocrResult = { score1: verificationResult.extractedScores?.score1, score2: verificationResult.extractedScores?.score2, confidence: verificationResult.ocrConfidence, rawText: verificationResult.ocrText, isValid: verificationResult.extractedScores?.score1 !== undefined && verificationResult.extractedScores?.score2 !== undefined && verificationResult.ocrConfidence > 50 };
        console.log(`📊 OCR Result: score=${ocrResult.score1}-${ocrResult.score2} conf=${ocrResult.confidence}% geminiRaw=`, JSON.stringify(verificationResult.geminiResult));
        console.log(`📊 Winner:`, JSON.stringify(verificationResult.winner));
        console.log(`📊 Recommendation: ${verificationResult.recommendation} fraudScore=${verificationResult.fraudScore}`);

        // ── HARD BLOCK: no valid score = no winner declared, route to admin review ──
        // Note: confidence >= 0 is enough — Gemini sometimes returns 0 confidence even with a valid score.
        // We trust the score if it's present and not null; fraud checks handle manipulation separately.
        const scoreValid = ocrResult.score1 !== null && ocrResult.score1 !== undefined &&
                           ocrResult.score2 !== null && ocrResult.score2 !== undefined;
        if (!scoreValid) {
            console.warn(`🚫 OCR score invalid (score1=${ocrResult.score1}, score2=${ocrResult.score2}, confidence=${ocrResult.confidence}%) — storing for admin review`);
            // Store the screenshot anyway so admin can view it
            let adminScreenshotUrl = null;
            try {
                const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
                const storageKey = `match-screenshots/${matchId}/unreadable-${user.id}-${Date.now()}.${ext}`;
                const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, imageBuffer, { contentType: req.file.mimetype, upsert: false });
                if (!uploadErr) {
                    const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);
                    adminScreenshotUrl = publicUrl;
                    // Track storage key and 1-hour expiry for auto-delete
                    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
                    try {
                        const { error: qErr } = await supabaseAdmin.from('screenshot_review_queue').insert([{
                            match_id: matchId, uploader_id: user.id, screenshot_url: adminScreenshotUrl,
                            storage_key: storageKey, ocr_confidence: ocrResult.confidence ?? 0,
                            reason: 'ocr_score_unreadable', expires_at: expiresAt, created_at: new Date().toISOString()
                        }]);
                        if (qErr) console.error('screenshot_review_queue insert failed:', qErr.message);
                    } catch (qEx) { console.error('screenshot_review_queue insert exception:', qEx.message); }
                }
            } catch (storeErr) { console.error('Failed to store unreadable screenshot:', storeErr.message); }
            return res.status(422).json({
                error: 'Could not read a valid score from this screenshot. The image has been sent to admin for review — do not resubmit.',
                adminReview: true, ocrConfidence: ocrResult.confidence ?? 0,
                screenshotStored: !!adminScreenshotUrl,
                instruction: 'An admin will review your screenshot and settle the match. You will be notified.'
            });
        }

        const isDuplicate = verificationResult?.checks?.duplicate?.passed === false && verificationResult.checks.duplicate.details?.originalMatch;
        if (isDuplicate) { console.warn(`🚫 Duplicate screenshot rejected: match=${matchId}, user=${user.id}`); return res.status(409).json({ error: verificationResult.checks.duplicate.warning || 'This screenshot has already been used in another match.', fraudScore: verificationResult.fraudScore, warnings: verificationResult.warnings }); }

        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = `match-screenshots/${matchId}/${user.id}-${Date.now()}.${ext}`;
        const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, imageBuffer, { contentType: req.file.mimetype, upsert: false });
        if (uploadErr) { console.error('Storage upload error:', uploadErr); return res.status(500).json({ error: 'Failed to store screenshot' }); }
        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        const uploadHash = verificationResult?.checks?.duplicate?.details?.hash;
        if (uploadHash) {
            try { await supabaseAdmin.from('screenshot_hashes').insert([{ hash: uploadHash, user_id: user.id, match_id: matchId }]); }
            catch (err) { if (!err.message?.includes('duplicate') && !err.code?.includes('23505')) console.error('Error storing hash:', err); }
        }

        const screenshotExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
        // opponentId already declared above (used for profile fetch)
        const myScoreField      = isCreator ? 'creator_screenshot_url'  : 'joiner_screenshot_url';
        const myScoreData       = isCreator ? 'creator_ocr_data'        : 'joiner_ocr_data';
        const opponentScoreUrl  = isCreator ? match.joiner_screenshot_url  : match.creator_screenshot_url;
        const opponentOcrRaw    = isCreator ? match.joiner_ocr_data        : match.creator_ocr_data;

        // Store this player's screenshot + OCR result
        const myOcrData = JSON.stringify({
            score1: verificationResult.extractedScores?.score1,
            score2: verificationResult.extractedScores?.score2,
            winner: verificationResult.winner,
            confidence: verificationResult.confidence,
            fraudScore: verificationResult.fraudScore,
        });
        await supabaseAdmin.from('friend_matches').update({
            [myScoreField]: publicUrl,
            [myScoreData]:  myOcrData,
            screenshot_url: publicUrl,
            screenshot_expires_at: screenshotExpiresAt,
        }).eq('id', matchId);

        // ── FIRST UPLOAD: opponent hasn't submitted yet ──────────────────────────
        if (!opponentScoreUrl) {
            // Give opponent 1 hour to upload their screenshot before ghost forfeit kicks in
            const opponentUploadDeadline = new Date(Date.now() + 60 * 60 * 1000).toISOString();
            await supabaseAdmin.from('friend_matches').update({
                [myScoreField]: publicUrl,
                [myScoreData]:  myOcrData,
                screenshot_url: publicUrl,
                screenshot_expires_at: screenshotExpiresAt,
                opponent_upload_deadline: opponentUploadDeadline,
            }).eq('id', matchId);

            console.log(`📸 First screenshot: match=${matchId}, user=${user.id}, score=${verificationResult.extractedScores?.score1}-${verificationResult.extractedScores?.score2}`);
            await sendMatchNotification(matchId, opponentId, 'upload_your_screenshot', {
                message: '⚠️ Your opponent has uploaded their match result. Upload YOUR screenshot within 1 hour — if you don\'t, the match will be awarded to them automatically.',
                deadline: opponentUploadDeadline,
                urgency: 'high',
            });
            return res.status(200).json({
                waitingForOpponent: true,
                message: 'Screenshot received! Your opponent has 1 hour to upload theirs. If they don\'t, you win automatically.',
                yourScore: { score1: verificationResult.extractedScores?.score1, score2: verificationResult.extractedScores?.score2, confidence: verificationResult.confidence },
                opponentDeadline: opponentUploadDeadline,
            });
        }

        // ── SECOND UPLOAD: cross-validate both screenshots ───────────────────────
        let opponentOcr = null;
        try { opponentOcr = JSON.parse(opponentOcrRaw); } catch {}

        const myScore1    = verificationResult.extractedScores?.score1;
        const myScore2    = verificationResult.extractedScores?.score2;
        const oppScore1   = opponentOcr?.score1;
        const oppScore2   = opponentOcr?.score2;
        const scoresAgree = myScore1 != null && myScore2 != null && oppScore1 != null && oppScore2 != null &&
                            myScore1 === oppScore1 && myScore2 === oppScore2;

        console.log(`🔀 Cross-validation match=${matchId}: uploader=${myScore1}-${myScore2} opponent=${oppScore1}-${oppScore2} agree=${scoresAgree}`);

        if (!scoresAgree) {
            // Scores don't match — ask Gemini to compare both screenshots and pick the credible one
            console.log(`🤖 [arbitrate] Score mismatch ${oppScore1}-${oppScore2} vs ${myScore1}-${myScore2} — asking Gemini to adjudicate...`);

            let creatorBuffer = null, joinerBuffer = null;
            try {
                const creatorUrl = isCreator ? match.joiner_screenshot_url : match.creator_screenshot_url; // opponent's
                const joinerUrl  = isCreator ? publicUrl : (isCreator ? match.creator_screenshot_url : publicUrl);
                // Simpler: fetch both stored URLs
                const creatorScreenshotUrl = match.creator_screenshot_url || (isCreator ? null : publicUrl);
                const joinerScreenshotUrl  = match.joiner_screenshot_url  || (isCreator ? publicUrl : null);

                const fetchBuf = async (url) => {
                    if (!url) return null;
                    const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
                    return r.ok ? Buffer.from(await r.arrayBuffer()) : null;
                };
                [creatorBuffer, joinerBuffer] = await Promise.all([fetchBuf(creatorScreenshotUrl), fetchBuf(joinerScreenshotUrl)]);
            } catch(e) { console.error('mismatch fetch error:', e.message); }

            const arbResult = creatorBuffer && joinerBuffer
                ? await geminiArbitrate('mismatch', { creatorBuffer, joinerBuffer, creatorTeam: match.creator_team, joinerTeam: match.joiner_team, score1A: oppScore1, score2A: oppScore2, score1B: myScore1, score2B: myScore2 })
                : { resolved: false, reason: 'could_not_fetch_images' };

            if (arbResult.resolved) {
                console.log(`✅ [arbitrate] Mismatch resolved: winner=${arbResult.winner} score=${arbResult.score1}-${arbResult.score2} conf=${arbResult.confidence}%`);
                const arbWinnerId = arbResult.winner === 'creator' ? match.creator_id : arbResult.winner === 'joiner' ? match.joiner_id : null;
                const arbLoserId  = arbResult.winner === 'creator' ? match.joiner_id  : arbResult.winner === 'joiner' ? match.creator_id : null;

                if (arbResult.winner === 'draw') {
                    const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                    await supabaseAdmin.from('friend_matches').update({ status: 'penalty_shootout', penalty_deadline: penaltyDeadline, draw_score: `${arbResult.score1}-${arbResult.score2}`, draw_detected_at: new Date().toISOString(), arbitration_data: JSON.stringify(arbResult) }).eq('id', matchId);
                    await sendMatchNotification(matchId, match.creator_id, 'draw_detected', { score: `${arbResult.score1}-${arbResult.score2}`, penaltyDeadline });
                    await sendMatchNotification(matchId, match.joiner_id,  'draw_detected', { score: `${arbResult.score1}-${arbResult.score2}`, penaltyDeadline });
                    return res.status(200).json({ draw: true, penaltyShootout: true, penaltyDeadline, message: 'AI review confirmed a draw. Play a Penalty Shootout.' });
                }
                if (arbResult.confidence >= 80 && arbWinnerId) {
                    const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: arbWinnerId, p_amount: match.winner_prize });
                    if (payoutErr) throw payoutErr;
                    await supabaseAdmin.from('friend_matches').update({ winner_id: arbWinnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'gemini_arbitration', settlement_confidence: arbResult.confidence, arbitration_data: JSON.stringify(arbResult) }).eq('id', matchId);
                    await sendMatchNotification(matchId, arbWinnerId, 'match_settled', { youWon: true, prize: match.winner_prize, method: 'gemini_arbitration', note: arbResult.reasoning });
                    await sendMatchNotification(matchId, arbLoserId,  'match_settled', { youWon: false, method: 'gemini_arbitration', note: arbResult.reasoning });
                    console.log(`✅ Gemini arbitration settled match ${matchId} — winner ${arbWinnerId}`);
                    return res.status(200).json({ settled: true, message: 'AI reviewed both screenshots and determined the winner.', winnerId: arbWinnerId, youWon: arbWinnerId === user.id });
                }
                // Gemini resolved but low confidence — pending review with arbitration data attached
                await supabaseAdmin.from('friend_matches').update({ winner_id: arbWinnerId, status: 'pending_review', settlement_method: 'gemini_arbitration_low_conf', arbitration_data: JSON.stringify(arbResult) }).eq('id', matchId);
                await sendMatchNotification(matchId, match.creator_id, 'admin_review_needed', { reason: 'mismatch_low_conf', note: arbResult.reasoning });
                await sendMatchNotification(matchId, match.joiner_id,  'admin_review_needed', { reason: 'mismatch_low_conf', note: arbResult.reasoning });
                return res.status(200).json({ pendingReview: true, message: 'AI reviewed both screenshots but confidence was low. Pending admin confirmation.' });
            }

            // Gemini couldn't decide → genuine dispute, needs human
            console.log(`🚫 [arbitrate] Mismatch unresolved (${arbResult.reason}) — genuine dispute`);
            await supabaseAdmin.from('friend_matches').update({ status: 'disputed', disputed_at: new Date().toISOString(), dispute_reason: `Score mismatch: player1 saw ${oppScore1}-${oppScore2}, player2 saw ${myScore1}-${myScore2}. AI could not determine credible screenshot.` }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'score_mismatch', { message: `Score mismatch (${oppScore1}-${oppScore2} vs ${myScore1}-${myScore2}). AI couldn't decide — an admin will review.` });
            await sendMatchNotification(matchId, match.joiner_id,  'score_mismatch', { message: `Score mismatch (${oppScore1}-${oppScore2} vs ${myScore1}-${myScore2}). AI couldn't decide — an admin will review.` });
            return res.status(200).json({ disputed: true, message: 'Screenshots show different scores and AI could not determine which is correct. An admin will review.' });
        }

        // Scores agree — determine winner from the verified data
        const agreedWinner = verificationResult.winner;
        if (!agreedWinner || agreedWinner.winner === null) {
            // Both screenshots agree on score but team side unknown — ask Gemini
            console.log(`🤖 [arbitrate] Dual-upload team_side_unknown — asking Gemini...`);
            const arbResult = await geminiArbitrate('team_side', {
                imageBuffer,
                score1: myScore1,
                score2: myScore2,
                creatorTeam: match.creator_team,
                joinerTeam:  match.joiner_team,
            });
            if (arbResult.resolved) {
                console.log(`✅ [arbitrate] Team side resolved for dual-upload: winner=${arbResult.winner} conf=${arbResult.confidence}%`);
                const arbWinnerId = arbResult.winner === 'draw' ? null : arbResult.winner === 'creator' ? match.creator_id : match.joiner_id;
                const arbLoserId  = arbResult.winner === 'draw' ? null : arbResult.winner === 'creator' ? match.joiner_id  : match.creator_id;
                if (arbResult.winner === 'draw') {
                    const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                    await supabaseAdmin.from('friend_matches').update({ status: 'penalty_shootout', penalty_deadline: penaltyDeadline, draw_score: `${myScore1}-${myScore2}`, draw_detected_at: new Date().toISOString() }).eq('id', matchId);
                    await sendMatchNotification(matchId, match.creator_id, 'draw_detected', { score: `${myScore1}-${myScore2}`, penaltyDeadline });
                    await sendMatchNotification(matchId, match.joiner_id,  'draw_detected', { score: `${myScore1}-${myScore2}`, penaltyDeadline });
                    return res.status(200).json({ draw: true, penaltyShootout: true, penaltyDeadline, message: 'Both screenshots confirm a draw! Play a Penalty Shootout.' });
                }
                const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: arbWinnerId, p_amount: match.winner_prize });
                if (payoutErr) throw payoutErr;
                await supabaseAdmin.from('friend_matches').update({ winner_id: arbWinnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'gemini_arbitration', settlement_confidence: arbResult.confidence, arbitration_data: JSON.stringify(arbResult) }).eq('id', matchId);
                await sendMatchNotification(matchId, arbWinnerId, 'match_settled', { youWon: true, prize: match.winner_prize, method: 'gemini_arbitration' });
                await sendMatchNotification(matchId, arbLoserId,  'match_settled', { youWon: false, method: 'gemini_arbitration' });
                return res.status(200).json({ settled: true, message: 'Both screenshots confirmed — AI identified the winner.', winnerId: arbWinnerId, youWon: arbWinnerId === user.id });
            }
            // Gemini failed — only now escalate to admin
            await supabaseAdmin.from('friend_matches').update({ status: 'pending_review', verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'admin_review_needed', { reason: 'team_side_unknown', score: `${myScore1}-${myScore2}` });
            await sendMatchNotification(matchId, match.joiner_id,  'admin_review_needed', { reason: 'team_side_unknown', score: `${myScore1}-${myScore2}` });
            return res.status(200).json({ adminReview: true, message: `Both screenshots agree on score ${myScore1}-${myScore2}. AI couldn't identify team sides — admin will confirm the winner.` });
        }

        if (agreedWinner.winner === 'draw') {
            const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            await supabaseAdmin.from('friend_matches').update({ status: 'penalty_shootout', penalty_deadline: penaltyDeadline, draw_score: `${myScore1}-${myScore2}`, draw_detected_at: new Date().toISOString(), verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, match.creator_id, 'draw_detected', { score: `${myScore1}-${myScore2}`, penaltyDeadline });
            await sendMatchNotification(matchId, match.joiner_id,  'draw_detected', { score: `${myScore1}-${myScore2}`, penaltyDeadline });
            return res.status(200).json({ draw: true, penaltyShootout: true, penaltyDeadline, score: `${myScore1}-${myScore2}`, message: "Both screenshots confirm a draw! Play a Penalty Shootout and upload the result." });
        }

        const winnerId = agreedWinner.winner === 'creator' ? match.creator_id : match.joiner_id;
        const loserId  = agreedWinner.winner === 'creator' ? match.joiner_id  : match.creator_id;
        const bothHighConf = verificationResult.confidence >= 75 && (opponentOcr?.confidence ?? 0) >= 75;
        const bothClean    = verificationResult.fraudScore < 30 && (opponentOcr?.fraudScore ?? 99) < 30;

        if (bothHighConf && bothClean) {
            // Both screenshots are clean, high-confidence, and agree → auto-settle
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
            if (payoutErr) throw payoutErr;
            await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_confidence: verificationResult.confidence, settlement_method: 'dual_upload_auto', verification_data: verificationResult }).eq('id', matchId);
            await sendMatchNotification(matchId, winnerId, 'match_settled', { youWon: true, score: `${agreedWinner.creatorScore}-${agreedWinner.joinerScore}`, prize: match.winner_prize, method: 'dual_upload_auto' });
            await sendMatchNotification(matchId, loserId,  'match_settled', { youWon: false, score: `${agreedWinner.creatorScore}-${agreedWinner.joinerScore}`, method: 'dual_upload_auto' });
            console.log(`✅ Dual-upload auto-settled match ${matchId} — winner ${winnerId}, prize ${match.winner_prize}`);
            return res.status(200).json({ settled: true, message: 'Both screenshots confirmed — winner paid!', winnerId, prizePaid: match.winner_prize, score: `${myScore1}-${myScore2}`, youWon: winnerId === user.id });
        }

        // Scores agree but confidence/fraud borderline — try Gemini second-look before admin
        console.log(`🤖 [arbitrate] Dual-upload borderline (conf=${verificationResult.confidence}/${opponentOcr?.confidence} fraud=${verificationResult.fraudScore}/${opponentOcr?.fraudScore}) — Gemini second-look...`);
        const arbResult = await geminiArbitrate('team_side', {
            imageBuffer,
            score1: myScore1, score2: myScore2,
            creatorTeam: match.creator_team, joinerTeam: match.joiner_team,
        });
        if (arbResult.resolved && arbResult.confidence >= 75) {
            const arbWinnerId = arbResult.winner === 'creator' ? match.creator_id : match.joiner_id;
            const arbLoserId  = arbResult.winner === 'creator' ? match.joiner_id  : match.creator_id;
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: arbWinnerId, p_amount: match.winner_prize });
            if (payoutErr) throw payoutErr;
            await supabaseAdmin.from('friend_matches').update({ winner_id: arbWinnerId, status: 'completed', completed_at: new Date().toISOString(), settlement_method: 'dual_upload_gemini', settlement_confidence: arbResult.confidence, verification_data: verificationResult, arbitration_data: JSON.stringify(arbResult) }).eq('id', matchId);
            await sendMatchNotification(matchId, arbWinnerId, 'match_settled', { youWon: true,  prize: match.winner_prize, score: `${myScore1}-${myScore2}`, method: 'dual_upload_gemini' });
            await sendMatchNotification(matchId, arbLoserId,  'match_settled', { youWon: false, score: `${myScore1}-${myScore2}`, method: 'dual_upload_gemini' });
            console.log(`✅ Gemini second-look settled dual-upload match ${matchId} — winner ${arbWinnerId}`);
            return res.status(200).json({ settled: true, message: 'Both screenshots confirmed — winner paid!', winnerId: arbWinnerId, prizePaid: match.winner_prize, score: `${myScore1}-${myScore2}`, youWon: arbWinnerId === user.id });
        }
        // Gemini also unsure — only now escalate to admin
        console.log(`🚫 [arbitrate] Gemini second-look failed (${arbResult.reason}) — routing to admin`);
        await supabaseAdmin.from('friend_matches').update({ winner_id: winnerId, status: 'pending_review', settlement_method: 'dual_upload_review', verification_data: verificationResult }).eq('id', matchId);
        await sendMatchNotification(matchId, winnerId, 'admin_review_needed', { youWon: true, score: `${myScore1}-${myScore2}`, message: 'Both screenshots agree. Pending admin approval before payout.' });
        await sendMatchNotification(matchId, loserId,  'admin_review_needed', { youWon: false, score: `${myScore1}-${myScore2}`, message: 'Both screenshots agree. Pending admin review.' });
        return res.status(200).json({ pendingReview: true, message: 'Both screenshots agree on the result. Pending admin review before payout.', score: `${myScore1}-${myScore2}` });

    } catch (err) {
        console.error('Screenshot upload/verify error:', err);
        return sendGenericError(res, 500, 'Screenshot processing failed', err);
    }
});

// ============================================================
// OCR-ONLY ENDPOINT
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

        const VerifierClass = await getVerifierClass();
        const verifier = new VerifierClass(supabaseAdmin, { teams: EFOOTBALL_TEAMS, extractTeamNames });

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        const response = await fetch(screenshotUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) return res.status(502).json({ error: 'Failed to fetch screenshot' });

        const buffer = Buffer.from(await response.arrayBuffer());
        const ocrResult = await verifier.extractScoreWithConfidence(buffer);
        res.json({ score1: ocrResult.score1, score2: ocrResult.score2, confidence: Math.round(ocrResult.confidence), isValid: ocrResult.isValid, rawText: ocrResult.rawText });
    } catch (err) { console.error('Extract score error:', err); return sendGenericError(res, 500, 'OCR extraction failed', err); }
});

// ============================================================
// STORE SCREENSHOT ONLY
// ============================================================
app.post('/screenshots/store-only', screenshotUploadLimiter, async (req, res) => {
    const multer = getMulter();
    const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 }, fileFilter: (req, file, cb) => { const allowed = ['image/jpeg', 'image/png', 'image/webp']; if (allowed.includes(file.mimetype)) cb(null, true); else cb(new Error('Only JPEG, PNG, and WebP images are allowed')); } }).single('screenshot');
    await new Promise((resolve, reject) => { upload(req, res, err => err ? reject(err) : resolve()); }).catch(err => res.status(400).json({ error: err.message || 'Invalid file upload' }));
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

        const { data: match, error: matchErr } = await supabaseAdmin.from('friend_matches').select('creator_id, joiner_id').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'You are not part of this match' });

        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = `match-screenshots/${matchId}/ref-${user.id}-${Date.now()}.${ext}`;
        const { error: uploadErr } = await supabaseAdmin.storage.from('screenshots').upload(storageKey, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
        if (uploadErr) { console.error('store-only upload error:', uploadErr); return res.status(500).json({ error: 'Failed to store screenshot' }); }

        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);
        console.log(`📸 store-only: match=${matchId} user=${user.id}`);
        res.status(200).json({ screenshotUrl: publicUrl });
    } catch (err) { console.error('store-only error:', err); return res.status(500).json({ error: 'Server error storing screenshot' }); }
});

// ============================================================
// SCREENSHOT HELPERS & AUTO-DELETE (1-HOUR TTL)
// ============================================================

// Delete all screenshots for a match from Supabase Storage + review queue
async function deleteMatchScreenshots(matchId) {
    try {
        // 1. Delete files from storage bucket under match-screenshots/{matchId}/
        const { data: files, error: listErr } = await supabaseAdmin.storage
            .from('screenshots')
            .list(`match-screenshots/${matchId}`);
        if (listErr) { console.error(`deleteMatchScreenshots list error [${matchId}]:`, listErr.message); }
        else if (files && files.length > 0) {
            const paths = files.map(f => `match-screenshots/${matchId}/${f.name}`);
            const { error: removeErr } = await supabaseAdmin.storage.from('screenshots').remove(paths);
            if (removeErr) console.error(`deleteMatchScreenshots remove error [${matchId}]:`, removeErr.message);
            else console.log(`🗑️  Deleted ${paths.length} screenshot(s) for match ${matchId}`);
        }
        // 2. Clear screenshot URL columns on the match row
        await supabaseAdmin.from('friend_matches').update({
            screenshot_url: null, declared_screenshot_url: null, confirmer_screenshot_url: null,
            draw_screenshot_url: null, penalty_screenshot_url: null,
            first_upload_screenshot_url: null, challenge_screenshot_url: null, disputer_screenshot_url: null,
            screenshots_deleted_at: new Date().toISOString()
        }).eq('id', matchId);
        // 3. Remove from review queue
        await supabaseAdmin.from('screenshot_review_queue').delete().eq('match_id', matchId);
    } catch (err) { console.error(`deleteMatchScreenshots error [${matchId}]:`, err.message); }
}

// Auto-delete screenshots that have exceeded their 1-hour TTL
async function purgeExpiredScreenshots() {
    try {
        const now = new Date().toISOString();

        // 1. Find matches whose screenshot TTL has passed (pending_review or completed with expiry set)
        const { data: expiredMatches, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, status')
            .lt('screenshot_expires_at', now)
            .is('screenshots_deleted_at', null)
            .not('screenshot_expires_at', 'is', null);

        if (matchErr) { console.error('purgeExpiredScreenshots match query error:', matchErr.message); }
        else if (expiredMatches && expiredMatches.length > 0) {
            console.log(`🗑️  Purging screenshots for ${expiredMatches.length} expired match(es)...`);
            for (const match of expiredMatches) {
                await deleteMatchScreenshots(match.id);
                console.log(`🗑️  Screenshots purged for match ${match.match_code} (status: ${match.status})`);
            }
        }

        // 2. Also purge individual review queue entries (unreadable screenshots stored for admin)
        const { data: expiredQueue, error: qErr } = await supabaseAdmin
            .from('screenshot_review_queue')
            .select('id, match_id, storage_key')
            .lt('expires_at', now);

        if (qErr) { console.error('purgeExpiredScreenshots queue query error:', qErr.message); }
        else if (expiredQueue && expiredQueue.length > 0) {
            const keysToDelete = expiredQueue.map(r => r.storage_key).filter(Boolean);
            if (keysToDelete.length > 0) {
                const { error: rmErr } = await supabaseAdmin.storage.from('screenshots').remove(keysToDelete);
                if (rmErr) console.error('purgeExpiredScreenshots storage remove error:', rmErr.message);
            }
            const ids = expiredQueue.map(r => r.id);
            await supabaseAdmin.from('screenshot_review_queue').delete().in('id', ids);
            console.log(`🗑️  Purged ${expiredQueue.length} review queue screenshot(s)`);
        }
    } catch (err) { console.error('purgeExpiredScreenshots error:', err.message); }
}

// Run every 10 minutes
setInterval(purgeExpiredScreenshots, 10 * 60 * 1000);
setTimeout(purgeExpiredScreenshots, 15000); // initial check 15s after boot

// ============================================================
// SERVER START
// ============================================================

// Export app for Vercel serverless functions
module.exports = app;

const host = '::';
const finalPort = process.env.PORT || 8100;

const server = app.listen(finalPort, host, () => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log("========================================");
    console.log(`✅ Vumbua Game running on ${host}:${finalPort}`);
    console.log(`   Memory: ${memMB}MB`);
    console.log("========================================");

    // ── FIX: Pre-warm OCR worker correctly ──────────────────────
    // screenshot-verifier.js exports:
    //   module.exports = ScreenshotVerifier        (the class)
    //   module.exports.initWorkerPool = initWorkerPool  (standalone fn)
    // So we call require('./screenshot-verifier').initWorkerPool()
    // NOT new VerifierClass().initWorkerPool() — that method doesn't exist on the instance.
    setTimeout(async () => {
        try {
            const screenshotVerifierModule = require('./screenshot-verifier');
            if (typeof screenshotVerifierModule.initWorkerPool === 'function') {
                await screenshotVerifierModule.initWorkerPool();
                console.log('✅ OCR worker pre-warmed and ready.');
            } else {
                console.log('ℹ️ OCR pre-warm skipped: initWorkerPool not exported.');
            }
        } catch (e) {
            console.warn('⚠️ OCR pre-warm failed (non-fatal):', e.message);
        }
    }, 3000);
});

server.timeout          = 90000;
server.headersTimeout   = 95000;
server.keepAliveTimeout = 65000;