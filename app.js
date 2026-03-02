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
// ⚠️ DISABLED: Tesseract OCR is causing hangs. Use manual score declaration instead.
let _verifier = null;
function getVerifier() {
    // OCR disabled - return null to force manual score entry
    console.log('ℹ️ OCR disabled. Users will declare scores manually.');
    return null;
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

// ✅ NEW: Admin endpoint rate limiter (prevents brute force)
const adminLimiter = rateLimit({
    windowMs: 60 * 1000,        // 1 minute
    max: 5,                      // 5 requests per minute
    message: { error: 'Admin rate limit exceeded. Try again later.' },
    keyGenerator: (req, res) => {
        // Rate limit per IP, not per user
        return req.ip;
    },
    skip: (req) => {
        // Skip rate limiting if no admin key (just check early)
        return !req.headers['x-admin-key'];
    }
});

// Helpers
/**
 * IMPROVED: Validate and normalize Kenya phone numbers
 * Accepts: +254712345678, 0712345678, 712345678, 254712345678
 * Returns: +254712345678 or null if invalid
 */
function normalizePhone(phone) {
    // Input type validation
    if (!phone || typeof phone !== 'string') {
        console.warn('⚠️ Invalid phone type:', typeof phone);
        return null;
    }
    
    // Prevent ReDoS: limit input length
    if (phone.length > 30) {
        console.warn('⚠️ Phone number too long');
        return null;
    }
    
    // Remove all non-digits
    const cleaned = phone.replace(/\D/g, '');
    
    // Prevent empty input
    if (cleaned.length === 0) {
        console.warn('⚠️ Phone number has no digits');
        return null;
    }
    
    // Kenya number formats validation
    if (cleaned.startsWith('254') && cleaned.length === 12) {
        // Already has country code: 254712345678
        const prefix = cleaned.substring(3, 4);
        if (!['1', '7'].includes(prefix)) {
            console.warn('⚠️ Invalid Kenya number prefix:', prefix);
            return null;
        }
        return '+' + cleaned;
    } else if (cleaned.startsWith('0') && cleaned.length === 10) {
        // Has leading zero: 0712345678
        const prefix = cleaned.substring(1, 2);
        if (!['1', '7'].includes(prefix)) {
            console.warn('⚠️ Invalid Kenya number prefix:', prefix);
            return null;
        }
        return '+254' + cleaned.slice(1);
    } else if (cleaned.length === 9) {
        // No country code or leading zero: 712345678
        const prefix = cleaned.substring(0, 1);
        if (!['1', '7'].includes(prefix)) {
            console.warn('⚠️ Invalid Kenya number prefix:', prefix);
            return null;
        }
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

// eFootball teams list - used for team name matching and validation
const EFOOTBALL_TEAMS = [
    // Premier League
    'Arsenal', 'Aston Villa', 'Bournemouth', 'Brentford', 'Brighton', 'Chelsea', 'Crystal Palace',
    'Everton', 'Fulham', 'Ipswich Town', 'Leicester City', 'Liverpool', 'Manchester City',
    'Manchester United', 'Newcastle United', 'Nottingham Forest', 'Southampton', 'Tottenham',
    'West Ham', 'Wolverhampton',
    // La Liga
    'Real Madrid', 'Barcelona', 'Atletico Madrid', 'Sevilla', 'Real Sociedad', 'Villarreal',
    'Betis', 'Getafe', 'Rayo Vallecano', 'Osasuna', 'Celta Vigo', 'Athletic Bilbao',
    'Real Valladolid', 'Almeria', 'Girona', 'Las Palmas', 'Valencia', 'Mallorca',
    // Serie A
    'Juventus', 'Inter Milan', 'AC Milan', 'Roma', 'Lazio', 'Napoli', 'Atalanta',
    'Fiorentina', 'Torino', 'Monza', 'Bologna', 'Sassuolo', 'Sampdoria', 'Lecce',
    'Verona', 'Salernitana', 'Frosinone', 'Cagliari', 'Empoli', 'Genoa',
    // Bundesliga
    'Bayern Munich', 'Borussia Dortmund', 'RB Leipzig', 'Bayer Leverkusen', 'VfB Stuttgart',
    'Hamburg', 'Mainz', 'Cologne', 'Union Berlin', 'Hoffenheim', 'Freiburg', 'Wolfsburg',
    'Eintracht Frankfurt', 'Schalke 04', 'Borussia Monchengladbach', 'Augsburg', 'Hertha Berlin',
    // Ligue 1
    'Paris Saint-Germain', 'Marseille', 'Lyon', 'AS Monaco', 'Lille', 'Nice', 'Rennes',
    'Lens', 'Toulouse', 'Montpellier', 'Nantes', 'Strasbourg', 'Brest', 'Reims',
    // Champions League/International
    'PSV Eindhoven', 'Ajax', 'Feyenoord', 'Porto', 'Benfica', 'Sporting CP', 'Celtic',
    'Rangers', 'RB Salzburg', 'Galatasaray', 'Fenerbahçe', 'Santos', 'Flamengo', 'Corinthians',
    'Palmeiras', 'Juventus', 'Al Ahly', 'Al Nassr', 'Al Hilal', 'River Plate', 'Boca Juniors'
];

// Validate eFootball-generated match code format
function validateEFootballCode(code) {
    if (!code || typeof code !== 'string') return false;
    // eFootball codes are typically uppercase alphanumeric, 4-8 characters
    // Format: XXXX or similar
    return /^[A-Z0-9]{4,8}$/.test(code.toUpperCase());
}

// Find team names in OCR text using fuzzy matching
function extractTeamNames(ocrText) {
    if (!ocrText || typeof ocrText !== 'string') return { home: null, away: null };

    const textUpper = ocrText.toUpperCase();
    const foundTeams = [];

    // Search for each team in the eFootball teams list
    for (const team of EFOOTBALL_TEAMS) {
        const teamUpper = team.toUpperCase();
        // Try exact match first, then substring match
        if (textUpper.includes(teamUpper)) {
            foundTeams.push({ name: team, position: ocrText.toUpperCase().indexOf(teamUpper) });
        }
    }

    // Sort by position (first occurrence = home, second = away)
    foundTeams.sort((a, b) => a.position - b.position);

    return {
        home: foundTeams.length > 0 ? foundTeams[0].name : null,
        away: foundTeams.length > 1 ? foundTeams[1].name : null,
        allFound: foundTeams.map(t => t.name)
    };
}

// Generic error response - prevents leaking internal errors
function sendGenericError(res, statusCode, message, internalError) {
    console.error('Error:', message, '|', internalError?.message || internalError);
    res.status(statusCode).json({ error: message });
}

// Auth helper used by declare/confirm/dispute-score routes
async function getAuthUser(jwt) {
    const { data: { user }, error } = await supabase.auth.getUser(jwt);
    return { user: user || null, error: error || null };
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

// Skip JSON body parsing for multipart routes — multer handles those instead.
// If express.json() runs first on a multipart request it tries to parse the
// boundary string as JSON and throws a SyntaxError.
const MULTIPART_ROUTES = [
    "/screenshots/upload-and-verify",
    "/friends/submit-penalty-result",
    "/friends/challenge"
];
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

// Diagnostic endpoint - check all configurations (admin only)
// ✅ UPDATED: Added admin rate limiter
app.get('/debug/config', adminLimiter, (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
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
app.get('/war-room', (req, res) => res.sendFile(path.join(__dirname, 'public', 'war-room.html')));

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
// WITHDRAWAL ROUTES
// FIX: properly import processMpesaWithdrawal and inject it
//      into `req` so the router can call it after responding.
// ============================================================
const { router: withdrawalRouter, processMpesaWithdrawal } = require('./routes/withdrawals');

// Inject processMpesaWithdrawal into every request hitting the withdrawals router
app.use('/wallet/withdrawals', (req, res, next) => {
    req.processMpesaWithdrawal = (withdrawalId) =>
        processMpesaWithdrawal(supabaseAdmin, withdrawalId);
    next();
}, withdrawalRouter);

// Backward-compat alias for old /wallet/withdraw endpoint
app.post('/wallet/withdraw', sensitiveLimiter, (req, res, next) => {
    // Normalise field name: old endpoint used 'phone', new router uses 'phoneNumber'
    if (req.body.phone && !req.body.phoneNumber) {
        req.body.phoneNumber = req.body.phone;
    }
    // Inject processMpesaWithdrawal here too
    req.processMpesaWithdrawal = (withdrawalId) =>
        processMpesaWithdrawal(supabaseAdmin, withdrawalId);
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

        const { wagerAmount, efootballCode } = req.body;
        if (!wagerAmount || isNaN(wagerAmount) || wagerAmount < 50) {
            return res.status(400).json({ error: 'Minimum wager is KES 50' });
        }

        // Validate eFootball code (required - no auto-generation)
        if (!efootballCode) {
            return res.status(400).json({
                error: 'eFootball room code is required. Create a Friends Match room in eFootball first, then enter the code here.'
            });
        }

        if (!validateEFootballCode(efootballCode)) {
            return res.status(400).json({
                error: 'Invalid eFootball code format. Codes should be 4-8 alphanumeric characters (e.g., ABC123).'
            });
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

        // Check if this eFootball code is already in use
        const { data: existing } = await supabaseAdmin
            .from('friend_matches')
            .select('id')
            .eq('match_code', `VUM-${efootballCode.toUpperCase()}`)
            .eq('status', 'pending')
            .gte('expires_at', new Date().toISOString())
            .maybeSingle();

        if (existing) {
            return res.status(400).json({
                error: 'This eFootball code is already in use. Create a new Friends Match room in eFootball.'
            });
        }

        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const platformFee = Math.floor(wagerAmount * 0.10);
        const winnerPrize = (wagerAmount * 2) - platformFee;

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .insert([{
                match_code: `VUM-${efootballCode.toUpperCase()}`, // Prefix for DB constraint compatibility
                efootball_room_code: efootballCode.toUpperCase(),
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
            console.error('Match creation DB error:', matchErr);
            return res.status(500).json({
                error: 'Failed to create match in database',
                details: matchErr.message,
                code: matchErr.code
            });
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
            efootballCode: efootballCode.toUpperCase(),
            wagerAmount,
            winnerPrize,
            platformFee,
            expiresAt,
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

        if (!validateEFootballCode(efootballCode)) {
            return res.status(400).json({
                error: 'Invalid eFootball code format. Codes should be 4-8 alphanumeric characters.'
            });
        }

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('match_code', `VUM-${efootballCode.toUpperCase()}`)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Invalid eFootball code. No active match found.' });
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
            // Draw – send to penalty shootout instead of closing the match
            const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            await supabaseAdmin.from('friend_matches').update({
                status: 'penalty_shootout',
                penalty_deadline: penaltyDeadline,
                draw_screenshot_url: screenshotUrl,
                draw_score: `${score1}-${score2}`,
                draw_detected_at: new Date().toISOString(),
                verification_data: verificationResult
            }).eq('id', matchId);

            return res.status(200).json({
                draw: true,
                penaltyShootout: true,
                penaltyDeadline,
                message: 'Match ended in a draw! Go back to eFootball, create a new Friends Match room with your opponent and play a Penalty Shootout. Either player can then upload the result screenshot here.',
                instructions: [
                    '1. One player creates a new Friends Match room in eFootball',
                    '2. Share the room code with your opponent',
                    '3. Play the Penalty Shootout match',
                    '4. Either player uploads the result screenshot to settle the wager'
                ]
            });
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
// PENALTY SHOOTOUT RESULT
// POST /friends/submit-penalty-result
// ============================================================
app.post('/friends/submit-penalty-result', screenshotUploadLimiter, async (req, res) => {
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
        upload(req, res, (err) => { if (err) reject(err); else resolve(); });
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

        const { matchId } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });
        if (!req.file) return res.status(400).json({ error: 'No screenshot provided' });

        // Fetch match and validate state
        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'penalty_shootout')
            return res.status(400).json({ error: 'This match is not awaiting penalties. Only drawn matches go to a penalty shootout.' });

        // Check deadline
        if (match.penalty_deadline && new Date() > new Date(match.penalty_deadline)) {
            await supabaseAdmin.from('friend_matches').update({
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: 'Penalty shootout deadline passed — no result submitted'
            }).eq('id', matchId);
            return res.status(400).json({ error: 'Penalty shootout deadline has passed. Match sent for admin review.' });
        }

        const imageBuffer = req.file.buffer;
        const verifier = getVerifier();
        if (!verifier) return res.status(503).json({ error: 'Verification service unavailable' });

        // Get usernames for OCR context
        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const [uploaderRes, opponentRes] = await Promise.all([
            supabaseAdmin.from('profiles').select('username').eq('id', user.id).maybeSingle(),
            supabaseAdmin.from('profiles').select('username').eq('id', opponentId).maybeSingle()
        ]);
        const uploaderUsername = uploaderRes.data?.username || null;
        const opponentUsername = opponentRes.data?.username || null;

        // Run OCR + verification in parallel
        const [verificationResult, ocrResult] = await Promise.all([
            verifier.verifyScreenshot(imageBuffer, {
                userId: user.id,
                matchId,
                startedAt: match.draw_detected_at || match.started_at,
                opponentUsername,
                uploaderUsername,
                matchCode: match.match_code,
                creatorTeam: match.creator_team,
                joinerTeam: match.joiner_team,
                isPenaltyShootout: true
            }),
            verifier.extractScoreWithConfidence(imageBuffer)
        ]);

        const confidence = verificationResult?.confidence ?? 0;
        const fraudScore = verificationResult?.fraudScore ?? 999;
        const score1 = ocrResult?.score1;
        const score2 = ocrResult?.score2;

        // Reject manipulated screenshots
        if (fraudScore >= 50) {
            await supabaseAdmin.from('friend_matches').update({
                status: 'disputed',
                disputed_at: new Date().toISOString(),
                dispute_reason: 'Suspicious penalty screenshot — fraud score: ' + fraudScore,
                verification_data: verificationResult
            }).eq('id', matchId);
            return res.status(422).json({
                error: 'Screenshot flagged as suspicious. Match sent for admin review.',
                fraudScore,
                warnings: verificationResult?.warnings
            });
        }

        if (confidence < 50) {
            return res.status(422).json({
                error: `Screenshot confidence too low (${confidence}%) — upload a clearer penalty result screen.`,
                confidence
            });
        }

        // Scores must be readable
        if (score1 === null || score1 === undefined || score2 === null || score2 === undefined) {
            return res.status(422).json({
                error: 'Could not read the score. Make sure you upload the final penalty result screen from eFootball.'
            });
        }

        // Penalties CANNOT end in a draw
        if (score1 === score2) {
            return res.status(422).json({
                error: 'Penalty shootouts cannot end in a draw. Please upload the correct final penalty result screenshot.',
                detectedScore: score1 + '-' + score2,
                hint: 'Make sure this is the penalty shootout result screen, not the regular match result.'
            });
        }

        // Determine winner via team name mapping
        const teamMatch = verificationResult?.teamMatch;
        let winnerId = null;

        if (teamMatch && teamMatch.bestMapping !== 'ambiguous') {
            const isCreatorHome = (teamMatch.bestHome === match.creator_team);
            const homeId = isCreatorHome ? match.creator_id : match.joiner_id;
            const awayId = isCreatorHome ? match.joiner_id : match.creator_id;
            winnerId = score1 > score2 ? homeId : awayId;
        } else {
            return res.status(422).json({
                error: 'Could not reliably identify which team belongs to which player. Match sent for admin review.',
                hint: 'Make sure both team names are visible in the screenshot.'
            });
        }

        // Store the penalty screenshot in Supabase Storage
        const ext = req.file.mimetype === 'image/png' ? 'png' : req.file.mimetype === 'image/webp' ? 'webp' : 'jpg';
        const storageKey = 'match-screenshots/' + matchId + '/penalty-' + user.id + '-' + Date.now() + '.' + ext;
        const { error: uploadErr } = await supabaseAdmin.storage
            .from('screenshots').upload(storageKey, imageBuffer, { contentType: req.file.mimetype, upsert: false });
        if (uploadErr) throw uploadErr;
        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        // Auto-settle if confidence is high
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
                settlement_method: 'penalty_shootout',
                settlement_confidence: confidence,
                penalty_screenshot_url: publicUrl,
                penalty_score: score1 + '-' + score2,
                verification_data: verificationResult
            }).eq('id', matchId);

            console.log('\u26bd Penalty auto-settled: match=' + matchId + ', winner=' + winnerId + ', prize=' + match.winner_prize);

            return res.status(200).json({
                message: 'Penalty shootout settled! Winner has been paid.',
                winnerId,
                prizePaid: match.winner_prize,
                penaltyScore: score1 + '-' + score2,
                confidence,
                youWon: winnerId === user.id,
                settlementMethod: 'penalty_shootout'
            });
        }

        // Medium confidence — open 2hr challenge window
        const challengeDeadline = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
        await supabaseAdmin.from('friend_matches').update({
            challenge_deadline: challengeDeadline,
            challenge_uploaded: false,
            first_upload_winner_id: winnerId,
            first_upload_confidence: confidence,
            first_upload_screenshot_url: publicUrl,
            penalty_screenshot_url: publicUrl,
            penalty_score: score1 + '-' + score2,
            settlement_confidence: confidence,
            verification_data: verificationResult
        }).eq('id', matchId);

        return res.status(200).json({
            message: 'Penalty result recorded. Your opponent has 2 hours to challenge.',
            challengeDeadline,
            confidence,
            penaltyScore: score1 + '-' + score2
        });

    } catch (err) {
        console.error('Penalty result error:', err);
        return sendGenericError(res, 500, 'Failed to process penalty result', err);
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
// MY MATCHES ENDPOINT
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

// ============================================================
// SCORE DECLARATION SYSTEM
// New fraud-resistant flow:
//   1. Player A declares score + uploads screenshot
//   2. Player B gets notified, sees declared score, confirms or disputes
//   3. On confirm → instant payout. On dispute → admin review.
//
// This makes cheating socially hard: you must declare a false score
// AND your opponent will immediately see and dispute it.
// ============================================================

// POST /friends/declare-score
// Player declares the score and uploads their screenshot.
// The money does NOT move yet — waiting for opponent confirmation.
app.post('/friends/declare-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, myScore, opponentScore, screenshotUrl } = req.body;

        if (!matchId || myScore === undefined || opponentScore === undefined) {
            return res.status(400).json({ error: 'matchId, myScore and opponentScore are required' });
        }
        if (!Number.isInteger(myScore) || !Number.isInteger(opponentScore) ||
            myScore < 0 || opponentScore < 0 || myScore > 20 || opponentScore > 20) {
            return res.status(400).json({ error: 'Invalid score values' });
        }
        if (!screenshotUrl || !isValidScreenshotUrl(screenshotUrl)) {
            return res.status(400).json({ error: 'A valid screenshot URL is required' });
        }

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, status, creator_id, joiner_id, winner_prize, wager_amount, declared_score_by, draw_score')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active')
            return res.status(400).json({ error: 'Match is not active' });
        if (match.declared_score_by)
            return res.status(400).json({ error: 'Score already declared for this match. Waiting for opponent confirmation.' });

        const isCreator = match.creator_id === user.id;
        // Score from the declaring player's perspective:
        // myScore = their own goals, opponentScore = opponent's goals
        const creatorScore = isCreator ? myScore : opponentScore;
        const joinerScore  = isCreator ? opponentScore : myScore;

        const isDraw = creatorScore === joinerScore;
        const declaringWinnerId = myScore > opponentScore ? user.id
            : opponentScore > myScore ? (isCreator ? match.joiner_id : match.creator_id)
            : null;

        const opponentId = isCreator ? match.joiner_id : match.creator_id;
        const confirmDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 min to confirm or auto-payout

        // Draw → immediately transition to penalty_shootout
        // Non-draw → awaiting_confirmation with 30-min auto-payout timer
        const penaltyDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();

        if (isDraw) {
            await supabaseAdmin.from('friend_matches').update({
                declared_score_creator: creatorScore,
                declared_score_joiner:  joinerScore,
                declared_score_by:      user.id,
                declared_at:            new Date().toISOString(),
                draw_score:             `${creatorScore}-${joinerScore}`,
                draw_screenshot_url:    screenshotUrl,
                draw_detected_at:       new Date().toISOString(),
                status:                 'penalty_shootout',
                penalty_deadline:       penaltyDeadline
            }).eq('id', matchId);

            console.log(`⚽ Draw declared for match ${matchId}: ${creatorScore}-${joinerScore} → penalty shootout`);

            return res.status(200).json({
                success: true,
                isDraw: true,
                draw: true,
                penaltyShootout: true,
                penaltyDeadline,
                creatorScore,
                joinerScore,
                message: "It's a draw! Go to eFootball, create a new Friends Match room and play a Penalty Shootout with your opponent, then come back and upload the result.",
                instructions: [
                    '1. One player creates a new Friends Match room in eFootball',
                    '2. Share the room code with your opponent',
                    '3. Play the Penalty Shootout match',
                    '4. Either player uploads the result screenshot here'
                ]
            });
        }

        await supabaseAdmin.from('friend_matches').update({
            declared_score_creator: creatorScore,
            declared_score_joiner:  joinerScore,
            declared_score_by:      user.id,
            declared_winner_id:     declaringWinnerId,
            declared_at:            new Date().toISOString(),
            declared_screenshot_url: screenshotUrl,
            score_confirm_deadline: confirmDeadline,
            status:                 'awaiting_confirmation'
        }).eq('id', matchId);

        console.log(`📋 Score declared for match ${matchId}: ${creatorScore}-${joinerScore} by ${user.id} | auto-payout at ${confirmDeadline}`);

        res.status(200).json({
            success: true,
            isDraw: false,
            creatorScore,
            joinerScore,
            confirmDeadline,
            opponentId,
            message: "Score declared! Your opponent has 30 minutes to confirm or dispute. If they don't respond, you win automatically."
        });
    } catch (err) {
        console.error('Declare score error:', err);
        res.status(500).json({ error: 'Failed to declare score' });
    }
});

// POST /friends/confirm-score
// Opponent confirms the declared score → instant payout.
app.post('/friends/confirm-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, status, creator_id, joiner_id, declared_score_by, declared_winner_id, winner_prize, score_confirm_deadline, declared_score_creator, declared_score_joiner')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'awaiting_confirmation')
            return res.status(400).json({ error: 'Match is not awaiting confirmation' });
        if (match.declared_score_by === user.id)
            return res.status(400).json({ error: 'You declared the score — you cannot confirm your own declaration' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (new Date() > new Date(match.score_confirm_deadline))
            return res.status(400).json({ error: 'Confirmation window has expired' });

        const winnerId = match.declared_winner_id;
        if (!winnerId) return res.status(400).json({ error: 'No winner declared — cannot confirm' });

        // Pay out winner immediately
        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: winnerId,
            p_amount: match.winner_prize
        });
        if (payoutErr) {
            console.error('Payout error on confirm:', payoutErr);
            return res.status(500).json({ error: 'Payout failed — please contact support' });
        }

        await supabaseAdmin.from('friend_matches').update({
            winner_id:           winnerId,
            status:              'completed',
            completed_at:        new Date().toISOString(),
            settlement_method:   'mutual_confirmation',
            confirmer_id:        user.id,
            confirmed_at:        new Date().toISOString(),
            confirmer_screenshot_url: screenshotUrl || null,
            settlement_confidence: 100
        }).eq('id', matchId);

        console.log(`✅ Score confirmed for match ${matchId} – winner ${winnerId}, prize ${match.winner_prize}`);

        res.status(200).json({
            success: true,
            winnerId,
            prizePaid: match.winner_prize,
            youWon: winnerId === user.id,
            score: `${match.declared_score_creator}-${match.declared_score_joiner}`,
            message: winnerId === user.id ? '🏆 You won! Prize credited to your wallet.' : 'Result confirmed. Better luck next time!'
        });
    } catch (err) {
        console.error('Confirm score error:', err);
        res.status(500).json({ error: 'Failed to confirm score' });
    }
});

// POST /friends/dispute-score
// Opponent disputes → sends to admin with both screenshots and declared scores.
app.post('/friends/dispute-score', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId, screenshotUrl, myScore, opponentScore } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, status, creator_id, joiner_id, declared_score_by, declared_score_creator, declared_score_joiner')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'awaiting_confirmation')
            return res.status(400).json({ error: 'Match is not awaiting confirmation' });
        if (match.declared_score_by === user.id)
            return res.status(400).json({ error: 'You cannot dispute your own declaration' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });

        const isCreator = match.creator_id === user.id;
        const disputerCreatorScore = isCreator ? myScore : opponentScore;
        const disputerJoinerScore  = isCreator ? opponentScore : myScore;

        await supabaseAdmin.from('friend_matches').update({
            status:                    'disputed',
            disputed_at:               new Date().toISOString(),
            dispute_reason:            'Score disputed by opponent',
            disputer_id:               user.id,
            disputer_screenshot_url:   screenshotUrl || null,
            disputer_declared_creator: disputerCreatorScore ?? null,
            disputer_declared_joiner:  disputerJoinerScore ?? null
        }).eq('id', matchId);

        console.log(`⚠️ Score disputed for match ${matchId} by ${user.id}`);

        res.status(200).json({
            success: true,
            message: 'Dispute raised. An admin will review both screenshots and declared scores within 24 hours.'
        });
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
// FORFEIT
// POST /friends/forfeit
// ============================================================
app.post('/friends/forfeit', sensitiveLimiter, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!matchId) return res.status(400).json({ error: 'matchId is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });

        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });

        if (match.status !== 'active' && match.status !== 'penalty_shootout')
            return res.status(400).json({ error: 'Match is not active — cannot forfeit' });

        const winnerId = match.creator_id === user.id ? match.joiner_id : match.creator_id;

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: winnerId,
            p_amount: match.winner_prize
        });
        if (payoutErr) throw payoutErr;

        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId,
            status: 'completed',
            completed_at: new Date().toISOString(),
            settlement_method: 'forfeit',
            forfeit_by: user.id
        }).eq('id', matchId);

        await supabaseAdmin.rpc('increment_forfeit_count', { p_user_id: user.id })
            .catch(() => {});

        console.log(`🏳️  Forfeit: match=${matchId}, forfeitedBy=${user.id}, winner=${winnerId}`);

        res.status(200).json({
            message: 'Match forfeited. Opponent has been paid.',
            winnerId,
            prizePaid: match.winner_prize
        });
    } catch (err) {
        console.error('Forfeit error:', err);
        res.status(500).json({ error: 'Failed to process forfeit' });
    }
});

// ============================================================
// FRIEND MATCH STATUS CHECK
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
            .select('id, match_code, status, creator_id, joiner_id, wager_amount, winner_prize, winner_id, expires_at, started_at, completed_at, challenge_deadline, penalty_deadline, draw_score, penalty_score, settlement_method, forfeit_by, efootball_room_code, declared_score_creator, declared_score_joiner, declared_score_by, declared_winner_id, score_confirm_deadline')
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

        let statusMessage = null;
        if (match.status === 'penalty_shootout') {
            statusMessage = 'Match ended in a draw! Go to eFootball, play a Penalty Shootout match with your opponent, then upload the result here.';
        } else if (match.status === 'disputed') {
            statusMessage = 'Match is under admin review. Please wait.';
        } else if (match.status === 'awaiting_confirmation') {
            const iDeclared = match.declared_score_by === user.id;
            statusMessage = iDeclared
                ? 'Score declared! Waiting for your opponent to confirm or dispute.'
                : 'Your opponent declared the score. Please confirm or dispute.';
        } else if (match.status === 'completed' && match.settlement_method === 'forfeit') {
            const forfeitedByYou = match.forfeit_by === user.id;
            statusMessage = forfeitedByYou ? 'You forfeited this match.' : 'Your opponent forfeited. You won!';
        }

        // Declaration data — needed by the confirmation UI
        const iDeclared = match.declared_score_by === user.id;
        const isCreator = match.creator_id === user.id;
        const myDeclaredScore = isCreator ? match.declared_score_creator : match.declared_score_joiner;
        const opponentDeclaredScore = isCreator ? match.declared_score_joiner : match.declared_score_creator;

        res.json({
            matchId: match.id,
            matchCode: match.match_code,
            status: match.status,
            statusMessage,
            joinerUsername,
            wagerAmount: match.wager_amount,
            winnerPrize: match.winner_prize,
            winnerId: match.winner_id,
            youWon: match.winner_id === user.id,
            expiresAt: match.expires_at,
            startedAt: match.started_at,
            challengeDeadline: match.challenge_deadline,
            penaltyDeadline: match.penalty_deadline || null,
            drawScore: match.draw_score || null,
            penaltyScore: match.penalty_score || null,
            settlementMethod: match.settlement_method || null,
            // Score declaration fields
            awaitingConfirmation: match.status === 'awaiting_confirmation',
            iDeclared,
            myDeclaredScore: myDeclaredScore ?? null,
            opponentDeclaredScore: opponentDeclaredScore ?? null,
            declaredWinnerId: match.declared_winner_id || null,
            youWonDeclaration: match.declared_winner_id === user.id,
            confirmDeadline: match.score_confirm_deadline || null,
            efootballRoomCode: match.efootball_room_code || null
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
        console.log('🔍 Checking for abandoned/expired matches...');
        const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
        const now = new Date().toISOString();

        // ── 1. Old-style abandoned matches (pre-declaration system) ─────────
        const { data: abandonedMatches, error } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code')
            .eq('status', 'active')
            .not('reported_by_id', 'is', null)
            .lt('reported_at', twoHoursAgo);

        if (error) {
            console.error('Error fetching abandoned matches:', error);
        } else if (abandonedMatches && abandonedMatches.length > 0) {
            console.log(`⚠️  Found ${abandonedMatches.length} abandoned matches`);
            for (const match of abandonedMatches) {
                await supabaseAdmin.from('friend_matches').update({
                    status: 'disputed',
                    disputed_at: now,
                    dispute_reason: 'Only one player reported within time limit'
                }).eq('id', match.id);
                console.log(`⚠️  Match ${match.match_code} disputed — missing opponent report.`);
            }
        }

        // ── 2. Auto-payout: awaiting_confirmation past deadline ─────────────
        // If the opponent didn't confirm or dispute within 30 min,
        // auto-pay the declared winner and close the match.
        const { data: expiredDeclarations, error: declErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, declared_winner_id, winner_prize')
            .eq('status', 'awaiting_confirmation')
            .lt('score_confirm_deadline', now);

        if (declErr) {
            console.error('Error fetching expired declarations:', declErr);
        } else if (expiredDeclarations && expiredDeclarations.length > 0) {
            console.log(`💰 Auto-paying ${expiredDeclarations.length} unconfirmed declarations`);
            for (const match of expiredDeclarations) {
                if (!match.declared_winner_id) {
                    // No winner declared (draw slipped through?) → dispute
                    await supabaseAdmin.from('friend_matches').update({
                        status: 'disputed',
                        disputed_at: now,
                        dispute_reason: 'Confirmation deadline expired — no winner declared'
                    }).eq('id', match.id);
                    continue;
                }
                try {
                    const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
                        p_user_id: match.declared_winner_id,
                        p_amount:  match.winner_prize
                    });
                    if (payoutErr) throw payoutErr;

                    await supabaseAdmin.from('friend_matches').update({
                        winner_id:           match.declared_winner_id,
                        status:              'completed',
                        completed_at:        now,
                        settlement_method:   'auto_declaration', // opponent timed out
                        settlement_confidence: 80
                    }).eq('id', match.id);

                    console.log(`✅ Auto-paid match ${match.match_code} → winner ${match.declared_winner_id}, prize KES ${match.winner_prize}`);
                } catch (payErr) {
                    console.error(`Payout failed for match ${match.match_code}:`, payErr);
                    // Don't leave it hanging — dispute it so admin can handle
                    await supabaseAdmin.from('friend_matches').update({
                        status: 'disputed',
                        disputed_at: now,
                        dispute_reason: 'Auto-payout failed after confirmation timeout'
                    }).eq('id', match.id);
                }
            }
        } else {
            console.log('✅ No expired declarations');
        }

        // ── 3. Expired penalty shootout deadlines → dispute ─────────────────
        const { data: expiredPenalties, error: penErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code')
            .eq('status', 'penalty_shootout')
            .lt('penalty_deadline', now);

        if (penErr) {
            console.error('Error fetching expired penalty matches:', penErr);
        } else if (expiredPenalties && expiredPenalties.length > 0) {
            console.log(`⚠️  Found ${expiredPenalties.length} expired penalty shootout matches`);
            for (const match of expiredPenalties) {
                await supabaseAdmin.from('friend_matches').update({
                    status: 'disputed',
                    disputed_at: now,
                    dispute_reason: 'Penalty shootout deadline passed — no result submitted'
                }).eq('id', match.id);
                console.log(`⚠️  Match ${match.match_code} disputed — penalty deadline expired.`);
            }
        }

    } catch (err) {
        console.error('Auto-resolve error:', err);
    }
}

// Run every 2 minutes — declarations expire in 30 min so we need frequent checks
setInterval(autoResolveAbandonedMatches, 2 * 60 * 1000);
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

// ============================================================
// M-PESA CALLBACK
// FIX: Added a warning log if MPESA_CALLBACK_SECRET is not set,
//      and basic signature validation when it is.
// ============================================================
app.post('/mpesa/callback', async (req, res) => {
    try {
        // Optional: verify callback authenticity via a shared secret in the header
        // Set MPESA_CALLBACK_SECRET in your .env and pass it as a custom header
        // from your M-Pesa middleware/proxy if supported.
        if (process.env.MPESA_CALLBACK_SECRET) {
            const providedSecret = req.headers['x-mpesa-secret'];
            if (providedSecret !== process.env.MPESA_CALLBACK_SECRET) {
                console.warn('⚠️  M-Pesa callback received with invalid secret — rejecting.');
                return res.status(401).json({ ResultCode: 1, ResultDesc: 'Unauthorized' });
            }
        } else {
            // Log once at startup is better, but this catches runtime too
            console.warn('⚠️  MPESA_CALLBACK_SECRET not set — callback endpoint is unauthenticated!');
        }

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

        // FIX: Audit log — log errors instead of silently swallowing them
        const { error: auditErr } = await supabaseAdmin.from('admin_audit_log').insert([{
            action: 'withdrawal_paid',
            withdrawal_id: req.params.id,
            mpesa_code: req.body.mpesaCode || null,
            admin_ip: req.ip || req.headers['x-forwarded-for'],
            created_at: new Date().toISOString()
        }]);
        if (auditErr) console.error('⚠️  Audit log insert failed (withdrawal_paid):', auditErr.message);

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
        const { winnerId, resolution } = req.body;
        const { matchId } = req.params;

        const isDraw = resolution === 'draw';
        if (!isDraw && !winnerId) return res.status(400).json({ error: 'Either winnerId or resolution="draw" is required' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('*').eq('id', matchId).single();
        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.status !== 'disputed' && match.status !== 'penalty_shootout')
            return res.status(400).json({ error: 'Match is not in a resolvable state' });

        if (isDraw) {
            const [r1, r2] = await Promise.all([
                supabaseAdmin.rpc('credit_wallet', { p_user_id: match.creator_id, p_amount: match.wager_amount }),
                supabaseAdmin.rpc('credit_wallet', { p_user_id: match.joiner_id,  p_amount: match.wager_amount })
            ]);
            if (r1.error) throw r1.error;
            if (r2.error) throw r2.error;

            await supabaseAdmin.from('friend_matches').update({
                status: 'completed',
                completed_at: new Date().toISOString(),
                settlement_method: 'draw_refund',
                resolved_by_admin: true
            }).eq('id', matchId);

            return res.json({
                message: 'Match declared a draw. Both players refunded their wager.',
                refundedAmount: match.wager_amount,
                resolution: 'draw'
            });
        }

        if (winnerId !== match.creator_id && winnerId !== match.joiner_id) {
            return res.status(400).json({ error: 'Winner must be one of the players in this match' });
        }

        const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: winnerId, p_amount: match.winner_prize });
        if (payoutErr) throw payoutErr;

        await supabaseAdmin.from('friend_matches').update({
            winner_id: winnerId,
            status: 'completed',
            completed_at: new Date().toISOString(),
            resolved_by_admin: true
        }).eq('id', matchId);

        // FIX: Audit log — log errors instead of silently swallowing them
        const { error: auditErr } = await supabaseAdmin.from('admin_audit_log').insert([{
            action: 'resolve_dispute',
            match_id: matchId,
            winner_id: winnerId,
            admin_ip: req.ip || req.headers['x-forwarded-for'],
            created_at: new Date().toISOString()
        }]);
        if (auditErr) console.error('⚠️  Audit log insert failed (resolve_dispute):', auditErr.message);

        res.json({ message: 'Dispute resolved. Winner has been paid.', winnerId, prizePaid: match.winner_prize });
    } catch (err) {
        console.error('Resolve dispute error:', err);
        res.status(500).json({ error: 'Failed to resolve dispute' });
    }
});

// ============================================================
// ADMIN ANALYTICS ENDPOINT
// ============================================================
app.get('/admin/analytics', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });

        const now = new Date();
        const startOfToday    = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
        const startOfMonth    = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const startOfLastMonth= new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString();
        const endOfLastMonth  = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59).toISOString();
        const thirtyDaysAgo   = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        const sevenDaysAgo    = new Date(Date.now() -  7 * 24 * 60 * 60 * 1000).toISOString();

        const [
            allMatchesRes,
            mtdMatchesRes,
            lastMonthMatchesRes,
            allWithdrawalsRes,
            mtdWithdrawalsRes,
            pendingWithdrawalsRes,
            allUsersRes,
            newUsersTodayRes,
            newUsersMtdRes,
            walletTotalsRes,
            tournamentStatsRes,
            dailyVolumeRes,
        ] = await Promise.all([
            supabaseAdmin.from('friend_matches')
                .select('wager_amount, winner_prize, platform_fee, completed_at, status, settlement_method, started_at, created_at')
                .eq('status', 'completed'),
            supabaseAdmin.from('friend_matches')
                .select('wager_amount, winner_prize, platform_fee, settlement_method')
                .eq('status', 'completed')
                .gte('completed_at', startOfMonth),
            supabaseAdmin.from('friend_matches')
                .select('wager_amount, platform_fee')
                .eq('status', 'completed')
                .gte('completed_at', startOfLastMonth)
                .lte('completed_at', endOfLastMonth),
            supabaseAdmin.from('withdrawals')
                .select('amount, status, requested_at, processed_at, created_at'),
            supabaseAdmin.from('withdrawals')
                .select('amount, status')
                .gte('created_at', startOfMonth),
            supabaseAdmin.from('withdrawals')
                .select('amount, id')
                .eq('status', 'pending'),
            supabaseAdmin.from('profiles')
                .select('id, created_at'),
            supabaseAdmin.from('profiles')
                .select('id', { count: 'exact', head: true })
                .gte('created_at', startOfToday),
            supabaseAdmin.from('profiles')
                .select('id', { count: 'exact', head: true })
                .gte('created_at', startOfMonth),
            supabaseAdmin.from('wallets')
                .select('balance'),
            supabaseAdmin.from('tournaments')
                .select('id, status, entry_fee, max_players'),
            supabaseAdmin.from('friend_matches')
                .select('wager_amount, platform_fee, completed_at')
                .eq('status', 'completed')
                .gte('completed_at', thirtyDaysAgo)
                .order('completed_at', { ascending: true }),
        ]);

        const allMatches = allMatchesRes.data || [];
        const completedMatches = allMatches.filter(m => m.status === 'completed');
        const allTimeVolume   = completedMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const allTimeFees     = completedMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);
        const avgWager        = completedMatches.length > 0
            ? completedMatches.reduce((s, m) => s + parseFloat(m.wager_amount), 0) / completedMatches.length
            : 0;

        const settlementBreakdown = completedMatches.reduce((acc, m) => {
            const method = m.settlement_method || 'manual';
            acc[method] = (acc[method] || 0) + 1;
            return acc;
        }, {});

        const mtdMatches  = mtdMatchesRes.data || [];
        const mtdVolume   = mtdMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const mtdFees     = mtdMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);

        const lastMonthMatches = lastMonthMatchesRes.data || [];
        const lastMonthVolume  = lastMonthMatches.reduce((s, m) => s + (parseFloat(m.wager_amount) * 2), 0);
        const lastMonthFees    = lastMonthMatches.reduce((s, m) => s + parseFloat(m.platform_fee || 0), 0);

        const volumeGrowth = lastMonthVolume > 0
            ? (((mtdVolume - lastMonthVolume) / lastMonthVolume) * 100).toFixed(1)
            : null;
        const feesGrowth = lastMonthFees > 0
            ? (((mtdFees - lastMonthFees) / lastMonthFees) * 100).toFixed(1)
            : null;

        const allFriendMatchesForDisputeRes = await supabaseAdmin
            .from('friend_matches')
            .select('status', { count: 'exact' })
            .in('status', ['disputed', 'completed', 'active', 'cancelled', 'expired', 'penalty_shootout']);
        const allFriendMatchesForDispute = allFriendMatchesForDisputeRes.data || [];
        const totalFinishedMatches = allFriendMatchesForDispute.length;
        const disputedCount = allFriendMatchesForDispute.filter(m => m.status === 'disputed').length;
        const disputeRate = totalFinishedMatches > 0
            ? ((disputedCount / totalFinishedMatches) * 100).toFixed(1)
            : 0;

        const allWithdrawals = allWithdrawalsRes.data || [];
        const completedWithdrawals = allWithdrawals.filter(w => ['paid', 'completed'].includes(w.status));
        const allTimeWithdrawalVolume = completedWithdrawals.reduce((s, w) => s + parseFloat(w.amount), 0);

        const mtdWithdrawals = mtdWithdrawalsRes.data || [];
        const mtdWithdrawalVolume = mtdWithdrawals
            .filter(w => ['paid', 'completed'].includes(w.status))
            .reduce((s, w) => s + parseFloat(w.amount), 0);

        const pendingWithdrawals = pendingWithdrawalsRes.data || [];
        const pendingWithdrawalCount  = pendingWithdrawals.length;
        const pendingWithdrawalVolume = pendingWithdrawals.reduce((s, w) => s + parseFloat(w.amount), 0);

        const processedWithdrawals = allWithdrawals.filter(w =>
            ['paid', 'completed'].includes(w.status) && w.requested_at && w.processed_at
        );
        const avgProcessingHours = processedWithdrawals.length > 0
            ? processedWithdrawals.reduce((s, w) => {
                return s + (new Date(w.processed_at) - new Date(w.requested_at)) / (1000 * 60 * 60);
              }, 0) / processedWithdrawals.length
            : null;

        const allUsers    = allUsersRes.data || [];
        const totalUsers  = allUsers.length;
        const newToday    = newUsersTodayRes.count || 0;
        const newMtd      = newUsersMtdRes.count    || 0;

        const activeUserRes = await supabaseAdmin
            .from('friend_matches')
            .select('creator_id, joiner_id')
            .gte('created_at', sevenDaysAgo)
            .not('joiner_id', 'is', null);
        const activeUserSet = new Set();
        (activeUserRes.data || []).forEach(m => {
            if (m.creator_id) activeUserSet.add(m.creator_id);
            if (m.joiner_id)  activeUserSet.add(m.joiner_id);
        });
        const dau7 = activeUserSet.size;

        const wallets = walletTotalsRes.data || [];
        const totalFloat = wallets.reduce((s, w) => s + parseFloat(w.balance || 0), 0);
        const walletsWithBalance = wallets.filter(w => parseFloat(w.balance) > 0).length;

        const tournaments = tournamentStatsRes.data || [];
        const activeTournaments = tournaments.filter(t => ['open', 'live'].includes(t.status)).length;
        const tourEstimatedPool = tournaments
            .filter(t => t.status === 'live')
            .reduce((s, t) => s + (parseFloat(t.entry_fee) * parseInt(t.max_players)), 0);

        const dailyVolumeData = dailyVolumeRes.data || [];
        const dailyMap = {};
        dailyVolumeData.forEach(m => {
            const day = m.completed_at.substring(0, 10);
            if (!dailyMap[day]) dailyMap[day] = { volume: 0, fees: 0, matches: 0 };
            dailyMap[day].volume  += parseFloat(m.wager_amount) * 2;
            dailyMap[day].fees    += parseFloat(m.platform_fee || 0);
            dailyMap[day].matches += 1;
        });
        const dailyChart = [];
        for (let i = 29; i >= 0; i--) {
            const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
            const key = d.toISOString().substring(0, 10);
            dailyChart.push({
                date: key,
                volume:  Math.round((dailyMap[key]?.volume  || 0) * 100) / 100,
                fees:    Math.round((dailyMap[key]?.fees    || 0) * 100) / 100,
                matches: dailyMap[key]?.matches || 0
            });
        }

        res.json({
            generatedAt: now.toISOString(),
            revenue: {
                allTimeFees:      Math.round(allTimeFees * 100) / 100,
                mtdFees:          Math.round(mtdFees * 100) / 100,
                lastMonthFees:    Math.round(lastMonthFees * 100) / 100,
                feesGrowthPct:    feesGrowth,
                allTimeVolume:    Math.round(allTimeVolume * 100) / 100,
                mtdVolume:        Math.round(mtdVolume * 100) / 100,
                lastMonthVolume:  Math.round(lastMonthVolume * 100) / 100,
                volumeGrowthPct:  volumeGrowth,
            },
            matches: {
                totalCompleted:    completedMatches.length,
                mtdCompleted:      mtdMatches.length,
                avgWager:          Math.round(avgWager * 100) / 100,
                disputeRate:       parseFloat(disputeRate),
                disputedCount,
                totalMatches:      totalFinishedMatches,
                settlementMethods: settlementBreakdown,
            },
            users: {
                total:           totalUsers,
                newToday,
                newMtd,
                active7Days:     dau7,
                walletsWithFunds: walletsWithBalance,
            },
            withdrawals: {
                allTimeVolume:     Math.round(allTimeWithdrawalVolume * 100) / 100,
                mtdVolume:         Math.round(mtdWithdrawalVolume * 100) / 100,
                pendingCount:      pendingWithdrawalCount,
                pendingVolume:     Math.round(pendingWithdrawalVolume * 100) / 100,
                avgProcessingHrs:  avgProcessingHours !== null ? Math.round(avgProcessingHours * 10) / 10 : null,
            },
            platform: {
                totalFloat:        Math.round(totalFloat * 100) / 100,
                activeTournaments,
                livePoolValue:     Math.round(tourEstimatedPool * 100) / 100,
            },
            dailyChart,
        });

    } catch (err) {
        console.error('Analytics error:', err);
        res.status(500).json({ error: 'Failed to generate analytics' });
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
            console.warn('⚠️ Verifier unavailable - using manual score entry instead of OCR');
            // Skip OCR entirely - user will declare score manually
            return res.status(200).json({
                screenshotUrl: null,
                ocrResult: null,
                verificationResult: null,
                skipOCR: true,
                message: 'Screenshot service unavailable. Please declare your score manually instead.',
                instruction: 'Go back and select "Declare Score" to enter the final result manually.'
            });
        }

        // ✅ OPTIMIZATION 1: Parallelize database queries (saves 1-2s)
        // Instead of running queries one after another, run them simultaneously
        const opponentId = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        
        const [oppProfileResult, uploaderProfileResult] = await Promise.all([
            opponentId ? supabaseAdmin
                .from('profiles')
                .select('username')
                .eq('id', opponentId)
                .maybeSingle() : Promise.resolve({ data: null }),
            supabaseAdmin
                .from('profiles')
                .select('username')
                .eq('id', user.id)
                .maybeSingle()
        ]);

        const opponentUsername = oppProfileResult.data?.username || null;
        const uploaderUsername = uploaderProfileResult.data?.username || null;

        // ✅ OPTIMIZATION 2: Single OCR pass (saves 20-30s!)
        // Run OCR once via verifyScreenshot(), get all data back
        console.log('🔍 Running screenshot verification (OCR + fraud checks)...');
        const startVerification = Date.now();

        // ⏱️ Add timeout wrapper: max 35 seconds total
        const verificationPromise = verifier.verifyScreenshot(imageBuffer, {
            userId: user.id,
            matchId,
            startedAt: match.started_at,
            opponentUsername,
            uploaderUsername,
            matchCode: match.match_code,
            creatorTeam: match.creator_team,
            joinerTeam: match.joiner_team
        });

        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Screenshot verification timeout (35s exceeded) - Please try again')), 35000)
        );

        let verificationResult;
        try {
            verificationResult = await Promise.race([verificationPromise, timeoutPromise]);
        } catch (timeoutErr) {
            console.error('⏱️ Verification timeout:', timeoutErr.message);
            // Instead of failing, allow manual score entry
            return res.status(200).json({
                screenshotUrl: null,
                ocrResult: null,
                verificationResult: null,
                skipOCR: true,
                message: 'Screenshot analysis took too long. Please declare your score manually instead.',
                instruction: 'Go back and select "Declare Score" to enter the final result manually.',
                retryable: true
            });
        }

        const verificationTime = Date.now() - startVerification;
        console.log(`✅ Verification complete in ${verificationTime}ms`);

        // ✅ OPTIMIZATION 3: Reuse OCR result from verification
        // DO NOT call extractScoreWithConfidence() again - that runs OCR a SECOND time!
        const ocrResult = {
            score1: verificationResult.extractedScores?.score1,
            score2: verificationResult.extractedScores?.score2,
            confidence: verificationResult.ocrConfidence,
            rawText: verificationResult.ocrText,
            isValid: verificationResult.extractedScores?.score1 !== undefined &&
                     verificationResult.extractedScores?.score2 !== undefined &&
                     verificationResult.ocrConfidence > 50
        };

        console.log(`📊 OCR Result: ${ocrResult.score1}-${ocrResult.score2} (${ocrResult.confidence}% confidence)`);

        // ⚠️ If OCR failed to extract score, redirect to manual entry
        if (!ocrResult.score1 || !ocrResult.score2 || ocrResult.confidence < 30) {
            console.warn(`⚠️ OCR could not extract score reliably (confidence: ${ocrResult.confidence}%) - redirecting to manual entry`);
            return res.status(200).json({
                screenshotUrl: null,
                ocrResult: null,
                verificationResult: null,
                skipOCR: true,
                message: 'Could not read the score from the screenshot clearly. Please declare your score manually instead.',
                instruction: 'Go back and select "Declare Score" to enter the final result manually.',
                ocrConfidence: ocrResult.confidence,
                suggestedFallback: true
            });
        }

        // Fraud checks
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
const host = '::'; // Required by Alwaysdata
const finalPort = process.env.PORT || 8100;

app.listen(finalPort, host, () => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log("========================================");
    console.log(`✅ Vumbua Game running on ${host}:${finalPort}`);
    console.log(`   Memory: ${memMB}MB`);
    console.log("========================================");
});