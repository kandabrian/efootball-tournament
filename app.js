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

// Strip /api prefix — frontend calls /api/auth/login, backend routes are /auth/login
app.use((req, res, next) => {
    if (req.url.startsWith('/api/')) req.url = req.url.slice(4);
    next();
});

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
// HTML pages loaded at startup
const HTML_INDEX = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vumbua — Kenya's #1 eFootball Arena</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon: #00ff41;
            --neon-dim: #00cc34;
            --neon-glow: rgba(0, 255, 65, 0.4);
            --bg: #060608;
            --card: rgba(17, 17, 22, 0.6);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f0f0f0;
            --muted: #888;
            --error: #ff4444;
            --error-bg: rgba(255, 68, 68, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            background: var(--bg); 
            color: var(--text); 
            font-family: 'Outfit', sans-serif; 
            min-height: 100vh; 
            overflow-x: hidden; 
            -webkit-font-smoothing: antialiased;
        }

        /* ── Background Animations ── */
        .pitch-bg {
            position: fixed; inset: 0; z-index: 0;
            background:
                radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,255,65,0.08) 0%, transparent 60%),
                radial-gradient(ellipse 60% 40% at 80% 110%, rgba(0,200,255,0.03) 0%, transparent 50%);
        }
        .pitch-lines {
            position: fixed; inset: 0; z-index: 0; opacity: 0.035;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px),
                repeating-linear-gradient(90deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px);
            animation: gridDrift 20s linear infinite;
        }
        @keyframes gridDrift { 0% { transform: translateY(0); } 100% { transform: translateY(80px); } }

        .page-wrap {
            position: relative; z-index: 1; min-height: 100vh;
            display: grid; grid-template-columns: 1.1fr 0.9fr;
        }

        /* ── Hero Section ── */
        .hero {
            display: flex; flex-direction: column; justify-content: center;
            padding: 60px 8%; position: relative; overflow: hidden;
        }
        .hero::after {
            content: ''; position: absolute; right: 0; top: 15%; bottom: 15%;
            width: 1px; background: linear-gradient(to bottom, transparent, rgba(0,255,65,0.2), transparent);
        }
        .logo {
            font-family: 'Bebas Neue', sans-serif; font-size: 3.8rem;
            letter-spacing: 6px; color: var(--neon);
            text-shadow: 0 0 40px var(--neon-glow);
            line-height: 1; animation: fadeUp 0.6s ease both;
        }
        .logo-tagline {
            font-size: 0.7rem; letter-spacing: 4px; color: var(--muted);
            text-transform: uppercase; margin-top: 8px; font-weight: 600;
            animation: fadeUp 0.6s 0.1s ease both;
        }
        .hero-headline {
            margin-top: 60px; font-family: 'Bebas Neue', sans-serif;
            font-size: 5.2rem; line-height: 0.95; letter-spacing: 2px;
            animation: fadeUp 0.6s 0.2s ease both;
        }
        .hero-headline span { color: var(--neon); text-shadow: 0 0 30px var(--neon-glow); }
        .hero-sub {
            margin-top: 24px; font-size: 1.05rem; color: #aaa;
            line-height: 1.6; max-width: 420px; font-weight: 300;
            animation: fadeUp 0.6s 0.3s ease both;
        }
        
        .stats-row {
            display: flex; gap: 45px; margin-top: 50px;
            animation: fadeUp 0.6s 0.4s ease both;
        }
        .stat { display: flex; flex-direction: column; }
        .stat-num { font-family: 'Bebas Neue', sans-serif; font-size: 2.5rem; color: var(--neon); line-height: 1; }
        .stat-label { font-size: 0.7rem; color: var(--muted); letter-spacing: 1.5px; text-transform: uppercase; margin-top: 6px; font-weight: 500;}
        
        .live-badge {
            display: inline-flex; align-items: center; gap: 8px;
            background: rgba(0,255,65,0.05); border: 1px solid rgba(0,255,65,0.2);
            backdrop-filter: blur(4px);
            border-radius: 30px; padding: 8px 18px; font-size: 0.8rem; color: var(--neon);
            margin-top: 45px; width: fit-content; font-weight: 500;
            animation: fadeUp 0.6s 0.5s ease both;
        }
        .live-dot { width: 8px; height: 8px; background: var(--neon); border-radius: 50%; animation: pulse 1.5s infinite; box-shadow: 0 0 10px var(--neon);}
        @keyframes pulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.4; transform:scale(0.7); } }

        /* ── Form Section ── */
        .form-panel {
            display: flex; flex-direction: column; justify-content: center;
            padding: 60px 10%; background: var(--card); backdrop-filter: blur(20px);
            border-left: 1px solid rgba(255,255,255,0.03);
            animation: fadeIn 0.8s 0.15s ease both;
        }
        .form-title { font-family: 'Bebas Neue', sans-serif; font-size: 2.5rem; letter-spacing: 2px; margin-bottom: 8px; }
        .form-subtitle { color: var(--muted); font-size: 0.95rem; margin-bottom: 35px; }

        .form-group { margin-bottom: 18px; }
        .form-group label {
            display: block; font-size: 0.7rem; letter-spacing: 1.5px;
            text-transform: uppercase; color: #aaa; margin-bottom: 8px; font-weight: 600;
        }
        .form-group input {
            width: 100%; background: rgba(0,0,0,0.4); border: 1px solid var(--border);
            color: var(--text); padding: 14px 18px; border-radius: 12px;
            font-size: 1rem; font-family: 'Outfit', sans-serif;
            transition: all 0.3s ease;
        }
        .form-group input:focus { 
            outline: none; 
            border-color: rgba(0,255,65,0.5); 
            box-shadow: 0 0 0 4px rgba(0,255,65,0.08); 
            background: rgba(0,0,0,0.6);
        }
        .form-group input::placeholder { color: #444; }

        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

        .checkbox-label {
            display: flex; align-items: center; gap: 12px;
            font-size: 0.85rem; color: #888; cursor: pointer; margin-top: 10px;
            transition: color 0.2s ease;
        }
        .checkbox-label:hover { color: #aaa; }
        .checkbox-label input[type="checkbox"] { 
            width: 18px; height: 18px; accent-color: var(--neon); 
            flex-shrink: 0; cursor: pointer;
        }

        .btn-primary {
            width: 100%; padding: 16px; margin-top: 24px;
            background: linear-gradient(135deg, var(--neon), var(--neon-dim)); 
            color: #000; border: none; border-radius: 12px;
            font-weight: 800; font-size: 0.95rem; letter-spacing: 2px; text-transform: uppercase;
            cursor: pointer; font-family: 'Outfit', sans-serif;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,255,65,0.2);
        }
        .btn-primary:hover:not(:disabled) { 
            transform: translateY(-2px); 
            box-shadow: 0 8px 25px rgba(0,255,65,0.35); 
            filter: brightness(1.1);
        }
        .btn-primary:active:not(:disabled) { transform: translateY(0); }
        .btn-primary:disabled { background: #333; color: #666; cursor: not-allowed; box-shadow: none; }

        .divider { display: flex; align-items: center; gap: 16px; margin: 24px 0; color: #444; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px;}
        .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }

        .switch-link { text-align: center; font-size: 0.9rem; color: var(--muted); }
        .switch-link a { color: var(--neon); text-decoration: none; font-weight: 600; transition: text-shadow 0.2s;}
        .switch-link a:hover { text-shadow: 0 0 10px var(--neon-glow); }

        .error-msg {
            background: var(--error-bg); border: 1px solid rgba(255,68,68,0.3);
            color: var(--error); padding: 12px 16px; border-radius: 10px;
            font-size: 0.85rem; margin-top: 16px; display: none; font-weight: 500;
            animation: slideDown 0.3s ease out;
        }

        .trust-row { display: flex; gap: 20px; margin-top: 35px; flex-wrap: wrap; justify-content: center;}
        .trust-badge { display: flex; align-items: center; gap: 8px; font-size: 0.75rem; color: #666; font-weight: 500;}
        .trust-badge svg { color: var(--neon); flex-shrink: 0; opacity: 0.8;}

        /* Animations */
        @keyframes fadeUp { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
        @keyframes slideDown { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
        @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }
        .shake { animation: shake 0.4s ease-in-out; }

        /* Mobile Adjustments */
        .mobile-header { display: none; text-align: center; margin-bottom: 35px; }
        .mobile-header .logo { font-size: 3.2rem; display: block; }
        .mobile-header .logo-tagline { margin-top: 6px; display: block; }

        @media (max-width: 900px) {
            .page-wrap { grid-template-columns: 1fr; }
            .hero { display: none; }
            .form-panel { 
                padding: 50px 6%; 
                min-height: 100vh; 
                justify-content: flex-start; 
                background: transparent; 
                backdrop-filter: none;
                border: none;
            }
            .mobile-header { display: block; }
            .form-row { grid-template-columns: 1fr; gap: 0; }
            .trust-row { justify-content: flex-start; }
        }
    </style>
</head>
<body>
<div class="pitch-bg"></div>
<div class="pitch-lines"></div>

<div class="page-wrap">
    <div class="hero">
        <div class="logo">VUMBUA</div>
        <div class="logo-tagline">Kenya's eFootball Arena</div>
        <div class="hero-headline">CHEZA.<br><span>SHINDA.</span><br>PATA PESA.</div>
        <p class="hero-sub">Piga challenge marafiki wako, ingia tournaments za wiki, na pokea pesa moja kwa moja kwa M-PESA. Real money. Real matches. Real respect.</p>
        
        <div class="stats-row">
            <div class="stat"><span class="stat-num">12K+</span><span class="stat-label">Players</span></div>
            <div class="stat"><span class="stat-num">KES 2M</span><span class="stat-label">Paid Out</span></div>
            <div class="stat"><span class="stat-num">50+</span><span class="stat-label">Tournaments</span></div>
        </div>
        
        <div class="live-badge"><div class="live-dot"></div> 3 Tournaments Live Now</div>
    </div>

    <div class="form-panel">
        <div class="mobile-header">
            <span class="logo">VUMBUA</span>
            <span class="logo-tagline">Kenya's eFootball Arena</span>
        </div>

        <div class="form-title">JIUNGE SASA</div>
        <p class="form-subtitle">Create your account — it takes 30 seconds.</p>

        <form id="signup-form" autocomplete="off">
            <div class="form-group">
                <label for="phone">Phone Number (M-PESA)</label>
                <input type="tel" id="phone" placeholder="0712 345 678" required>
            </div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" placeholder="eFootball_King254" required>
            </div>
            <!-- NEW: Team Name Field -->
            <div class="form-group">
                <label for="team">Your eFootball Team Name</label>
                <input type="text" id="team" placeholder="e.g., Manchester United" required>
            </div>
            
            <div class="form-row">
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" placeholder="••••••••" minlength="6" required>
                </div>
                <div class="form-group">
                    <label for="confirm-password">Confirm Password</label>
                    <input type="password" id="confirm-password" placeholder="••••••••" required>
                </div>
            </div>
            
            <label class="checkbox-label">
                <input type="checkbox" id="terms" required>
                Nakubali masharti &amp; Nina umri wa miaka 18+
            </label>
            
            <div class="error-msg" id="error-msg"></div>
            
            <button type="submit" class="btn-primary" id="submit-btn">Ingia Uwanjani →</button>
        </form>

        <div class="divider">au</div>
        <div class="switch-link">Una akaunti? <a href="/login">Login hapa</a></div>

        <div class="trust-row">
            <div class="trust-badge">
                <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Secure &amp; Encrypted
            </div>
            <div class="trust-badge">
                <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>
                M-PESA Payouts
            </div>
            <div class="trust-badge">
                <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                Instant Withdrawals
            </div>
        </div>
    </div>
</div>

<script>
    // Escape function to prevent XSS
    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Auto-detect: Use localhost for local dev, Koyeb URL for production
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const API = isLocal 
        ? 'http://localhost:3000' 
        : '/api';
    
    console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
    console.log('🔍 API URL:', API);

    // Redirect if already logged in
    if (sessionStorage.getItem('supabaseToken')) {
        window.location.href = '/dashboard';
    }

    const form = document.getElementById('signup-form');
    const errorEl = document.getElementById('error-msg');
    const btn = document.getElementById('submit-btn');

    function showError(msg) { 
        errorEl.textContent = escapeHtml(msg); 
        errorEl.style.display = 'block'; 
        errorEl.classList.remove('shake');
        void errorEl.offsetWidth; // trigger reflow
        errorEl.classList.add('shake');
    }
    
    function hideError() { 
        errorEl.style.display = 'none'; 
        errorEl.classList.remove('shake');
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault(); 
        hideError();

        const rawPhone = document.getElementById('phone').value;
        const username = document.getElementById('username').value.trim();
        const teamName = document.getElementById('team').value.trim();  // NEW
        const password = document.getElementById('password').value;
        const confirm = document.getElementById('confirm-password').value;

        if (password !== confirm) return showError("Passwords do not match. Tafadhali rudia.");
        if (password.length < 6) return showError("Password must be at least 6 characters.");
        if (!teamName) return showError("Team name is required.");  // NEW validation
        if (teamName.length < 3) return showError("Team name must be at least 3 characters.");  // NEW

        // Phone formatting
        let cleanPhone = rawPhone.replace(/\\s+/g, '');
        if (cleanPhone.startsWith('+')) cleanPhone = cleanPhone.substring(1);
        if (cleanPhone.startsWith('0')) {
            cleanPhone = '254' + cleanPhone.substring(1);
        } else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) {
            cleanPhone = '254' + cleanPhone;
        }
        if (!/^254[17]\\d{8}$/.test(cleanPhone)) {
            return showError("Weka namba ya simu sahihi (e.g., 0712345678).");
        }
        cleanPhone = '+' + cleanPhone;

        btn.disabled = true; 
        btn.textContent = 'Inaload...';

        try {
            const res = await fetch(\`\${API}/auth/signup\`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    phone: cleanPhone, 
                    password, 
                    username,
                    teamName  // NEW: send team name
                })
            });

            const result = await res.json();

            if (res.ok) {
                if (result.session) {
                    sessionStorage.setItem('supabaseToken', result.session.access_token);
                    sessionStorage.setItem('supabaseUser', JSON.stringify(result.session.user));
                    window.location.href = '/dashboard';
                } else {
                    window.location.href = '/login';
                }
            } else { 
                showError(result.error || 'Kuna shida kidogo. Please try again.'); 
            }
        } catch (err) { 
            showError('Network error. Check connection yako ya internet.'); 
        } finally { 
            btn.disabled = false; 
            btn.textContent = 'Ingia Uwanjani →'; 
        }
    });
</script>

<footer style="position:relative;z-index:1;margin-top:50px;padding:24px 20px;border-top:1px solid rgba(255,255,255,0.08);text-align:center;font-family:'Outfit',sans-serif;">
    <p style="color:#ccc;font-size:0.85rem;line-height:1.6;max-width:600px;margin:0 auto 10px;">
        <strong>Vumbua eFootball</strong> is a skill-based eSports management platform. We facilitate competitive gaming tournaments and community matches.
        <strong>This platform does not offer betting, gambling, or lottery services.</strong>
    </p>
    <p style="color:#666;font-size:0.75rem;">Proprietor: Brian Toroitich Kipyatich &nbsp;|&nbsp; Contact: <a href="/cdn-cgi/l/email-protection" class="__cf_email__" `;

const HTML_LOGIN = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | Vumbua eFootball [v2.1-FIXED]</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon: #00ff41;
            --neon-dim: #00cc34;
            --neon-glow: rgba(0, 255, 65, 0.35);
            --bg: #060608;
            --card: rgba(17, 17, 22, 0.7);
            --border: rgba(255, 255, 255, 0.08);
            --text: #f0f0f0;
            --muted: #888;
            --error: #ff4444;
            --error-bg: rgba(255, 68, 68, 0.1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: var(--bg); color: var(--text); font-family: 'Outfit', sans-serif;
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            padding: 24px; overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }

        /* ── Background Elements ── */
        .pitch-bg {
            position: fixed; inset: 0; z-index: 0;
            background: radial-gradient(circle at 50% 50%, rgba(0,255,65,0.07) 0%, transparent 70%);
        }
        .pitch-lines {
            position: fixed; inset: 0; z-index: 0; opacity: 0.035;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px),
                repeating-linear-gradient(90deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px);
            animation: gridDrift 20s linear infinite;
        }
        @keyframes gridDrift { 0% { transform: translateY(0); } 100% { transform: translateY(80px); } }

        /* ── Login Card ── */
        .login-card {
            position: relative; z-index: 1;
            background: var(--card); 
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 24px; padding: 50px 40px;
            width: 100%; max-width: 420px;
            box-shadow: 0 40px 100px rgba(0,0,0,0.8);
            animation: cardIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
        }

        /* Neon Top Accent */
        .login-card::before {
            content: ''; position: absolute; top: -1px; left: 40px; right: 40px; height: 2px;
            background: linear-gradient(90deg, transparent, var(--neon), transparent);
            filter: drop-shadow(0 0 8px var(--neon));
        }

        @keyframes cardIn { 
            from { opacity:0; transform:translateY(30px) scale(0.97); } 
            to { opacity:1; transform:translateY(0) scale(1); } 
        }

        .card-header { text-align: center; margin-bottom: 35px; }
        .card-logo {
            font-family: 'Bebas Neue', sans-serif; font-size: 2.8rem;
            letter-spacing: 6px; color: var(--neon);
            text-shadow: 0 0 30px var(--neon-glow);
            line-height: 1; display: block;
        }
        .card-logo-sub {
            font-size: 0.7rem; color: var(--muted);
            letter-spacing: 4px; text-transform: uppercase; margin-top: 8px; font-weight: 600;
        }

        .form-title { font-family: 'Bebas Neue', sans-serif; font-size: 2rem; letter-spacing: 2px; margin-bottom: 6px; }
        .form-subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 28px; font-weight: 300; }

        .form-group { margin-bottom: 20px; position: relative; }
        .form-group label {
            display: block; font-size: 0.7rem; letter-spacing: 1.5px;
            text-transform: uppercase; color: #aaa; margin-bottom: 8px; font-weight: 600;
        }
        .form-group input {
            width: 100%; background: rgba(0,0,0,0.4); border: 1px solid var(--border);
            color: var(--text); padding: 14px 18px; border-radius: 12px;
            font-size: 1rem; font-family: 'Outfit', sans-serif;
            transition: all 0.3s ease;
        }
        .form-group input:focus { 
            outline: none; border-color: rgba(0,255,65,0.5); 
            box-shadow: 0 0 0 4px rgba(0,255,65,0.08); 
            background: rgba(0,0,0,0.6);
        }

        .forgot-link {
            position: absolute; right: 0; top: 0;
            font-size: 0.7rem; color: var(--neon); text-decoration: none;
            text-transform: uppercase; letter-spacing: 1px; font-weight: 600;
            opacity: 0.8; transition: opacity 0.2s;
        }
        .forgot-link:hover { opacity: 1; text-shadow: 0 0 8px var(--neon-glow); }

        .btn-primary {
            width: 100%; padding: 16px; margin-top: 10px;
            background: linear-gradient(135deg, var(--neon), var(--neon-dim)); 
            color: #000; border: none; border-radius: 12px;
            font-weight: 800; font-size: 0.95rem; letter-spacing: 2px; text-transform: uppercase;
            cursor: pointer; font-family: 'Outfit', sans-serif;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,255,65,0.2);
        }
        .btn-primary:hover:not(:disabled) { 
            transform: translateY(-2px); 
            box-shadow: 0 8px 25px rgba(0,255,65,0.35); 
            filter: brightness(1.1);
        }
        .btn-primary:disabled { background: #333; color: #666; cursor: not-allowed; }

        .divider { display: flex; align-items: center; gap: 16px; margin: 26px 0; color: #444; font-size: 0.8rem; text-transform: uppercase; }
        .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }

        .switch-link { text-align: center; font-size: 0.9rem; color: var(--muted); }
        .switch-link a { color: var(--neon); text-decoration: none; font-weight: 600; transition: 0.2s; }
        .switch-link a:hover { text-shadow: 0 0 10px var(--neon-glow); text-decoration: underline; }

        .error-msg {
            background: var(--error-bg); border: 1px solid rgba(255,68,68,0.3);
            color: var(--error); padding: 12px 16px; border-radius: 10px;
            font-size: 0.85rem; margin-bottom: 18px; display: none; font-weight: 500;
        }

        /* Animations */
        @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-6px); } 75% { transform: translateX(6px); } }
        .shake { animation: shake 0.4s ease-in-out; }

        @media (max-width: 480px) {
            .login-card { padding: 40px 24px; border-radius: 0; border: none; background: transparent; box-shadow: none; backdrop-filter: none;}
            .login-card::before { display: none; }
        }
    </style>
</head>
<body>
<div class="pitch-bg"></div>
<div class="pitch-lines"></div>

<div class="login-card">
    <div class="card-header">
        <span class="card-logo">VUMBUA</span>
        <span class="card-logo-sub">Kenya's eFootball Arena</span>
    </div>

    <div class="form-title">KARIBU TENA</div>
    <p class="form-subtitle">Login to enter the arena.</p>

    <form id="login-form">
        <div class="error-msg" id="error-msg"></div>

        <div class="form-group">
            <label for="login-phone">Phone Number</label>
            <input type="tel" id="login-phone" placeholder="0712 345 678" required autocomplete="username">
        </div>

        <div class="form-group">
            <label for="login-password">Password</label>
            <a href="/forgot-password" class="forgot-link">Umesahau?</a>
            <input type="password" id="login-password" placeholder="••••••••" required autocomplete="current-password">
        </div>

        <button type="submit" class="btn-primary" id="submit-btn">Enter Uwanja →</button>
    </form>

    <div class="divider">au</div>
    <div class="switch-link">Bado haujajisajili? <a href="/">Jiunge sasa</a></div>
</div>

<script>
    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Auto-detect: Use localhost for local dev, Koyeb URL for production
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const API = isLocal 
        ? 'http://localhost:3000' 
        : '/api';
    
    // Debug: Log API URL to console
    console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
    console.log('🔍 API URL:', API);

    // Redirect if session exists
    if (sessionStorage.getItem('supabaseToken')) { 
        window.location.href = '/dashboard'; 
    }

    const errorEl = document.getElementById('error-msg');
    const btn = document.getElementById('submit-btn');

    function showError(msg) { 
        errorEl.textContent = escapeHtml(msg); 
        errorEl.style.display = 'block';
        errorEl.classList.remove('shake');
        void errorEl.offsetWidth;
        errorEl.classList.add('shake');
    }

    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        errorEl.style.display = 'none';

        const phone = document.getElementById('login-phone').value.trim();
        const password = document.getElementById('login-password').value;

        // Format phone
        let cleanPhone = phone.replace(/\\s+/g, '');
        if (cleanPhone.startsWith('+')) cleanPhone = cleanPhone.substring(1);
        if (cleanPhone.startsWith('0')) {
            cleanPhone = '254' + cleanPhone.substring(1);
        } else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) {
            cleanPhone = '254' + cleanPhone;
        }
        if (!/^254[17]\\d{8}$/.test(cleanPhone)) {
            return showError("Namba ya simu si sahihi.");
        }
        cleanPhone = '+' + cleanPhone;

        btn.disabled = true; 
        btn.textContent = 'Inaload...';

        try {
            const res = await fetch(\`\${API}/auth/login\`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ phone: cleanPhone, password })
            });

            const result = await res.json();

            if (res.ok) {
                sessionStorage.setItem('supabaseToken', result.session.access_token);
                sessionStorage.setItem('supabaseUser', JSON.stringify(result.session.user));
                window.location.href = '/dashboard';
            } else {
                showError(result.error || 'Namba ya simu au password si sahihi.');
            }
        } catch (err) { 
            showError('Network error. Check connection yako.'); 
        } finally { 
            btn.disabled = false; 
            btn.textContent = 'Enter Uwanja →'; 
        }
    });
</script>
</body>
</html>`;

const HTML_DASHBOARD = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="theme-color" content="#050507">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vumbua — eFootball Wagers</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚽</text></svg>">
    <!-- Production-ready CSP -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https://wqnnuqudxsnxldlgxhwr.supabase.co wss://wqnnuqudxsnxldlgxhwr.supabase.co;">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        /* ... (all your existing styles remain exactly as before) ... */
        :root {
            --neon: #00ff41;
            --neon-dim: rgba(0,255,65,0.08);
            --neon-glow: rgba(0,255,65,0.15);
            --bg: #050507;
            --surface: #0a0a0e;
            --card: #0f0f14;
            --card2: #14141a;
            --border: rgba(255,255,255,0.07);
            --border-strong: rgba(255,255,255,0.12);
            --text: #f0f0f0;
            --muted: #55556a;
            --danger: #ff4455;
            --gold: #ffd700;
            --radius-card: 20px;
            --radius-btn: 14px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--bg); color: var(--text); font-family: 'Outfit', sans-serif; min-height: 100vh; overflow-x: hidden; }
        #loading-screen {
            position: fixed; inset: 0; z-index: 1000; background: var(--bg);
            display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px;
        }
        .spinner {
            width: 32px; height: 32px; border: 2px solid rgba(0,255,65,0.1);
            border-top-color: var(--neon); border-radius: 50%; animation: spin 0.8s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-text { font-size: 0.75rem; letter-spacing: 3px; color: var(--muted); text-transform: uppercase; }
        .pitch-bg {
            position: fixed; inset: 0; z-index: 0;
            background:
                radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,255,65,0.04) 0%, transparent 60%),
                radial-gradient(ellipse 40% 30% at 90% 80%, rgba(0,200,50,0.02) 0%, transparent 50%);
        }
        .pitch-lines {
            position: fixed; inset: 0; z-index: 0; opacity: 0.018;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px),
                repeating-linear-gradient(90deg, transparent, transparent 79px, rgba(0,255,65,0.8) 80px);
            animation: gridDrift 30s linear infinite;
        }
        @keyframes gridDrift { 0% { transform: translateY(0); } 100% { transform: translateY(80px); } }
        .noise-overlay {
            position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: 0.025;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='1'/%3E%3C/svg%3E");
            background-size: 200px;
        }
        .app {
            position: relative; z-index: 1; max-width: 480px; margin: 0 auto;
            padding: 0 0 80px 0; min-height: 100vh;
            animation: fadeIn 0.5s ease both;
        }
        @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
        .topnav {
            display: flex; align-items: center; justify-content: space-between;
            padding: 18px 20px 14px;
            position: sticky; top: 0; z-index: 10;
            background: linear-gradient(to bottom, rgba(5,5,7,0.98) 60%, transparent);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
        }
        .nav-logo { font-family: 'Bebas Neue', sans-serif; font-size: 1.8rem; letter-spacing: 4px; color: var(--neon); }
        .nav-right { display: flex; align-items: center; gap: 10px; }
        .nav-user {
            display: flex; align-items: center; gap: 8px;
            background: var(--card); border: 1px solid var(--border);
            padding: 7px 14px; border-radius: 20px;
            cursor: pointer;
        }
        .avatar {
            width: 26px; height: 26px; border-radius: 50%;
            background: var(--neon); color: #000; display: flex; align-items: center;
            justify-content: center; font-size: 0.7rem; font-weight: 800;
        }
        .nav-username { font-size: 0.82rem; color: var(--neon); font-weight: 600; }
        .btn-logout {
            background: none; border: 1px solid var(--border); color: var(--muted);
            padding: 7px 12px; border-radius: 20px; cursor: pointer; font-size: 0.75rem;
            font-family: 'Outfit', sans-serif; transition: border-color 0.2s, color 0.2s;
        }
        .btn-logout:hover { border-color: rgba(255,68,68,0.4); color: #ff8888; }
        .content { padding: 0 16px; }
        .wallet-card {
            background: linear-gradient(145deg, #0c1410 0%, #0a1209 50%, #0f1a0e 100%);
            border: 1px solid rgba(0,255,65,0.2);
            border-radius: 24px; padding: 28px 28px 24px;
            position: relative; overflow: hidden;
            box-shadow: 0 24px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,255,65,0.05), inset 0 1px 0 rgba(0,255,65,0.12);
            margin-bottom: 20px;
            animation: slideUp 0.5s 0.1s ease both;
        }
        @keyframes slideUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        .wallet-card::before {
            content: ''; position: absolute; top: -60px; right: -60px;
            width: 200px; height: 200px; border-radius: 50%;
            background: radial-gradient(circle, rgba(0,255,65,0.08) 0%, transparent 70%);
        }
        .wallet-card::after {
            content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(to right, transparent, rgba(0,255,65,0.2), transparent);
        }
        .wallet-label {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.65rem; letter-spacing: 3px; text-transform: uppercase; color: #555; margin-bottom: 10px;
        }
        .realtime-indicator {
            font-size: 0.6rem;
            color: var(--neon);
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .realtime-indicator .dot {
            width: 8px;
            height: 8px;
            background: var(--neon);
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        .wallet-amount {
            font-family: 'Bebas Neue', sans-serif; font-size: 4rem;
            color: var(--neon); line-height: 1;
            text-shadow: 0 0 40px rgba(0,255,65,0.4), 0 0 80px rgba(0,255,65,0.15);
            letter-spacing: 1px;
        }
        .wallet-currency { font-size: 1.5rem; opacity: 0.6; margin-right: 4px; }
        .wallet-meta { margin-top: 16px; display: flex; justify-content: space-between; align-items: flex-end; }
        .wallet-phone { font-size: 0.72rem; color: #444; }
        .wallet-phone span { color: #666; }
        .wallet-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 28px; animation: slideUp 0.5s 0.15s ease both; }
        .btn-action {
            padding: 15px; border-radius: var(--radius-btn); border: none; font-weight: 700;
            font-size: 0.85rem; letter-spacing: 1.5px; cursor: pointer; font-family: 'Outfit', sans-serif;
            transition: transform 0.2s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.2s, opacity 0.15s;
            display: flex; align-items: center; justify-content: center; gap: 8px;
            text-transform: uppercase;
        }
        .btn-action:hover { transform: translateY(-2px); }
        .btn-action:active { transform: translateY(0); opacity: 0.85; }
        .btn-deposit { background: var(--neon); color: #000; box-shadow: 0 6px 20px rgba(0,255,65,0.25); }
        .btn-deposit:hover { box-shadow: 0 12px 35px rgba(0,255,65,0.45); transform: translateY(-3px); }
        .btn-withdraw { background: var(--card2); color: var(--text); border: 1px solid var(--border); }
        .section-header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 14px; animation: slideUp 0.5s 0.2s ease both;
        }
        .section-title {
            font-family: 'Bebas Neue', sans-serif; font-size: 1.3rem;
            letter-spacing: 3px; color: #e0e0e0;
        }
        .section-link { font-size: 0.78rem; color: var(--neon); cursor: pointer; font-weight: 500; }
        .quick-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 28px; animation: slideUp 0.5s 0.25s ease both; }
        .quick-card {
            background: var(--card); border: 1px solid var(--border);
            border-radius: 18px; padding: 20px 12px; text-align: center;
            cursor: pointer; transition: border-color 0.25s, transform 0.25s, background 0.25s, box-shadow 0.25s;
            position: relative; overflow: hidden;
        }
        .quick-card::before {
            content: ''; position: absolute; inset: 0;
            background: radial-gradient(circle at 50% 0%, rgba(0,255,65,0.06) 0%, transparent 70%);
            opacity: 0; transition: opacity 0.3s;
        }
        .quick-card:hover { border-color: rgba(0,255,65,0.35); transform: translateY(-3px); background: #121218; box-shadow: 0 12px 30px rgba(0,0,0,0.4); }
        .quick-card:hover::before { opacity: 1; }
        .quick-icon { font-size: 1.5rem; margin-bottom: 8px; display: block; }
        .quick-label { font-size: 0.72rem; font-weight: 600; color: #ccc; letter-spacing: 0.5px; }
        .tournaments { animation: slideUp 0.5s 0.3s ease both; margin-bottom: 28px; }
        .tournament-card {
            background: var(--card); border: 1px solid var(--border);
            border-radius: 20px; padding: 20px; margin-bottom: 12px;
            cursor: pointer; transition: border-color 0.25s, transform 0.25s, box-shadow 0.25s;
            position: relative; overflow: hidden;
        }
        .tournament-card:hover { border-color: rgba(0,255,65,0.3); transform: translateY(-2px); box-shadow: 0 16px 40px rgba(0,0,0,0.4); }
        .tournament-card.live::before {
            content: ''; position: absolute; left: 0; top: 0; bottom: 0;
            width: 3px; background: var(--neon);
            box-shadow: 0 0 10px rgba(0,255,65,0.5);
        }
        .t-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
        .t-badge {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 4px 10px; border-radius: 20px; font-size: 0.65rem;
            font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
        }
        .t-badge.live-badge { background: rgba(0,255,65,0.1); color: var(--neon); border: 1px solid rgba(0,255,65,0.2); }
        .t-badge.soon-badge { background: rgba(255,180,0,0.1); color: #ffb400; border: 1px solid rgba(255,180,0,0.2); }
        .live-pip { width: 6px; height: 6px; background: var(--neon); border-radius: 50%; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.3;} }
        .t-name { font-weight: 700; font-size: 1rem; margin-bottom: 4px; }
        .t-meta { font-size: 0.78rem; color: var(--muted); }
        .t-footer { display: flex; justify-content: space-between; align-items: center; }
        .t-prize { font-family: 'Bebas Neue', sans-serif; font-size: 1.4rem; color: var(--neon); letter-spacing: 1px; }
        .t-prize small { font-family: 'Outfit', sans-serif; font-size: 0.65rem; color: var(--muted); font-weight: 400; display: block; letter-spacing: 0; margin-bottom: 1px; }
        .t-players { font-size: 0.75rem; color: var(--muted); display: flex; align-items: center; gap: 5px; }
        .progress-bar { height: 4px; background: rgba(255,255,255,0.06); border-radius: 4px; margin-top: 12px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--neon); border-radius: 4px; transition: width 0.5s ease; }
        .btn-join {
            padding: 9px 20px; border-radius: 10px; background: var(--neon); color: #000;
            border: none; font-weight: 700; font-size: 0.78rem; cursor: pointer;
            font-family: 'Outfit', sans-serif; letter-spacing: 1px;
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .btn-join:hover { transform: translateY(-1px); box-shadow: 0 5px 15px rgba(0,255,65,0.3); }
        .friend-section { animation: slideUp 0.5s 0.35s ease both; margin-bottom: 24px; }
        .friend-card {
            background: var(--card); border: 1px solid var(--border);
            border-radius: 22px; padding: 22px;
        }
        .friend-buttons {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 16px;
        }
        .btn-friend {
            padding: 14px;
            border-radius: 14px;
            border: none;
            font-weight: 700;
            font-size: 0.85rem;
            cursor: pointer;
            font-family: 'Outfit', sans-serif;
            transition: transform 0.15s, box-shadow 0.15s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .btn-friend:hover { transform: translateY(-2px); }
        .btn-friend-create {
            background: var(--neon);
            color: #000;
            box-shadow: 0 6px 20px rgba(0,255,65,0.2);
        }
        .btn-friend-create:hover { box-shadow: 0 10px 30px rgba(0,255,65,0.35); }
        .btn-friend-join {
            background: var(--card2);
            color: var(--text);
            border: 1px solid var(--border);
        }
        .friend-info {
            background: rgba(0,255,65,0.05);
            border: 1px solid rgba(0,255,65,0.1);
            border-radius: 12px;
            padding: 14px;
            font-size: 0.75rem;
            color: #aaa;
            line-height: 1.6;
        }
        .my-matches-section { margin-top: 24px; }
        .match-item {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 18px;
            margin-bottom: 12px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .match-item:hover { border-color: var(--border-strong); box-shadow: 0 8px 24px rgba(0,0,0,0.3); }
        .match-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .match-code {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 1.2rem;
            letter-spacing: 2px;
            color: var(--neon);
        }
        .match-status {
            font-size: 0.7rem;
            padding: 4px 10px;
            border-radius: 20px;
            background: rgba(255,180,0,0.1);
            color: #ffb400;
            text-transform: uppercase;
        }
        .match-detail {
            font-size: 0.85rem;
            color: #aaa;
            margin: 4px 0;
        }
        /* Confirmation countdown cards */
        .confirm-countdown {
            border-radius: 10px;
            padding: 10px 14px;
            font-size: 0.82rem;
        }
        .confirm-countdown.waiting {
            background: rgba(255,180,0,0.07);
            border: 1px solid rgba(255,180,0,0.2);
        }
        .confirm-countdown.urgent {
            background: rgba(255,68,68,0.07);
            border: 1px solid rgba(255,68,68,0.25);
        }
        .match-actions {
            margin-top: 12px;
            display: flex;
            gap: 8px;
        }
        .profile-modal .modal-sheet { max-width: 400px; }
        .profile-field { margin-bottom: 16px; }
        .profile-field label { display: block; font-size: 0.7rem; letter-spacing: 1.5px; text-transform: uppercase; color: #aaa; margin-bottom: 6px; }
        .profile-field input { width: 100%; background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 12px; border-radius: 10px; }
        .modal-overlay {
            position: fixed; inset: 0; z-index: 500;
            background: rgba(0,0,0,0.75); backdrop-filter: blur(6px);
            display: flex; align-items: flex-end; justify-content: center;
            opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
        }
        .modal-overlay.open { opacity: 1; pointer-events: all; }
        .modal-sheet {
            background: #0f0f13; border: 1px solid var(--border);
            border-radius: 24px 24px 0 0; width: 100%; max-width: 480px;
            padding: 28px 24px 48px;
            transform: translateY(40px); transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1);
            position: relative;
        }
        .modal-overlay.open .modal-sheet { transform: translateY(0); }
        .modal-handle {
            width: 36px; height: 4px; background: #2a2a2a; border-radius: 4px;
            margin: 0 auto 24px;
        }
        .modal-title { font-family: 'Bebas Neue', sans-serif; font-size: 1.8rem; letter-spacing: 2px; margin-bottom: 6px; }
        .modal-subtitle { font-size: 0.85rem; color: var(--muted); margin-bottom: 24px; }
        .modal-input-group { margin-bottom: 16px; }
        .modal-input-group label {
            display: block; font-size: 0.68rem; letter-spacing: 2px;
            text-transform: uppercase; color: var(--muted); margin-bottom: 6px;
        }
        .modal-input {
            width: 100%; background: var(--card); border: 1px solid var(--border);
            color: var(--text); padding: 13px 16px; border-radius: 10px;
            font-size: 1rem; font-family: 'Outfit', sans-serif;
        }
        .btn-mpesa {
            width: 100%; padding: 15px; border-radius: 12px; border: none;
            background: #00a651; color: white; font-weight: 800; font-size: 0.9rem;
            cursor: pointer; font-family: 'Outfit', sans-serif;
        }
        .btn-cancel {
            width: 100%; padding: 13px; margin-top: 10px; border-radius: 12px;
            border: 1px solid var(--border); background: none; color: var(--muted);
            cursor: pointer;
        }
        .btn-cancel:hover { color: var(--text); border-color: #444; }
        .match-details-box {
            background: rgba(0,255,65,0.04); border: 1px solid rgba(0,255,65,0.12);
            border-radius: 14px; padding: 16px; margin-bottom: 18px;
        }
        .match-detail-row {
            display: flex; justify-content: space-between;
            padding: 7px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
        }
        .match-detail-row:last-child { border-bottom: none; }
        .match-detail-label { font-size: 0.72rem; color: var(--muted); }
        .match-detail-value { font-size: 0.88rem; font-weight: 700; }
        .match-detail-value.neon { color: var(--neon); }
        .balance-insufficient {
            background: rgba(255,68,68,0.08); border: 1px solid rgba(255,68,68,0.2);
            border-radius: 10px; padding: 12px 14px; font-size: 0.82rem; color: #ff8888;
            margin-bottom: 14px; display: none;
        }
        .bottom-nav {
            position: fixed; bottom: 0; left: 50%; transform: translateX(-50%);
            width: 100%; max-width: 480px; background: rgba(10,10,14,0.95);
            border-top: 1px solid var(--border); backdrop-filter: blur(12px);
            display: flex; padding: 10px 0 18px; z-index: 20;
        }
        .nav-item {
            flex: 1; display: flex; flex-direction: column; align-items: center;
            gap: 5px; cursor: pointer; color: var(--muted); transition: color 0.2s;
        }
        .nav-item svg { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 1.8; }
        .nav-item-label { font-size: 0.6rem; letter-spacing: 0.5px; text-transform: uppercase; }
        .nav-item.active { color: var(--neon); }
        .nav-item.active svg { filter: drop-shadow(0 0 5px rgba(0,255,65,0.5)); }
        .amount-presets { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 14px; }
        .preset-btn {
            padding: 9px 6px; background: var(--card); border: 1px solid var(--border);
            border-radius: 10px; color: var(--text); font-size: 0.8rem; font-weight: 600;
            cursor: pointer; font-family: 'Outfit', sans-serif; transition: all 0.2s;
        }
        .preset-btn:hover, .preset-btn.selected {
            border-color: var(--neon); color: var(--neon); background: rgba(0,255,65,0.06);
        }
        .status-pending { background: rgba(255,180,0,0.1); color: #ffb400; border: 1px solid rgba(255,180,0,0.2); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; }
        .status-live { background: rgba(0,255,65,0.1); color: var(--neon); border: 1px solid rgba(0,255,65,0.2); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; }
        .status-disputed { background: rgba(255,68,68,0.1); color: #ff6666; border: 1px solid rgba(255,68,68,0.2); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; }
        .status-closed { background: rgba(100,100,100,0.1); color: #777; border: 1px solid rgba(100,100,100,0.2); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; }
        .status-won { background: rgba(0,255,65,0.1); color: var(--neon); border: 1px solid rgba(0,255,65,0.2); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; font-weight: 700; }
        .status-lost { background: rgba(255,68,68,0.08); color: #ff7777; border: 1px solid rgba(255,68,68,0.18); border-radius: 20px; padding: 3px 10px; font-size: 0.65rem; text-transform: uppercase; }
        @keyframes balFlash { 0%,100%{color:var(--neon);} 50%{color:#80ffb0; text-shadow:0 0 40px rgba(0,255,65,0.8), 0 0 80px rgba(0,255,65,0.3);} }
        .balance-flash { animation: balFlash 0.7s ease; }
        .breakdown-box {
            background: rgba(0,255,65,0.04); border: 1px solid rgba(0,255,65,0.12);
            border-radius: 12px; padding: 14px; margin: 14px 0;
        }
        .breakdown-row {
            display: flex; justify-content: space-between;
            font-size: 0.8rem; color: #aaa; padding: 4px 0;
        }
        .breakdown-row.total { color: var(--neon); font-weight: 700; font-size: 0.9rem; border-top: 1px solid rgba(0,255,65,0.15); margin-top: 6px; padding-top: 10px; }
        .step { display: none; }
        .step.active { display: block; }
        .btn { padding: 10px 18px; border-radius: 10px; font-weight: 700; font-size: 0.82rem; cursor: pointer; font-family: 'Outfit', sans-serif; border: none; transition: all 0.2s; }
        .btn-green { background: var(--neon); color: #000; }
        .btn-red { background: rgba(255,68,68,0.15); color: #ff6666; border: 1px solid rgba(255,68,68,0.3); }
        .matches-list { min-height: 60px; }
        .modal-select { width: 100%; background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 13px 16px; border-radius: 10px; font-size: 1rem; font-family: 'Outfit', sans-serif; }
        .ocr-result-card {
            background: rgba(0,255,65,0.06); border: 1px solid rgba(0,255,65,0.2);
            border-radius: 16px; padding: 20px; text-align: center; margin-bottom: 14px;
        }
        .ocr-result-score {
            font-family: 'Bebas Neue', sans-serif; font-size: 3.5rem;
            color: var(--neon); letter-spacing: 8px; line-height: 1;
            text-shadow: 0 0 30px rgba(0,255,65,0.4);
        }
        .ocr-result-label { font-size: 0.65rem; letter-spacing: 3px; text-transform: uppercase; color: #555; margin-top: 8px; }
        .winner-announce {
            background: linear-gradient(135deg, rgba(0,255,65,0.08), rgba(0,255,65,0.03));
            border: 1px solid rgba(0,255,65,0.15); border-radius: 16px;
            padding: 20px; text-align: center; margin-bottom: 16px;
        }
        .winner-crown { font-size: 2rem; margin-bottom: 6px; }
        .winner-name { font-family: 'Bebas Neue', sans-serif; font-size: 2rem; letter-spacing: 3px; color: var(--neon); }
        .winner-prize-text { font-size: 0.85rem; color: #aaa; margin-top: 4px; font-weight: 600; }
        .winner-announce.you-won { border-color: rgba(0,255,65,0.4); background: linear-gradient(135deg, rgba(0,255,65,0.12), rgba(0,255,65,0.04)); }
        .winner-announce.you-won .winner-name { text-shadow: 0 0 20px rgba(0,255,65,0.5); }
        /* ── Screenshot guide ── */
        .screenshot-guide {
            background: rgba(0,0,0,0.5);
            border: 1px solid rgba(0,255,65,0.15);
            border-radius: 14px;
            padding: 14px;
            margin-bottom: 14px;
        }
        .guide-header {
            display: flex; align-items: center; gap: 8px;
            font-size: 0.68rem; letter-spacing: 1.5px; text-transform: uppercase;
            color: var(--neon); font-weight: 700; margin-bottom: 12px;
            cursor: pointer;
        }
        .guide-header .guide-toggle { margin-left: auto; color: #555; font-size: 0.8rem; transition: transform 0.2s; }
        .guide-header.open .guide-toggle { transform: rotate(180deg); }
        .guide-body { display: none; }
        .guide-body.open { display: block; }
        /* Mock eFootball end-screen */
        .mock-screenshot {
            background: linear-gradient(160deg, #0a0a1a 0%, #12103a 50%, #0a0a1a 100%);
            border-radius: 10px;
            padding: 16px 12px 12px;
            margin-bottom: 10px;
            position: relative;
            border: 1px solid rgba(255,255,255,0.08);
            overflow: hidden;
        }
        .mock-screenshot::before {
            content: '';
            position: absolute; inset: 0;
            background: radial-gradient(ellipse at 50% 40%, rgba(80,60,200,0.15) 0%, transparent 70%);
        }
        .mock-match-header {
            text-align: center;
            font-size: 0.55rem;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: rgba(255,255,255,0.35);
            margin-bottom: 10px;
            font-family: 'Outfit', sans-serif;
        }
        .mock-scoreboard {
            display: flex; align-items: center; justify-content: space-between;
            gap: 6px;
        }
        .mock-team {
            flex: 1; text-align: center;
        }
        .mock-team-logo {
            width: 28px; height: 28px; border-radius: 50%;
            margin: 0 auto 5px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1rem;
        }
        .mock-team-logo.home { background: rgba(0,100,255,0.3); border: 1px solid rgba(0,100,255,0.5); }
        .mock-team-logo.away { background: rgba(255,50,50,0.3); border: 1px solid rgba(255,50,50,0.5); }
        .mock-team-name {
            font-size: 0.52rem; color: rgba(255,255,255,0.7);
            font-family: 'Outfit', sans-serif; font-weight: 600; letter-spacing: 0.5px;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .mock-score-center {
            display: flex; align-items: center; gap: 4px;
        }
        .mock-score-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2.6rem; color: #fff; line-height: 1;
            text-shadow: 0 0 20px rgba(255,255,255,0.4);
        }
        .mock-score-sep { color: rgba(255,255,255,0.25); font-size: 1.2rem; font-family: 'Bebas Neue', sans-serif; }
        .mock-ft-badge {
            text-align: center;
            font-size: 0.5rem; letter-spacing: 2px; color: rgba(255,255,255,0.3);
            margin-top: 8px; font-family: 'Outfit', sans-serif; font-weight: 700;
        }
        /* Annotation callouts */
        .mock-annotations {
            display: flex; flex-direction: column; gap: 5px;
            margin-top: 10px;
        }
        .annotation {
            display: flex; align-items: flex-start; gap: 7px;
            font-size: 0.7rem; color: #aaa; line-height: 1.4;
        }
        .annotation-dot {
            width: 16px; height: 16px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 0.6rem; font-weight: 800; flex-shrink: 0;
            margin-top: 1px;
        }
        .annotation-dot.green { background: rgba(0,255,65,0.2); color: var(--neon); border: 1px solid rgba(0,255,65,0.4); }
        .annotation-dot.yellow { background: rgba(255,180,0,0.2); color: #ffb400; border: 1px solid rgba(255,180,0,0.4); }
        .annotation strong { color: #ccc; }
        /* Tips list */
        .guide-tips { margin-top: 10px; display: flex; flex-direction: column; gap: 5px; }
        .guide-tip {
            display: flex; align-items: center; gap: 7px;
            font-size: 0.72rem; color: #888; background: rgba(255,255,255,0.03);
            border-radius: 8px; padding: 7px 10px;
        }
        .guide-tip.good { border-left: 2px solid rgba(0,255,65,0.5); }
        .guide-tip.bad { border-left: 2px solid rgba(255,68,68,0.5); }
        .guide-tip .tip-icon { font-size: 0.85rem; flex-shrink: 0; }

        /* ── Upload zone ── */
        .screenshot-upload-zone {
            border: 2px dashed rgba(0,255,65,0.25);
            border-radius: 14px; padding: 28px 16px;
            text-align: center; cursor: pointer;
            transition: border-color 0.2s, background 0.2s;
            background: rgba(0,255,65,0.02);
            position: relative; margin-bottom: 4px;
        }
        .screenshot-upload-zone:hover, .screenshot-upload-zone.drag-over {
            border-color: rgba(0,255,65,0.6);
            background: rgba(0,255,65,0.05);
        }
        .screenshot-upload-zone input[type=file] {
            position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
        }
        .upload-icon { font-size: 2.4rem; margin-bottom: 10px; display: block; }
        .upload-label { font-size: 0.85rem; color: var(--muted); line-height: 1.5; }
        .upload-label strong { color: var(--neon); }
        .upload-hint {
            display: flex; align-items: center; justify-content: center; gap: 12px;
            margin-top: 12px; padding-top: 12px;
            border-top: 1px solid rgba(255,255,255,0.05);
            font-size: 0.65rem; color: #444;
        }
        .upload-hint span { display: flex; align-items: center; gap: 4px; }

        /* ── In-modal toast ── */
        .modal-toast {
            position: fixed; top: 0; left: 50%; transform: translateX(-50%) translateY(-100%);
            background: #111116; border: 1px solid var(--border);
            border-radius: 0 0 16px 16px; padding: 12px 20px;
            font-size: 0.82rem; font-weight: 600;
            z-index: 9999; transition: transform 0.35s cubic-bezier(0.34,1.56,0.64,1);
            display: flex; align-items: center; gap: 10px;
            max-width: 420px; width: 90%; text-align: left;
            box-shadow: 0 8px 30px rgba(0,0,0,0.5);
        }
        .modal-toast.show { transform: translateX(-50%) translateY(0); }
        .modal-toast.success { border-color: rgba(0,255,65,0.4); }
        .modal-toast.success .toast-icon { color: var(--neon); }
        .modal-toast.error { border-color: rgba(255,68,68,0.4); }
        .modal-toast.error .toast-icon { color: #ff6666; }
        .modal-toast.info { border-color: rgba(255,180,0,0.4); }
        .modal-toast.info .toast-icon { color: #ffb400; }
        .toast-icon { font-size: 1.1rem; flex-shrink: 0; }
        .toast-body { flex: 1; }
        .toast-title { font-weight: 800; font-size: 0.82rem; margin-bottom: 1px; }
        .toast-msg { font-size: 0.74rem; color: #aaa; font-weight: 400; }

        /* ── Improved winner banner ── */
        .winner-banner {
            border-radius: 16px; padding: 22px; text-align: center; margin-bottom: 16px;
            position: relative; overflow: hidden;
        }
        .winner-banner.you-won {
            background: linear-gradient(135deg, rgba(0,255,65,0.1), rgba(0,255,65,0.04));
            border: 1px solid rgba(0,255,65,0.35);
        }
        .winner-banner.opp-won {
            background: linear-gradient(135deg, rgba(255,68,68,0.07), rgba(255,68,68,0.02));
            border: 1px solid rgba(255,68,68,0.25);
        }
        .winner-banner-emoji { font-size: 2.4rem; margin-bottom: 6px; display: block; }
        .winner-banner-label {
            font-size: 0.6rem; letter-spacing: 3px; text-transform: uppercase;
            color: #555; margin-bottom: 4px;
        }
        .winner-banner-name {
            font-family: 'Bebas Neue', sans-serif; font-size: 2.2rem;
            letter-spacing: 3px; line-height: 1.1;
        }
        .winner-banner.you-won .winner-banner-name { color: var(--neon); text-shadow: 0 0 20px rgba(0,255,65,0.4); }
        .winner-banner.opp-won .winner-banner-name { color: #ff7777; }
        .winner-banner-prize {
            margin-top: 8px; font-size: 0.82rem; font-weight: 600; color: #aaa;
        }
        .winner-banner.you-won .winner-banner-prize { color: var(--neon); font-size: 0.9rem; }

        /* ── Confidence badge strip ── */
        .conf-strip {
            display: flex; align-items: center; gap: 8px;
            background: rgba(255,255,255,0.03); border-radius: 10px;
            padding: 9px 14px; margin: 10px 0;
        }
        .conf-bar-wrap { flex: 1; background: rgba(255,255,255,0.06); border-radius: 6px; height: 6px; }
        .conf-bar-fill { height: 100%; border-radius: 6px; transition: width 0.5s ease; }
        .conf-bar-fill.high { background: var(--neon); box-shadow: 0 0 6px rgba(0,255,65,0.5); }
        .conf-bar-fill.medium { background: #ffb400; }
        .conf-bar-fill.low { background: #ff6666; }
        .conf-pct { font-size: 0.7rem; font-weight: 700; white-space: nowrap; }
        .conf-pct.high { color: var(--neon); }
        .conf-pct.medium { color: #ffb400; }
        .conf-pct.low { color: #ff6666; }
        .ocr-panel {
            background: rgba(0,255,65,0.05); border: 1px solid rgba(0,255,65,0.2);
            border-radius: 12px; padding: 14px 16px; margin: 12px 0; display: none;
        }
        .ocr-panel.visible { display: block; animation: fadeIn 0.3s ease; }
        .ocr-panel.fraud { background: rgba(255,68,68,0.07); border-color: rgba(255,68,68,0.3); }
        .ocr-panel.warn { background: rgba(255,180,0,0.07); border-color: rgba(255,180,0,0.3); }
        .ocr-title { font-size: 0.65rem; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
        .ocr-score-display {
            font-family: 'Bebas Neue', sans-serif; font-size: 2.4rem;
            color: var(--neon); letter-spacing: 4px; text-align: center;
            margin: 6px 0; line-height: 1;
        }
        .ocr-confidence { font-size: 0.72rem; color: #888; text-align: center; margin-top: 4px; }
        .ocr-badge {
            display: inline-block; padding: 3px 10px; border-radius: 20px;
            font-size: 0.65rem; font-weight: 700; letter-spacing: 1px;
            text-transform: uppercase; margin-top: 6px;
        }
        .ocr-badge.ok { background: rgba(0,255,65,0.15); color: var(--neon); }
        .ocr-badge.low { background: rgba(255,180,0,0.15); color: #ffb400; }
        .ocr-badge.fail { background: rgba(255,68,68,0.15); color: #ff4444; }
        .ocr-warn-list { margin-top: 8px; }
        .ocr-warn-item { font-size: 0.72rem; color: #ffb400; padding: 2px 0; }
        .ocr-warn-item::before { content: '\\26A0 '; }
        .upload-progress {
            height: 3px; background: rgba(255,255,255,0.06); border-radius: 3px;
            margin-top: 8px; overflow: hidden; display: none;
        }
        .upload-progress.visible { display: block; }
        .upload-progress-fill { height: 100%; background: var(--neon); border-radius: 3px; }
        .upload-progress-fill.indeterminate {
            width: 40%; animation: progressSlide 1.2s ease-in-out infinite;
        }
        @keyframes progressSlide { 0%{transform:translateX(-200%)} 100%{transform:translateX(400%)} }
        .screenshot-thumb {
            width: 100%; max-height: 120px; object-fit: contain;
            border-radius: 8px; margin-top: 8px; display: none;
            border: 1px solid var(--border);
        }
        .screenshot-thumb.visible { display: block; }
        .auto-fill-notice { font-size: 0.72rem; color: var(--neon); padding: 6px 0; display: none; }
        .auto-fill-notice.visible { display: block; }
        .confidence-meter {
            background: rgba(0,255,65,0.05);
            border-radius: 20px;
            padding: 8px 12px;
            margin: 12px 0;
            font-size: 0.8rem;
        }
        .confidence-high { color: var(--neon); }
        .confidence-medium { color: #ffb400; }
        .confidence-low { color: #ff8888; }

        /* ══════════════════════════════════════════
           MATCH STATE CARDS — ENHANCED UX
        ══════════════════════════════════════════ */

        /* --- Active: waiting for opponent to post results --- */
        .match-state-waiting-results {
            margin-top: 12px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 14px;
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .waiting-results-header {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .opponent-avatar-ring {
            position: relative;
            width: 38px;
            height: 38px;
            flex-shrink: 0;
        }
        .opponent-avatar-ring svg {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            animation: ringRotate 3s linear infinite;
        }
        @keyframes ringRotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        .opponent-avatar-inner {
            position: absolute;
            inset: 5px;
            border-radius: 50%;
            background: rgba(255,255,255,0.08);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 800;
            color: #aaa;
        }
        .waiting-results-text {}
        .waiting-results-label {
            font-size: 0.65rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #555;
        }
        .waiting-results-name {
            font-size: 0.9rem;
            font-weight: 700;
            color: #bbb;
            margin-top: 1px;
        }
        .waiting-results-sub {
            font-size: 0.72rem;
            color: #555;
            margin-top: 1px;
        }
        .waiting-dots {
            display: inline-flex;
            gap: 3px;
            margin-left: 4px;
        }
        .waiting-dots span {
            width: 4px; height: 4px;
            border-radius: 50%;
            background: #555;
            animation: dotBlink 1.4s infinite both;
        }
        .waiting-dots span:nth-child(2) { animation-delay: 0.2s; }
        .waiting-dots span:nth-child(3) { animation-delay: 0.4s; }
        @keyframes dotBlink {
            0%, 80%, 100% { opacity: 0.2; transform: scale(0.8); }
            40% { opacity: 1; transform: scale(1.2); }
        }
        .match-state-waiting-results .declare-cta {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(0,255,65,0.05);
            border: 1px solid rgba(0,255,65,0.12);
            border-radius: 10px;
            padding: 10px 14px;
        }
        .declare-cta-text {
            font-size: 0.78rem;
            color: #aaa;
        }
        .declare-cta-text strong { color: var(--neon); }
        .declare-cta-btn {
            padding: 7px 14px;
            border-radius: 8px;
            border: none;
            background: var(--neon);
            color: #000;
            font-size: 0.75rem;
            font-weight: 800;
            cursor: pointer;
            font-family: 'Outfit', sans-serif;
            white-space: nowrap;
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .declare-cta-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(0,255,65,0.3); }

        /* --- Awaiting confirmation: I declared, waiting for opponent to confirm --- */
        .match-state-confirming {
            margin-top: 12px;
            border-radius: 14px;
            overflow: hidden;
            position: relative;
        }
        .confirming-inner {
            background: linear-gradient(135deg, rgba(0,255,65,0.06) 0%, rgba(0,255,65,0.02) 100%);
            border: 1px solid rgba(0,255,65,0.2);
            border-radius: 14px;
            padding: 16px;
            position: relative;
            overflow: hidden;
        }
        .confirming-inner::before {
            content: '';
            position: absolute;
            top: 0; left: -100%; width: 60%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0,255,65,0.06), transparent);
            animation: shimmerSlide 2.5s ease-in-out infinite;
        }
        @keyframes shimmerSlide {
            0% { left: -100%; }
            100% { left: 200%; }
        }
        .confirming-top {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }
        .confirming-icon-wrap {
            width: 42px; height: 42px;
            position: relative; flex-shrink: 0;
        }
        .confirming-ring-svg {
            width: 100%; height: 100%;
            position: absolute; inset: 0;
        }
        .confirming-ring-track {
            fill: none;
            stroke: rgba(0,255,65,0.12);
            stroke-width: 3;
        }
        .confirming-ring-progress {
            fill: none;
            stroke: var(--neon);
            stroke-width: 3;
            stroke-linecap: round;
            stroke-dasharray: 110;
            stroke-dashoffset: 110;
            transform-origin: center;
            transform: rotate(-90deg);
            filter: drop-shadow(0 0 3px rgba(0,255,65,0.6));
            transition: stroke-dashoffset 1s linear;
        }
        .confirming-icon-center {
            position: absolute;
            inset: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }
        .confirming-text {}
        .confirming-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 0.6rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-weight: 800;
            color: var(--neon);
            margin-bottom: 3px;
        }
        .confirming-badge-dot {
            width: 6px; height: 6px;
            border-radius: 50%;
            background: var(--neon);
            animation: pulse 1.5s infinite;
            box-shadow: 0 0 6px rgba(0,255,65,0.6);
        }
        .confirming-title {
            font-size: 0.95rem;
            font-weight: 700;
            color: #eee;
        }
        .confirming-sub {
            font-size: 0.72rem;
            color: #777;
            margin-top: 2px;
        }
        .confirming-score-display {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 12px;
        }
        .confirming-score-team {
            text-align: center;
            flex: 1;
        }
        .confirming-score-team-name {
            font-size: 0.6rem;
            letter-spacing: 1px;
            text-transform: uppercase;
            color: #555;
            margin-bottom: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .confirming-score-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2.4rem;
            line-height: 1;
            color: #fff;
        }
        .confirming-score-num.my { color: var(--neon); text-shadow: 0 0 12px rgba(0,255,65,0.4); }
        .confirming-score-num.opp { color: #aaa; }
        .confirming-score-sep {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 1.8rem;
            color: #333;
        }
        /* ── Big countdown clock — confirming (green) ── */
        .confirming-clock-block {
            background: rgba(0,0,0,0.35);
            border-radius: 12px;
            padding: 14px 16px 10px;
            margin-top: 2px;
        }
        .confirming-clock-label {
            font-size: 0.58rem;
            letter-spacing: 2.5px;
            text-transform: uppercase;
            color: #444;
            text-align: center;
            margin-bottom: 8px;
        }
        .confirming-clock-digits {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0;
        }
        .clock-unit {
            text-align: center;
            min-width: 56px;
        }
        .clock-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 3rem;
            line-height: 1;
            color: var(--neon);
            text-shadow: 0 0 24px rgba(0,255,65,0.4);
            letter-spacing: 1px;
            display: block;
        }
        .clock-num.urgent-red { color: #ff4444; text-shadow: 0 0 24px rgba(255,68,68,0.5); }
        .clock-unit-label {
            font-size: 0.5rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #444;
            margin-top: 3px;
        }
        .clock-sep {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2rem;
            color: #2a2a2a;
            padding-bottom: 14px;
            line-height: 1;
            margin: 0 2px;
        }
        .confirming-countdown-bar {
            height: 3px;
            background: rgba(255,255,255,0.06);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 12px;
        }
        .confirming-countdown-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--neon), rgba(0,255,65,0.5));
            border-radius: 3px;
            transition: width 1s linear;
        }
        .confirming-auto-win-note {
            text-align: center;
            font-size: 0.68rem;
            color: #444;
            margin-top: 7px;
        }
        .confirming-auto-win-note strong { color: var(--neon); font-weight: 700; }

        /* --- Awaiting confirmation: OPPONENT declared, urgent action needed --- */
        .match-state-urgent {
            margin-top: 12px;
            border-radius: 14px;
            overflow: hidden;
        }
        .urgent-inner {
            background: linear-gradient(135deg, rgba(255,68,68,0.08) 0%, rgba(255,68,68,0.03) 100%);
            border: 1px solid rgba(255,68,68,0.3);
            border-radius: 14px;
            padding: 16px;
            position: relative;
            overflow: hidden;
        }
        .urgent-inner::after {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 14px;
            border: 1px solid rgba(255,68,68,0.5);
            animation: urgentBorderPulse 1.5s ease-in-out infinite;
            pointer-events: none;
        }
        @keyframes urgentBorderPulse {
            0%, 100% { opacity: 0; transform: scale(1); }
            50% { opacity: 1; transform: scale(1.005); }
        }
        .urgent-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }
        .urgent-alarm {
            width: 36px; height: 36px;
            background: rgba(255,68,68,0.15);
            border: 1px solid rgba(255,68,68,0.3);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 1rem;
            animation: alarmPulse 1s ease-in-out infinite;
            flex-shrink: 0;
        }
        @keyframes alarmPulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(255,68,68,0); }
            50% { box-shadow: 0 0 0 6px rgba(255,68,68,0.15); }
        }
        .urgent-text-group {}
        .urgent-label {
            font-size: 0.6rem;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-weight: 800;
            color: #ff4444;
        }
        .urgent-title {
            font-size: 0.9rem;
            font-weight: 700;
            color: #eee;
            margin-top: 2px;
        }
        .urgent-sub { font-size: 0.72rem; color: #888; margin-top: 2px; }
        .urgent-score-display {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 12px;
        }
        .urgent-score-team { text-align: center; flex: 1; }
        .urgent-score-team-name {
            font-size: 0.6rem; letter-spacing: 1px; text-transform: uppercase;
            color: #555; margin-bottom: 4px;
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .urgent-score-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2.4rem; line-height: 1; color: #777;
        }
        .urgent-score-num.winning { color: #ff6666; text-shadow: 0 0 12px rgba(255,68,68,0.4); }
        .urgent-score-sep { font-family: 'Bebas Neue', sans-serif; font-size: 1.8rem; color: #333; }
        /* ── Big countdown clock — urgent (red) ── */
        .urgent-clock-block {
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            padding: 14px 16px 10px;
            margin-bottom: 12px;
            border: 1px solid rgba(255,68,68,0.1);
        }
        .urgent-clock-label {
            font-size: 0.58rem;
            letter-spacing: 2.5px;
            text-transform: uppercase;
            color: #883333;
            text-align: center;
            margin-bottom: 8px;
        }
        .urgent-clock-digits {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .urgent-clock-sep {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2rem;
            color: #3a1a1a;
            padding-bottom: 14px;
            line-height: 1;
            margin: 0 2px;
        }
        .urgent-bar {
            height: 3px;
            background: rgba(255,68,68,0.12);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 12px;
        }
        .urgent-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff4444, rgba(255,68,68,0.5));
            border-radius: 3px;
            transition: width 1s linear;
        }
        .urgent-auto-lose-note {
            text-align: center;
            font-size: 0.68rem;
            color: #663333;
            margin-top: 7px;
        }
        .urgent-auto-lose-note strong { color: #ff6666; font-weight: 700; }
        .urgent-timer-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(255,68,68,0.06);
            border-radius: 8px;
            padding: 8px 12px;
            margin-bottom: 12px;
        }
        .urgent-timer-label { font-size: 0.7rem; color: #888; }
        .urgent-timer-val {
            font-weight: 800;
            font-size: 0.8rem;
            color: #ff4444;
        }
        .urgent-timer-val.countdown-timer { color: #ff4444; }
        .urgent-action-btn {
            width: 100%;
            padding: 13px;
            border-radius: 10px;
            border: none;
            background: linear-gradient(135deg, #ff4444, #cc2222);
            color: #fff;
            font-weight: 800;
            font-size: 0.88rem;
            cursor: pointer;
            font-family: 'Outfit', sans-serif;
            letter-spacing: 0.5px;
            transition: transform 0.15s, box-shadow 0.15s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            animation: urgentBtnPulse 2s ease-in-out infinite;
        }
        @keyframes urgentBtnPulse {
            0%, 100% { box-shadow: 0 4px 15px rgba(255,68,68,0.2); }
            50% { box-shadow: 0 4px 25px rgba(255,68,68,0.45); }
        }
        .urgent-action-btn:hover { transform: translateY(-1px); }

        /* ══════════════════════════════════════════════════════
           FLOATING CONFIRM-REQUIRED BANNER
           Slides up from bottom when opponent has declared
           and it's your turn to confirm or dispute.
        ══════════════════════════════════════════════════════ */
        #confirm-action-banner {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%) translateY(140%);
            width: calc(100% - 32px);
            max-width: 448px;
            z-index: 500;
            border-radius: 18px;
            transition: transform 0.45s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.35s ease;
            opacity: 0;
            pointer-events: none;
            box-shadow: 0 20px 60px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,68,68,0.35);
        }
        #confirm-action-banner.visible {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
            pointer-events: auto;
        }
        #confirm-action-banner.expired .banner-clock-row { opacity: 0.4; }
        #confirm-action-banner.expired .banner-btn { opacity: 0.45; pointer-events: none; }
        #confirm-action-banner.expired .banner-expired-msg { display: block; }

        .banner-inner {
            background: linear-gradient(145deg, rgba(22,5,5,0.98) 0%, rgba(28,8,8,0.98) 100%);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,68,68,0.3);
            border-radius: 18px;
            padding: 16px 16px 14px;
            position: relative;
            overflow: hidden;
        }
        .banner-inner::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, transparent 0%, #ff4444 50%, transparent 100%);
            animation: bannerTopGlow 2s ease-in-out infinite;
        }
        @keyframes bannerTopGlow {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 1; box-shadow: 0 0 12px rgba(255,68,68,0.6); }
        }
        .banner-top-row {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }
        .banner-alarm-dot {
            width: 34px; height: 34px; border-radius: 50%;
            background: rgba(255,68,68,0.15);
            border: 1px solid rgba(255,68,68,0.4);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.05rem; flex-shrink: 0;
            animation: alarmPulse 1.2s ease-in-out infinite;
        }
        .banner-text { flex: 1; min-width: 0; }
        .banner-badge {
            font-size: 0.55rem;
            letter-spacing: 2.5px;
            text-transform: uppercase;
            font-weight: 800;
            color: #ff4444;
            margin-bottom: 2px;
        }
        .banner-title {
            font-size: 0.86rem;
            font-weight: 800;
            color: #fff;
            line-height: 1.2;
        }
        .banner-sub {
            font-size: 0.68rem;
            color: #666;
            margin-top: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .banner-dismiss {
            background: none; border: none;
            color: #444; font-size: 1.2rem;
            cursor: pointer; padding: 4px;
            line-height: 1; flex-shrink: 0;
            transition: color 0.2s;
        }
        .banner-dismiss:hover { color: #777; }

        /* Score display inside banner */
        .banner-score-row {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            background: rgba(0,0,0,0.35);
            border-radius: 12px;
            padding: 10px 14px;
            margin-bottom: 10px;
        }
        .banner-score-team {
            flex: 1; text-align: center;
        }
        .banner-score-team-name {
            font-size: 0.52rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #444;
            margin-bottom: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .banner-score-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2.2rem;
            line-height: 1;
            color: #cc4444;
        }
        .banner-score-num.my-score { color: #aaa; }
        .banner-score-sep {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 1.6rem;
            color: #2a1a1a;
            flex-shrink: 0;
            padding: 0 2px;
        }
        .banner-result-line {
            text-align: center;
            font-size: 0.68rem;
            color: #666;
            margin-bottom: 10px;
        }
        .banner-result-line.win { color: var(--neon); }
        .banner-result-line.lose { color: #ff6666; }

        /* Countdown row */
        .banner-clock-row {
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,68,68,0.08);
            border-radius: 12px;
            padding: 10px 14px;
            margin-bottom: 10px;
            transition: opacity 0.3s;
        }
        .banner-clock-label-text {
            font-size: 0.62rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #663333;
            flex: 1;
            line-height: 1.3;
        }
        .banner-clock-digits {
            display: flex;
            align-items: flex-end;
            gap: 0;
            flex-shrink: 0;
        }
        .banner-digit-group {
            text-align: center;
        }
        .banner-clock-num {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 2rem;
            line-height: 1;
            color: #ff4444;
            text-shadow: 0 0 20px rgba(255,68,68,0.4);
            display: block;
            min-width: 2.2ch;
        }
        .banner-digit-label {
            font-size: 0.42rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #442222;
            display: block;
            margin-top: 2px;
        }
        .banner-clock-colon {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 1.6rem;
            color: #331111;
            line-height: 1;
            margin: 0 1px;
            padding-bottom: 6px;
        }

        /* Progress bar */
        .banner-progress {
            height: 3px;
            background: rgba(255,68,68,0.08);
            border-radius: 3px;
            overflow: hidden;
            margin-bottom: 12px;
        }
        .banner-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff4444, rgba(255,68,68,0.4));
            border-radius: 3px;
            transition: width 1s linear;
        }

        /* Expired message */
        .banner-expired-msg {
            text-align: center;
            font-size: 0.7rem;
            color: #553333;
            margin-bottom: 10px;
            display: none;
        }

        /* Action buttons */
        .banner-actions {
            display: flex;
            gap: 8px;
        }
        .banner-btn {
            flex: 1;
            padding: 12px 8px;
            border-radius: 11px;
            border: none;
            font-weight: 800;
            font-size: 0.8rem;
            font-family: 'Outfit', sans-serif;
            cursor: pointer;
            transition: transform 0.15s, box-shadow 0.15s, opacity 0.3s;
            letter-spacing: 0.3px;
        }
        .banner-btn:active { transform: scale(0.97); }
        .banner-btn-confirm {
            background: linear-gradient(135deg, #00ff41, #00cc30);
            color: #000;
            box-shadow: 0 4px 18px rgba(0,255,65,0.25);
        }
        .banner-btn-confirm:hover { box-shadow: 0 6px 26px rgba(0,255,65,0.4); transform: translateY(-1px); }
        .banner-btn-dispute {
            background: rgba(255,68,68,0.1);
            color: #ff7777;
            border: 1px solid rgba(255,68,68,0.3);
        }
        .banner-btn-dispute:hover { background: rgba(255,68,68,0.18); transform: translateY(-1px); }
    
        /* ── Enhanced visual polish ── */
        .wallet-card::before {
            content: ''; position: absolute; top: -80px; right: -80px;
            width: 260px; height: 260px; border-radius: 50%;
            background: radial-gradient(circle, rgba(0,255,65,0.07) 0%, transparent 70%);
            pointer-events: none;
        }
        .wallet-card::after {
            content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(to right, transparent, rgba(0,255,65,0.25), transparent);
        }
        .wallet-currency {
            font-size: 1.4rem; opacity: 0.45; margin-right: 2px;
            font-family: 'Outfit', sans-serif; font-weight: 300;
        }
        /* Scan line effect on wallet */
        @keyframes scanLine {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(400%); }
        }
        .wallet-card .scan-line {
            position: absolute; left: 0; right: 0; height: 60px;
            background: linear-gradient(to bottom, transparent, rgba(0,255,65,0.03), transparent);
            animation: scanLine 4s ease-in-out infinite;
            pointer-events: none;
        }
        /* Quick icon hover enlarge */
        .quick-icon {
            font-size: 1.6rem; margin-bottom: 8px; display: block;
            transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1);
        }
        .quick-card:hover .quick-icon { transform: scale(1.25) rotate(-5deg); }
        .quick-label {
            font-size: 0.7rem; font-weight: 700; color: #ccc;
            letter-spacing: 0.5px; text-transform: uppercase;
        }
        /* Progress bar glow */
        .progress-fill {
            box-shadow: 0 0 8px rgba(0,255,65,0.5);
        }
        /* Better modal inputs */
        .modal-input:focus {
            outline: none;
            border-color: rgba(0,255,65,0.4);
            box-shadow: 0 0 0 3px rgba(0,255,65,0.08);
            background: #131318;
        }
        /* Section link polish */
        .section-link {
            font-size: 0.72rem; color: var(--neon); cursor: pointer;
            font-weight: 600; opacity: 0.7; transition: opacity 0.2s;
            letter-spacing: 0.5px;
        }
        .section-link:hover { opacity: 1; }
        /* Nav logo glow on hover */
        .nav-logo { transition: text-shadow 0.3s; }
        .nav-logo:hover { text-shadow: 0 0 20px rgba(0,255,65,0.5); }
        /* Better bottom nav */
        .bottom-nav {
            background: rgba(8,8,12,0.97);
            border-top: 1px solid rgba(255,255,255,0.06);
            box-shadow: 0 -20px 40px rgba(0,0,0,0.5);
        }
        .nav-item { transition: color 0.2s, transform 0.2s; }
        .nav-item:hover { color: rgba(0,255,65,0.6); }
        .nav-item:active { transform: scale(0.92); }
        /* Match code style */
        .match-code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem; letter-spacing: 3px; color: var(--neon);
            background: rgba(0,255,65,0.07); padding: 3px 10px;
            border-radius: 6px; border: 1px solid rgba(0,255,65,0.15);
        }
        /* Declare CTA button */
        .declare-cta-btn {
            background: linear-gradient(135deg, var(--neon), #00cc33);
            box-shadow: 0 4px 16px rgba(0,255,65,0.3);
        }
        .declare-cta-btn:hover { box-shadow: 0 6px 22px rgba(0,255,65,0.45); }
        /* Friend info box */
        .friend-info {
            background: rgba(0,255,65,0.04);
            border: 1px solid rgba(0,255,65,0.1);
            border-radius: 14px; padding: 14px;
            font-size: 0.75rem; color: #777; line-height: 1.8;
        }
        /* Waiting dots animation improvement */
        @keyframes dotBlink {
            0%, 80%, 100% { opacity: 0.15; transform: scale(0.7); }
            40% { opacity: 1; transform: scale(1.3); }
        }
        /* Score OCR display */
        .ocr-score-display {
            font-family: 'JetBrains Mono', monospace;
        }
        /* Realtime indicator */
        .realtime-indicator {
            font-size: 0.58rem; letter-spacing: 1.5px; text-transform: uppercase;
        }
        /* Topnav user pill */
        .nav-user {
            border: 1px solid rgba(0,255,65,0.15);
            transition: border-color 0.2s, background 0.2s;
        }
        .nav-user:hover { border-color: rgba(0,255,65,0.35); background: #141418; }
        /* Pending status pulse */
        .status-live::before {
            content: '';
            display: inline-block;
            width: 6px; height: 6px;
            background: var(--neon);
            border-radius: 50%;
            margin-right: 5px;
            animation: pulse 1.5s infinite;
            vertical-align: middle;
        }
        /* Improve modal sheet */
        .modal-sheet {
            background: #0d0d12;
            border: 1px solid rgba(255,255,255,0.08);
            border-bottom: none;
        }
        /* Btn green / red */
        .btn-green {
            background: linear-gradient(135deg, var(--neon), #00cc33);
            color: #000; box-shadow: 0 4px 16px rgba(0,255,65,0.25);
        }
        .btn-green:hover { box-shadow: 0 6px 22px rgba(0,255,65,0.4); transform: translateY(-1px); }
        .btn-red {
            background: rgba(255,68,68,0.1); color: #ff7777;
            border: 1px solid rgba(255,68,68,0.25);
            transition: background 0.2s, transform 0.2s;
        }
        .btn-red:hover { background: rgba(255,68,68,0.18); transform: translateY(-1px); }

        
        /* ── Loading skeletons ── */
        @keyframes shimmer {
            0% { background-position: -200% center; }
            100% { background-position: 200% center; }
        }
        .skeleton {
            background: linear-gradient(90deg, #111116 25%, #1a1a22 50%, #111116 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s ease infinite;
            border-radius: 8px;
        }
        .skeleton-card {
            background: var(--card); border: 1px solid var(--border);
            border-radius: 20px; padding: 20px; margin-bottom: 12px;
        }
        /* ── Empty state ── */
        .empty-state {
            display: flex; flex-direction: column; align-items: center;
            gap: 10px; padding: 40px 20px; text-align: center;
        }
        .empty-state-icon { font-size: 2.5rem; opacity: 0.4; }
        .empty-state-text { font-size: 0.82rem; color: var(--muted); line-height: 1.6; }
        .empty-state-cta {
            margin-top: 4px; padding: 10px 22px; border-radius: 12px;
            background: rgba(0,255,65,0.08); border: 1px solid rgba(0,255,65,0.2);
            color: var(--neon); font-size: 0.78rem; font-weight: 700; cursor: pointer;
            font-family: 'Outfit', sans-serif; transition: background 0.2s;
        }
        .empty-state-cta:hover { background: rgba(0,255,65,0.14); }

        </style>
</head>
<body>
<div id="loading-screen">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:2.2rem;letter-spacing:6px;color:rgba(0,255,65,0.9);text-shadow:0 0 30px rgba(0,255,65,0.4);margin-bottom:20px;">VUMBUA</div>
    <div class="spinner"></div>
    <div class="loading-text" style="margin-top:12px;">Loading your wallet...</div>
</div>

<!-- ══════════════════════════════════════════════════════════
     FLOATING CONFIRM-REQUIRED BANNER
     Shown when opponent has declared and it's your turn.
     Managed by showConfirmBanner() / hideConfirmBanner()
══════════════════════════════════════════════════════════ -->
<div id="confirm-action-banner" role="alert" aria-live="assertive">
    <div class="banner-inner">
        <div class="banner-top-row">
            <div class="banner-alarm-dot">⚠️</div>
            <div class="banner-text">
                <div class="banner-badge">⚡ Action Required</div>
                <div class="banner-title" id="banner-title">Opponent posted results</div>
                <div class="banner-sub" id="banner-sub">Confirm or dispute before time runs out</div>
            </div>
            <button class="banner-dismiss" id="banner-dismiss-btn" aria-label="Dismiss" title="Dismiss (banner will reappear on reload)">✕</button>
        </div>

        <!-- Score declared by opponent -->
        <div class="banner-score-row">
            <div class="banner-score-team">
                <div class="banner-score-team-name" id="banner-my-team">YOU</div>
                <div class="banner-score-num my-score" id="banner-my-score">?</div>
            </div>
            <div class="banner-score-sep">—</div>
            <div class="banner-score-team">
                <div class="banner-score-team-name" id="banner-opp-team">OPP</div>
                <div class="banner-score-num" id="banner-opp-score">?</div>
            </div>
        </div>
        <div class="banner-result-line" id="banner-result-line"></div>

        <!-- Countdown -->
        <div class="banner-clock-row" id="banner-clock-row">
            <div class="banner-clock-label-text">⏰ Time left<br>to respond</div>
            <div class="banner-clock-digits">
                <div class="banner-digit-group">
                    <span class="banner-clock-num" id="banner-min">--</span>
                    <span class="banner-digit-label">min</span>
                </div>
                <span class="banner-clock-colon">:</span>
                <div class="banner-digit-group">
                    <span class="banner-clock-num" id="banner-sec">--</span>
                    <span class="banner-digit-label">sec</span>
                </div>
            </div>
        </div>

        <!-- Shrinking bar -->
        <div class="banner-progress">
            <div class="banner-progress-fill" id="banner-progress-fill" style="width:100%"></div>
        </div>

        <div class="banner-expired-msg" id="banner-expired-msg">
            ⏱ Time expired — this match may be auto-settled soon.
        </div>

        <!-- Buttons -->
        <div class="banner-actions">
            <button class="banner-btn banner-btn-confirm" id="banner-confirm-btn">✅ Confirm Score</button>
            <button class="banner-btn banner-btn-dispute" id="banner-dispute-btn">⚔️ Dispute</button>
        </div>
    </div>
</div>

<div class="pitch-bg"></div>
<div class="pitch-lines"></div>
<div class="noise-overlay"></div>

<div class="app" id="main-content" style="display:none;">
    <nav class="topnav">
        <span class="nav-logo">VUMBUA<span style="color:rgba(0,255,65,0.4);font-size:0.5em;vertical-align:super;letter-spacing:0px;">⚽</span></span>
        <div class="nav-right">
            <div class="nav-user" onclick="openProfileModal()">
                <div class="avatar" id="avatar-letter">P</div>
                <span class="nav-username" id="username-display">@Player</span>
            </div>
            <button class="btn-logout" id="logoutBtn">Logout</button>
        </div>
    </nav>
    <div class="content">
        <div class="wallet-card">
            <div class="scan-line"></div>
            <div class="wallet-label" style="margin-bottom:14px;">
                <span style="font-size:0.58rem;letter-spacing:3px;text-transform:uppercase;color:#333;">Available Balance</span>
                <span class="realtime-indicator" id="realtime-indicator" title="Live updates active" style="color:rgba(0,255,65,0.7);">
                    <span class="dot"></span> LIVE
                </span>
            </div>
            <div class="wallet-amount">
                <span class="wallet-currency">KES</span><span id="balance">0.00</span>
            </div>
            <div class="wallet-meta" style="margin-top:18px;display:flex;justify-content:space-between;align-items:flex-end;">
                <div class="wallet-phone" style="font-size:0.72rem;color:#333;">
                    <span style="color:#3a3a4a;letter-spacing:1px;text-transform:uppercase;font-size:0.6rem;">Team</span><br>
                    <span id="team-display" style="color:#666;font-weight:600;">—</span>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:0.55rem;letter-spacing:2px;text-transform:uppercase;color:#2a2a38;margin-bottom:3px;">Username</div>
                    <div style="font-size:0.72rem;color:#3a3a50;font-weight:600;" id="wallet-username-display">@player</div>
                </div>
            </div>
        </div>
        <div class="wallet-actions" style="margin-bottom:24px;">
            <button class="btn-action btn-deposit" onclick="openDepositModal()">
                <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M12 5v14M5 12l7 7 7-7"/></svg>
                Deposit
            </button>
            <button class="btn-action btn-withdraw" onclick="openWithdrawModal()">
                <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
                Withdraw
            </button>
        </div>

        <div class="section-header" style="margin-bottom:12px;">
            <div class="section-title">QUICK PLAY</div>
        </div>
        <div class="quick-grid">
            <div class="quick-card" onclick="document.querySelector('.friend-section').scrollIntoView({behavior: 'smooth'})">
                <span class="quick-icon">⚔️</span>
                <div class="quick-label">Piga Rafiki</div>
            </div>
            <div class="quick-card">
                <span class="quick-icon">🏆</span>
                <div class="quick-label">Tournaments</div>
            </div>
            <div class="quick-card">
                <span class="quick-icon">📊</span>
                <div class="quick-label">Matokeo</div>
            </div>
        </div>

        <div class="tournaments">
            <div class="section-header">
                <div class="section-title">LIVE NOW</div>
                <span class="section-link" onclick="loadTournaments()">Ona zote →</span>
            </div>
            <div id="tournament-list">
                <!-- Tournament cards will be injected safely via JS -->
            </div>
        </div>

        <div class="friend-section">
            <div class="section-header">
                <div class="section-title">CHALLENGE RAFIKI</div>
            </div>
            <div class="friend-card">
                <div class="friend-buttons">
                    <button class="btn-friend btn-friend-create" onclick="openCreateMatchModal()">
                        ⚔️ Create Challenge
                    </button>
                    <button class="btn-friend btn-friend-join" onclick="openJoinMatchModal()">
                        🎯 Join Challenge
                    </button>
                </div>
                <div class="friend-info" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:16px;">
                    <div style="display:flex;gap:8px;align-items:flex-start;"><span>💰</span><span>Equal stakes from both players</span></div>
                    <div style="display:flex;gap:8px;align-items:flex-start;"><span>🏆</span><span>Winner takes 90% of the pot</span></div>
                    <div style="display:flex;gap:8px;align-items:flex-start;"><span>📸</span><span>Upload screenshot to settle</span></div>
                    <div style="display:flex;gap:8px;align-items:flex-start;"><span>⏱️</span><span>Codes expire in 30 minutes</span></div>
                </div>
            </div>
        </div>

        <!-- MY MATCHES SECTION -->
        <div class="my-matches-section">
            <div class="section-header">
                <div class="section-title">MY MATCHES</div>
                <span class="section-link" onclick="loadMyFriendMatches()">Refresh ↻</span>
            </div>
            <div id="my-matches-list" class="matches-list">
                <!-- Dynamically loaded -->
            </div>
        </div>
    </div>
</div>

<div class="bottom-nav">
    <div class="nav-item active">
        <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
        <span class="nav-item-label">Home</span>
    </div>
    <div class="nav-item">
        <svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
        <span class="nav-item-label">Chat</span>
    </div>
    <div class="nav-item">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
        <span class="nav-item-label">Matches</span>
    </div>
    <div class="nav-item">
        <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
        <span class="nav-item-label">Profile</span>
    </div>
</div>

<!-- ═══ PROFILE MODAL ═══ -->
<div class="modal-overlay profile-modal" id="profile-modal" onclick="if(event.target === this) closeModal('profile-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title">YOUR PROFILE</div>
        <p class="modal-subtitle">Update your eFootball team name</p>
        <div class="profile-field">
            <label>Username</label>
            <input type="text" id="profile-username" class="modal-input" disabled>
        </div>
        <div class="profile-field">
            <label>Team Name</label>
            <input type="text" id="profile-team" class="modal-input" placeholder="e.g., Manchester United">
        </div>
        <div class="balance-insufficient" id="profile-error"></div>
        <button class="btn-mpesa" style="background:var(--neon);color:#000;" onclick="saveProfile()">SAVE CHANGES</button>
        <button class="btn-cancel" onclick="closeModal('profile-modal')">Cancel</button>
    </div>
</div>

<!-- ═══ DEPOSIT MODAL ═══ -->
<div class="modal-overlay" id="deposit-modal" onclick="if(event.target === this) closeModal('deposit-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title">DEPOSIT</div>
        <p class="modal-subtitle">Top up via M-PESA STK Push</p>

        <div class="step active" id="deposit-step-1">
            <div class="modal-input-group">
                <label>Amount (KES)</label>
                <div class="amount-presets">
                    <button class="preset-btn" onclick="selectPreset(this,100)">100</button>
                    <button class="preset-btn" onclick="selectPreset(this,200)">200</button>
                    <button class="preset-btn" onclick="selectPreset(this,500)">500</button>
                    <button class="preset-btn" onclick="selectPreset(this,1000)">1000</button>
                </div>
                <input type="number" id="deposit-amount" class="modal-input" placeholder="Enter amount" min="10">
            </div>
            <div class="modal-input-group">
                <label>M-PESA Number</label>
                <input type="tel" id="deposit-phone" class="modal-input" placeholder="07XX XXX XXX">
            </div>
            <div class="balance-insufficient" id="deposit-error"></div>
            <button class="btn-mpesa" onclick="processDeposit()">PAY WITH M-PESA 📲</button>
            <button class="btn-cancel" onclick="closeModal('deposit-modal')">Cancel</button>
        </div>

        <div class="step" id="deposit-step-2">
            <div class="friend-info" style="text-align:center; margin-bottom:20px;">
                <div style="font-size:2rem; margin-bottom:10px;">📲</div>
                <strong style="color:var(--text);">Check your phone!</strong><br>
                An M-PESA prompt has been sent. Enter your PIN to complete the payment.
            </div>
            <div style="text-align:center; color:var(--muted); font-size:0.8rem; margin-bottom:20px;" id="deposit-status-text">Waiting for payment...</div>
            <button class="btn-cancel" onclick="closeModal('deposit-modal')">Cancel</button>
        </div>
    </div>
</div>

<!-- ═══ WITHDRAW MODAL ═══ -->
<div class="modal-overlay" id="withdraw-modal" onclick="if(event.target === this) closeModal('withdraw-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title">WITHDRAW</div>
        <p class="modal-subtitle">Send winnings to your M-PESA</p>
        <div class="modal-input-group">
            <label>Amount (KES)</label>
            <input type="number" id="withdraw-amount" class="modal-input" placeholder="Enter amount" min="50">
        </div>
        <div class="modal-input-group">
            <label>M-PESA Number</label>
            <input type="tel" id="withdraw-phone" class="modal-input" placeholder="07XX XXX XXX">
        </div>
        <div class="balance-insufficient" id="withdraw-error"></div>
        <button class="btn-mpesa" onclick="processWithdraw()">WITHDRAW NOW →</button>
        <button class="btn-cancel" onclick="closeModal('withdraw-modal')">Cancel</button>
    </div>
</div>

<!-- ═══ TOURNAMENT JOIN / CHALLENGE MODAL ═══ -->
<div class="modal-overlay" id="challenge-modal" onclick="if(event.target === this) closeModal('challenge-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title" id="challenge-title">JOIN TOURNAMENT</div>
        <p class="modal-subtitle">Choose how to pay the entry fee</p>

        <div class="step active" id="challenge-step-1">
            <div class="match-details-box">
                <div class="match-detail-row"><span class="match-detail-label">Tournament</span><span class="match-detail-value" id="challenge-name">—</span></div>
                <div class="match-detail-row"><span class="match-detail-label">Entry Fee</span><span class="match-detail-value neon" id="challenge-fee">KES 0</span></div>
            </div>
            <div class="balance-insufficient" id="challenge-error"></div>
            <button class="btn-mpesa" style="background:var(--neon);color:#000;margin-bottom:10px;" onclick="confirmChallenge('wallet')">PAY FROM WALLET 💰</button>
            <button class="btn-mpesa" onclick="confirmChallenge('mpesa')">PAY WITH M-PESA 📲</button>
            <button class="btn-cancel" onclick="closeModal('challenge-modal')">Cancel</button>
        </div>

        <div class="step" id="challenge-step-2">
            <div class="friend-info" style="text-align:center; margin-bottom:20px;">
                <div style="font-size:2rem; margin-bottom:10px;">📲</div>
                Check your phone for the M-PESA prompt. Enter your PIN to complete.
            </div>
            <div style="text-align:center; color:var(--muted); font-size:0.8rem; margin-bottom:20px;" id="challenge-status">Waiting for payment...</div>
            <button class="btn-cancel" onclick="closeModal('challenge-modal')">Cancel</button>
        </div>
    </div>
</div>

<!-- ═══ ROOM CODE MODAL ═══ -->
<div class="modal-overlay" id="room-modal" onclick="if(event.target === this) closeModal('room-modal')">
    <div class="modal-sheet" style="text-align:center;">
        <div class="modal-handle"></div>
        <div class="modal-title">YOU'RE IN! 🏆</div>
        <p class="modal-subtitle">Use this code to enter the game room</p>
        <div style="font-family:'Bebas Neue',sans-serif; font-size:3.5rem; color:var(--neon); letter-spacing:8px; margin:20px 0; text-shadow:0 0 30px rgba(0,255,65,0.4);" id="room-code-display">—</div>
        <button class="btn-mpesa" style="background:var(--neon);color:#000;margin-bottom:10px;" onclick="shareRoomCode()">📲 Share via WhatsApp</button>
        <button class="btn-cancel" onclick="closeModal('room-modal')">Close</button>
    </div>
</div>

<!-- ═══ CREATE FRIEND MATCH MODAL ═══ -->
<div class="modal-overlay" id="create-friend-modal" onclick="if(event.target === this) closeModal('create-friend-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title">CREATE CHALLENGE ⚔️</div>
        <p class="modal-subtitle">Enter your eFootball room code & set your wager.</p>

        <!-- Guidelines Info Box -->
        <div style="background: rgba(0,255,65,0.05); border: 1px solid rgba(0,255,65,0.2); border-radius: 12px; padding: 14px 16px; margin-bottom: 16px; font-size: 0.75rem; color: var(--muted); line-height: 1.4;">
            <strong style="color: var(--text);">How to get your code:</strong><br>
            1. Create a Friends Match room in eFootball<br>
            2. eFootball will generate a code (e.g., ABC123)<br>
            3. Paste it below & share with your friend<br>
            <a href="EFOOTBALL_GUIDELINES.md" target="_blank" style="color: var(--neon); text-decoration: none;">📖 Full guidelines →</a>
        </div>

        <div class="modal-input-group">
            <label>eFootball Room Code</label>
            <input type="text" id="friend-efootball-code" class="modal-input" placeholder="ABC123" style="text-transform:uppercase; letter-spacing:4px; font-size:1.3rem; text-align:center;" maxlength="8">
        </div>

        <div class="modal-input-group">
            <label>Your Wager (KES)</label>
            <div class="amount-presets">
                <button class="preset-btn" onclick="selectFriendPreset(this,50)">50</button>
                <button class="preset-btn" onclick="selectFriendPreset(this,100)">100</button>
                <button class="preset-btn selected" onclick="selectFriendPreset(this,200)">200</button>
                <button class="preset-btn" onclick="selectFriendPreset(this,500)">500</button>
            </div>
            <input type="number" id="friend-wager-input" class="modal-input" value="200" min="50" oninput="updateFriendBreakdown()">
        </div>
        <div class="breakdown-box">
            <div class="breakdown-row"><span>Your stake</span><span>KES <span id="friend-your-stake">200</span></span></div>
            <div class="breakdown-row"><span>Opponent's stake</span><span>KES <span id="friend-opp-stake">200</span></span></div>
            <div class="breakdown-row"><span>Total pot</span><span>KES <span id="friend-total-pot">400</span></span></div>
            <div class="breakdown-row"><span>Platform fee (10%)</span><span>- KES <span id="friend-platform-fee">40</span></span></div>
            <div class="breakdown-row total"><span>Winner gets</span><span>KES <span id="friend-winner-prize">360</span></span></div>
        </div>
        <div class="balance-insufficient" id="create-friend-error"></div>
        <button class="btn-mpesa" id="create-friend-btn" style="background:var(--neon);color:#000;" onclick="createFriendMatch()">
            CREATE CHALLENGE (Pay KES <span id="create-friend-amount">200</span>)
        </button>
        <button class="btn-cancel" onclick="closeModal('create-friend-modal')">Cancel</button>
    </div>
</div>

<!-- ═══ WAITING FOR OPPONENT MODAL ═══ -->
<div class="modal-overlay" id="waiting-friend-modal">
    <div class="modal-sheet" style="text-align:center;">
        <div class="modal-handle"></div>
        <div class="modal-title">WAITING FOR OPPONENT ⏳</div>
        <p class="modal-subtitle" id="friend-match-timer">Expires in 30:00</p>
        <div style="font-family:'Bebas Neue',sans-serif; font-size:3rem; color:var(--neon); letter-spacing:8px; margin:20px 0; text-shadow:0 0 30px rgba(0,255,65,0.4);" id="friend-match-code">ABC123</div>
        <p style="font-size: 0.75rem; color: var(--muted); margin-bottom: 20px;">Share this code with your friend on eFootball</p>
        <div class="friend-info" style="margin-bottom:20px;">
            Your wager: KES <strong id="waiting-stake-display">0</strong> · Winner gets: KES <strong id="waiting-prize-display">0</strong>
        </div>
        <button class="btn-mpesa" style="background:var(--neon);color:#000;margin-bottom:10px;" onclick="shareFriendCode()">📲 Share Code via WhatsApp</button>
        <button class="btn-cancel" onclick="cancelFriendMatch()">Cancel Match (Refund)</button>
    </div>
</div>

<!-- ═══ JOIN FRIEND MATCH MODAL ═══ -->
<div class="modal-overlay" id="join-friend-modal" onclick="if(event.target === this) closeModal('join-friend-modal')">
    <div class="modal-sheet">
        <div class="modal-handle"></div>
        <div class="modal-title">JOIN CHALLENGE 🎯</div>
        <p class="modal-subtitle">Enter the eFootball room code your opponent shared.</p>

        <!-- Guidelines Info Box -->
        <div style="background: rgba(255,180,0,0.05); border: 1px solid rgba(255,180,0,0.2); border-radius: 12px; padding: 14px 16px; margin-bottom: 16px; font-size: 0.75rem; color: var(--muted); line-height: 1.4;">
            <strong style="color: var(--text);">📌 Important:</strong><br>
            • Your opponent created a room in eFootball<br>
            • They're sharing the room code with you<br>
            • Use that exact code here to join<br>
            <a href="EFOOTBALL_GUIDELINES.md" target="_blank" style="color: #ffb400; text-decoration: none;">📖 Full guidelines →</a>
        </div>

        <div class="modal-input-group">
            <label>eFootball Room Code</label>
            <input type="text" id="join-friend-code" class="modal-input" placeholder="ABC123" style="text-transform:uppercase; letter-spacing:4px; font-size:1.3rem; text-align:center;" maxlength="8">
        </div>
        <div class="balance-insufficient" id="join-friend-error"></div>
        <button class="btn-mpesa" style="background:var(--neon);color:#000;" onclick="joinFriendMatch()">JOIN & PAY WAGER</button>
        <button class="btn-cancel" onclick="closeModal('join-friend-modal')">Cancel</button>
    </div>
</div>

<!-- ── Global Toast ── -->
<div class="modal-toast" id="global-toast">
    <span class="toast-icon" id="toast-icon">✅</span>
    <div class="toast-body">
        <div class="toast-title" id="toast-title"></div>
        <div class="toast-msg" id="toast-msg"></div>
    </div>
</div>

<!-- ═══ DECLARE SCORE MODAL ═══ -->
<div class="modal-overlay" id="report-result-modal" onclick="if(event.target===this)closeModal('report-result-modal')">
    <div class="modal-sheet" style="max-height:92vh;overflow-y:auto;">
        <div class="modal-handle"></div>

        <!-- Step 1: Match info (hidden, skipped) -->
        <div class="step" id="declare-step-1" style="display:none;">
            <div class="match-details-box" id="report-match-details"></div>
        </div>

        <!-- Step 2: Upload screenshot -->
        <div class="step" id="declare-step-2">
            <div class="modal-title">UPLOAD SCREENSHOT 📲</div>
            <p class="modal-subtitle">Tap below to upload — Gemini reads the score automatically.</p>

            <!-- Match details for context -->
            <div id="score-summary-box" class="match-details-box" style="margin-bottom:18px;" id="upload-match-context">
                <div id="report-match-details-mini"></div>
            </div>

            <!-- Upload zone -->
            <div class="modal-input-group">
                <div class="screenshot-upload-zone" id="upload-zone" style="padding:32px 20px;">
                    <input type="file" id="screenshot-file-input" accept="image/jpeg,image/png,image/webp"
                        onchange="handleScreenshotSelected(this.files[0])">
                    <span class="upload-icon" id="upload-icon" style="font-size:2.8rem;">📲</span>
                    <div class="upload-label" id="upload-label">
                        <strong style="font-size:0.9rem;">Tap to upload screenshot</strong><br>
                        <span style="font-size:0.75rem;color:#444;margin-top:4px;display:block;">Upload the "Full Time" screen from eFootball</span>
                    </div>
                    <div class="upload-hint" style="margin-top:16px;padding-top:12px;border-top:1px solid rgba(0,255,65,0.08);">
                        <span>📷 JPEG</span><span>·</span><span>🖼 PNG</span><span>·</span><span>Max 10MB</span>
                    </div>
                    <img class="screenshot-thumb" id="screenshot-thumb" alt="preview">
                </div>
                <div class="upload-progress" id="upload-progress">
                    <div class="upload-progress-fill indeterminate" id="upload-progress-fill"></div>
                </div>
                <div style="text-align:center;margin-top:10px;font-size:0.7rem;color:#333;letter-spacing:1px;">
                    🤖 Gemini AI reads the score automatically
                </div>
            </div>

            <div class="balance-insufficient" id="declare-error-2"></div>
            <button class="btn-mpesa" id="declare-submit-btn" style="background:var(--neon);color:#000;font-size:0.9rem;letter-spacing:1.5px;" onclick="submitScoreDeclaration()">
                ✅ SUBMIT RESULT
            </button>
            <button class="btn-cancel" onclick="closeModal('report-result-modal')">← Close</button>
        </div>

        <!-- Step 3: Waiting for opponent -->
        <div class="step" id="declare-step-3" style="text-align:center;">
            <div style="font-size:3rem;margin-bottom:12px;animation:pulse 2s infinite;">⏳</div>
            <div class="modal-title" style="margin-bottom:6px;">RESULT SUBMITTED</div>
            <p class="modal-subtitle" style="margin-bottom:24px;">Your opponent has 2 hours to confirm or dispute.</p>
            <div style="background:linear-gradient(135deg,rgba(0,255,65,0.07),rgba(0,255,65,0.03));border:1px solid rgba(0,255,65,0.2);border-radius:16px;padding:20px;margin:0 0 20px;">
                <div style="font-size:0.58rem;letter-spacing:3px;text-transform:uppercase;color:#3a3a4a;margin-bottom:10px;">Gemini detected</div>
                <div id="declared-score-recap" style="font-family:'Bebas Neue',sans-serif;font-size:3rem;color:#fff;letter-spacing:6px;text-shadow:0 0 20px rgba(255,255,255,0.1);">—</div>
                <div id="declared-result-recap" style="font-size:0.82rem;margin-top:8px;font-weight:600;"></div>
            </div>
            <div style="background:rgba(255,180,0,0.06);border:1px solid rgba(255,180,0,0.15);border-radius:12px;padding:14px;margin-bottom:20px;font-size:0.8rem;color:#aaa;line-height:1.6;">
                ⚡ You <strong style="color:#ffb400;">auto-win</strong> in <strong class="countdown-timer" id="declare-countdown" data-deadline="">—</strong> if they don't respond.
            </div>
            <button class="btn-cancel" style="font-weight:700;" onclick="closeModal('report-result-modal')">← Back to Dashboard</button>
        </div>

        <!-- Step 4: Opponent needs to confirm (shown to the OPPONENT) -->
        <div class="step" id="declare-step-confirm" style="text-align:center;">
            <div style="font-size:3rem;margin-bottom:12px;">⚠️</div>
            <div class="modal-title">CONFIRM THE SCORE</div>
            <p class="modal-subtitle">Your opponent declared this result. Do you agree?</p>
            <div style="background:rgba(255,180,0,0.06);border:1px solid rgba(255,180,0,0.25);border-radius:12px;padding:18px;margin:16px 0;text-align:center;">
                <div style="font-size:0.65rem;letter-spacing:2px;text-transform:uppercase;color:#888;margin-bottom:8px;">Opponent declared</div>
                <div id="confirm-score-display" style="font-family:'Bebas Neue',sans-serif;font-size:2.5rem;color:#fff;letter-spacing:4px;">0 — 0</div>
                <div id="confirm-result-display" style="font-size:0.85rem;color:#aaa;margin-top:6px;"></div>
            </div>

            <!-- Confirm upload -->
            <div style="font-size:0.8rem;color:#888;margin-bottom:12px;">Upload your screenshot to confirm (optional but recommended)</div>
            <div class="modal-input-group" style="margin-bottom:16px;">
                <div class="screenshot-upload-zone" id="confirm-upload-zone" style="padding:12px;">
                    <input type="file" id="confirm-screenshot-input" accept="image/jpeg,image/png,image/webp"
                        onchange="handleConfirmScreenshot(this.files[0])">
                    <div class="upload-label" id="confirm-upload-label" style="font-size:0.8rem;">
                        <strong>Upload your screenshot</strong> (optional)
                    </div>
                    <img class="screenshot-thumb" id="confirm-screenshot-thumb" alt="preview" style="max-height:80px;">
                </div>
            </div>

            <div class="balance-insufficient" id="confirm-error"></div>
            <button class="btn-mpesa" style="background:var(--neon);color:#000;margin-bottom:10px;" onclick="confirmOpponentScore()">
                ✅ YES, CONFIRM SCORE
            </button>
            <button class="btn-mpesa" style="background:rgba(255,68,68,0.15);color:#ff6666;border:1px solid rgba(255,68,68,0.3);" onclick="showDisputeForm()">
                ❌ DISPUTE — SCORE IS WRONG
            </button>
        </div>

        <!-- Step 5: Dispute form -->
        <div class="step" id="declare-step-dispute" style="text-align:center;">
            <div style="font-size:3rem;margin-bottom:12px;">🔍</div>
            <div class="modal-title">RAISE A DISPUTE</div>
            <p class="modal-subtitle">Tell us what the real score was and upload your screenshot.</p>
            <div class="modal-input-group">
                <label style="text-align:left;display:block;">What was the REAL score?</label>
                <div style="display:flex;align-items:center;justify-content:center;gap:12px;margin:12px 0;">
                    <div style="text-align:center;">
                        <div style="font-size:0.6rem;letter-spacing:1px;color:#888;margin-bottom:4px;" id="dispute-my-label">MY GOALS</div>
                        <div style="display:flex;align-items:center;gap:6px;">
                            <button onclick="adjustDisputeScore('my',-1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #333;background:transparent;color:#fff;cursor:pointer;">−</button>
                            <div id="dispute-my-score" style="font-family:'Bebas Neue',sans-serif;font-size:3rem;color:var(--neon);min-width:40px;text-align:center;">0</div>
                            <button onclick="adjustDisputeScore('my',1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #333;background:transparent;color:#fff;cursor:pointer;">+</button>
                        </div>
                    </div>
                    <div style="font-family:'Bebas Neue',sans-serif;font-size:1.5rem;color:#444;padding-top:16px;">—</div>
                    <div style="text-align:center;">
                        <div style="font-size:0.6rem;letter-spacing:1px;color:#888;margin-bottom:4px;">OPP GOALS</div>
                        <div style="display:flex;align-items:center;gap:6px;">
                            <button onclick="adjustDisputeScore('opp',-1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #333;background:transparent;color:#fff;cursor:pointer;">−</button>
                            <div id="dispute-opp-score" style="font-family:'Bebas Neue',sans-serif;font-size:3rem;color:#ff4444;min-width:40px;text-align:center;">0</div>
                            <button onclick="adjustDisputeScore('opp',1)" style="width:30px;height:30px;border-radius:50%;border:1px solid #333;background:transparent;color:#fff;cursor:pointer;">+</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-input-group">
                <div class="screenshot-upload-zone" id="dispute-upload-zone" style="padding:12px;">
                    <input type="file" id="dispute-screenshot-input" accept="image/jpeg,image/png,image/webp"
                        onchange="handleDisputeScreenshot(this.files[0])">
                    <div class="upload-label" style="font-size:0.8rem;"><strong>Upload YOUR screenshot</strong> <span style="color:#ff4444;">*required</span></div>
                    <img class="screenshot-thumb" id="dispute-screenshot-thumb" alt="preview" style="max-height:80px;">
                </div>
            </div>
            <div class="balance-insufficient" id="dispute-error"></div>
            <button class="btn-mpesa" style="background:rgba(255,68,68,0.15);color:#ff6666;border:1px solid rgba(255,68,68,0.3);margin-bottom:10px;" onclick="submitDispute()">
                SUBMIT DISPUTE →
            </button>
            <button class="btn-cancel" onclick="switchStep('report-result-modal','confirm')">← Back</button>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.js" onerror="console.error('❌ Supabase CDN failed to load')"></script>
<script>
    // --- Escape function for XSS prevention ---
    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // --- Helper to safely create elements with text content ---
    function createElementSafe(tag, attributes = {}, textContent = '') {
        const el = document.createElement(tag);
        Object.entries(attributes).forEach(([key, value]) => el.setAttribute(key, value));
        if (textContent) el.textContent = escapeHtml(textContent);
        return el;
    }

    // --- Global variables ---
    let authToken = sessionStorage.getItem('supabaseToken');
    let currentUser = null;
    let currentBalance = 0;
    let currentPhone = '';
    let currentUsername = '';
    let currentTeam = '';
    let currentCheckoutId = null;
    let pollInterval = null;
    let currentFriendMatch = null;
    let friendMatchTimer = null;
    let currentReportMatch = null;
    let currentTournamentId = null, currentTournamentFee = 0, currentTournamentName = '';
    let balanceRefreshInterval = null;
    let matchStatusPollInterval = null;
    let realtimeChannel = null;

    // --- Utility functions ---
    function showError(elementId, message) {
        const el = document.getElementById(elementId);
        if (el) { el.textContent = escapeHtml(message); el.style.display = 'block'; }
    }
    function hideError(elementId) {
        const el = document.getElementById(elementId);
        if (el) el.style.display = 'none';
    }

    // Auto-detect: Use localhost for local dev, Koyeb URL for production
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const API = isLocal 
        ? 'http://localhost:3000' 
        : '/api';
    
    // Supabase configuration
    // Always use production Supabase — we only have one project.
    // The frontend API endpoint (localhost vs Koyeb) is separate from the Supabase project.
    const SUPABASE_URL = 'https://wqnnuqudxsnxldlgxhwr.supabase.co';
    const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Indxbm51cXVkeHNueGxkbGd4aHdyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA5MDQ4NDUsImV4cCI6MjA4NjQ4MDg0NX0.MIoGi_PiwbGPrAxEfaypLLlpNkHUNliDNFoehdf7uPg';

    console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
    console.log('🔍 API URL:', API);

    // --- Supabase realtime client (will be created in loadDashboard with fresh token) ---
    let supabaseRealtime = null;

    // --- Enhanced fetch with timeout ---
    async function fetchWithAuth(url, options = {}, timeoutMs = 8000) {
        if (!authToken) { window.location.href = '/login'; return; }
        // For multipart uploads, let the browser set Content-Type (with boundary).
        // Callers signal this by passing headers: {} or headers: { 'Content-Type': null }
        const isMultipart = options.body instanceof FormData;
        const headers = {
            ...(isMultipart ? {} : { 'Content-Type': 'application/json' }),
            'Authorization': \`Bearer \${authToken}\`,
            ...options.headers
        };
        // Remove any explicit null/undefined header values (clean signal from caller)
        Object.keys(headers).forEach(k => { if (headers[k] == null) delete headers[k]; });
        const fullUrl = url.startsWith('http') ? url : \`\${API}\${url}\`;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
        
        try {
            const res = await fetch(fullUrl, { ...options, headers, signal: controller.signal });
            clearTimeout(timeoutId);
            if (res.status === 401) {
                sessionStorage.removeItem('supabaseToken');
                sessionStorage.removeItem('supabaseUser');
                window.location.href = '/login';
                return;
            }
            return res;
        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                throw new Error(\`Request timeout after \${timeoutMs}ms\`);
            }
            throw err;
        }
    }

    // --- Real‑time balance subscription ---
    async function subscribeToBalance(userId) {
        if (!supabaseRealtime) {
            console.warn('⚠️ Supabase realtime not available, falling back to polling');
            startBalanceAutoRefresh();
            return;
        }
        
        console.log('🔔 Setting up realtime subscription for wallet:', userId);
        
        // Clean up existing channel first
        if (realtimeChannel) {
            console.log('🧹 Removing old realtime channel...');
            supabaseRealtime.removeChannel(realtimeChannel);
            realtimeChannel = null;
        }
        
        realtimeChannel = supabaseRealtime
            .channel(\`wallet-\${userId}\`)
            .on(
                'postgres_changes',
                {
                    event: 'UPDATE',
                    schema: 'public',
                    table: 'wallets',
                    filter: \`user_id=eq.\${userId}\`
                },
                (payload) => {
                    console.log('🔔 Real-time balance update received:', payload);
                    
                    // CRITICAL: Validate this update is for the current user
                    if (payload.new.user_id !== currentUser.id) {
                        console.error('❌ SECURITY: Received balance update for different user!');
                        console.error('   Expected:', currentUser.id);
                        console.error('   Received:', payload.new.user_id);
                        return; // Ignore updates for other users
                    }
                    
                    console.log(\`💰 Real-time balance update: \${currentBalance} → \${payload.new.balance}\`);
                    currentBalance = payload.new.balance;
                    updateBalanceDisplay();
                }
            )
            .subscribe((status) => {
                console.log('🔌 Realtime subscription status:', status);
                const indicator = document.getElementById('realtime-indicator');
                if (indicator) {
                    indicator.style.opacity = status === 'SUBSCRIBED' ? '1' : '0.5';
                }
                
                if (status === 'SUBSCRIBED') {
                    console.log('✅ Realtime subscription active for user:', userId);
                } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
                    console.error('❌ Realtime subscription failed:', status);
                    console.log('📡 Falling back to polling...');
                    startBalanceAutoRefresh(30000); // Poll every 30s if realtime fails
                }
            });
        
        console.log('✅ Realtime channel created:', \`wallet-\${userId}\`);
    }

    // --- Load user data and balance with timeout guard ---
    async function loadDashboard() {
        try {
            console.log('🚀 Starting loadDashboard...');
            
            // CRITICAL: Clean up any existing realtime connections first
            if (supabaseRealtime && realtimeChannel) {
                console.log('🧹 Cleaning up old realtime connection...');
                supabaseRealtime.removeChannel(realtimeChannel);
                realtimeChannel = null;
            }
            
            // Get fresh auth token from localStorage
            authToken = sessionStorage.getItem('supabaseToken');
            if (!authToken) {
                console.error('❌ No auth token found');
                window.location.href = '/login';
                return;
            }
            
            // Create fresh Supabase realtime client with current user's token
            if (typeof supabase !== 'undefined') {
                console.log('🔌 Creating new Supabase realtime client with fresh token...');
                supabaseRealtime = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
                    global: { headers: { Authorization: \`Bearer \${authToken}\` } },
                    realtime: { params: { apikey: SUPABASE_ANON_KEY } }
                });
            } else {
                console.error('❌ Supabase SDK not loaded! Realtime will be unavailable.');
            }
            
            const userStr = sessionStorage.getItem('supabaseUser');
            if (!userStr) { window.location.href = '/login'; return; }
            currentUser = JSON.parse(userStr);
            console.log('👤 Loaded user:', currentUser.id, currentUser.phone);
            
            currentUsername = currentUser.user_metadata?.username || currentUser.phone?.substring(0,8) || 'Player';
            const walletUsernameEl = document.getElementById('wallet-username-display');
            if (walletUsernameEl) walletUsernameEl.textContent = '@' + currentUsername;
            document.getElementById('username-display').innerText = '@' + currentUsername;
            document.getElementById('avatar-letter').innerText = currentUsername.charAt(0).toUpperCase();
            if (currentUser.phone) {
                let phone = currentUser.phone.replace('+254', '0');
                currentPhone = phone;
                const dPhone = document.getElementById('deposit-phone');
                const wPhone = document.getElementById('withdraw-phone');
                if (dPhone) dPhone.value = phone;
                if (wPhone) wPhone.value = phone;
            }

            console.log('🚀 Loading dashboard data...');
            
            // CRITICAL: Load balance first and ensure it succeeds
            let balanceLoaded = false;
            try {
                await refreshBalance(3); // Try 3 times
                if (currentBalance >= 0) { // Check if balance was actually set
                    balanceLoaded = true;
                    console.log('✅ Balance loaded successfully:', currentBalance);
                }
            } catch (e) {
                console.error('❌ Balance fetch failed:', e);
            }
            
            if (!balanceLoaded) {
                console.error('❌ CRITICAL: Balance could not be loaded!');
                // Force set to 0 explicitly and show warning
                currentBalance = 0;
                updateBalanceDisplay();
                alert('⚠️ Could not load your balance. Please refresh the page.');
            }
            
            // Load profile (non-critical)
            await loadProfile().catch(e => console.warn('Profile fetch failed:', e));

            // Load tournaments and matches in background (don't block)
            loadTournaments();
            loadMyFriendMatches();
            
            // Set up real-time subscription with fresh client
            if (supabaseRealtime) {
                console.log('🔔 Setting up realtime subscription for user:', currentUser.id);
                subscribeToBalance(currentUser.id);
            } else {
                console.warn('⚠️ Realtime unavailable, using polling only');
                startBalanceAutoRefresh(30000); // Poll every 30s
            }
            
            // Hide loading screen and show main content
            document.getElementById('loading-screen').style.display = 'none';
            document.getElementById('main-content').style.display = 'block';
            
            // Fallback polling every 2 minutes (in case realtime fails)
            startBalanceAutoRefresh(120000);
            
            console.log('✅ Dashboard loaded successfully');
            
        } catch (err) {
            console.error('Failed to load dashboard', err);
            // Still hide loading screen to prevent infinite spinner
            document.getElementById('loading-screen').style.display = 'none';
            document.getElementById('main-content').style.display = 'block';
            alert('⚠️ Error loading dashboard. Some features may not work correctly.');
        }
    }

    // --- Refresh balance with shorter retries ---
    async function refreshBalance(retries = 2) {
        console.log('🔄 refreshBalance called, current balance:', currentBalance);
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                console.log(\`📡 Fetching balance (attempt \${attempt}/\${retries})...\`);
                const res = await fetchWithAuth('/wallet/balance', {}, 5000);
                if (!res) {
                    console.error('❌ refreshBalance: No response from server');
                    if (attempt < retries) {
                        await new Promise(r => setTimeout(r, 1000 * attempt));
                        continue;
                    }
                    return;
                }
                if (!res.ok) {
                    console.error('❌ refreshBalance: HTTP', res.status);
                    if (attempt < retries) {
                        await new Promise(r => setTimeout(r, 1000 * attempt));
                        continue;
                    }
                    return;
                }
                const data = await res.json();
                console.log('📊 Balance response:', data);
                if (typeof data.balance === 'number') {
                    console.log(\`✅ Balance updated: \${currentBalance} → \${data.balance}\`);
                    currentBalance = data.balance;
                    updateBalanceDisplay();
                    return;
                } else {
                    console.error('❌ Invalid balance response:', data);
                }
            } catch (err) {
                console.error(\`❌ refreshBalance attempt \${attempt} failed:\`, err.message, err);
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 1000 * attempt));
                }
            }
        }
        console.error('❌ refreshBalance: All attempts failed, balance remains:', currentBalance);
    }

    function updateBalanceDisplay() {
        const balElement = document.getElementById('balance');
        if (!balElement) {
            console.error('❌ Balance element not found in DOM!');
            return;
        }
        console.log('💰 Updating balance display to:', currentBalance);
        balElement.innerText = currentBalance.toFixed(2);
        balElement.classList.remove('balance-flash');
        void balElement.offsetWidth;
        balElement.classList.add('balance-flash');
    }

    function startBalanceAutoRefresh(intervalMs = 30000) {
        if (balanceRefreshInterval) {
            clearInterval(balanceRefreshInterval);
        }
        balanceRefreshInterval = setInterval(() => {
            console.log('🔄 Auto-refreshing balance (fallback)...');
            refreshBalance().catch(err => {
                console.error('Failed to auto-refresh balance:', err);
            });
        }, intervalMs);
        console.log(\`✅ Balance auto-refresh started (\${intervalMs/1000}s interval)\`);
    }

    function stopBalanceAutoRefresh() {
        if (balanceRefreshInterval) {
            clearInterval(balanceRefreshInterval);
            balanceRefreshInterval = null;
            console.log('⏹️  Balance auto-refresh stopped');
        }
        if (realtimeChannel) {
            supabaseRealtime.removeChannel(realtimeChannel);
            realtimeChannel = null;
        }
    }

    // --- Profile (team name) ---
    async function loadProfile() {
        try {
            const res = await fetchWithAuth('/profile', {}, 5000);
            if (res && res.ok) {
                const profile = await res.json();
                currentTeam = profile.team_name || '';
                document.getElementById('team-display').innerText = currentTeam || '—';
                const walletUsernameEl2 = document.getElementById('wallet-username-display');
                if (walletUsernameEl2) walletUsernameEl2.textContent = '@' + currentUsername;
                document.getElementById('profile-username').value = escapeHtml(currentUsername);
                document.getElementById('profile-team').value = escapeHtml(currentTeam);
            }
        } catch (e) {
            console.warn('loadProfile failed:', e);
        }
    }

    async function saveProfile() {
        const teamName = document.getElementById('profile-team').value.trim();
        if (!teamName) { showError('profile-error', 'Team name cannot be empty'); return; }
        if (teamName.length < 3) { showError('profile-error', 'Team name must be at least 3 characters'); return; }
        const btn = document.querySelector('#profile-modal .btn-mpesa');
        btn.disabled = true;
        btn.textContent = 'Saving...';
        try {
            const res = await fetchWithAuth('/profile/team', {
                method: 'POST',
                body: JSON.stringify({ teamName })
            }, 5000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            currentTeam = teamName;
            document.getElementById('team-display').innerText = teamName;
            document.getElementById('profile-team').value = escapeHtml(teamName);
            closeModal('profile-modal');
            alert('Team name updated successfully!');
        } catch (err) {
            showError('profile-error', err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'SAVE CHANGES';
        }
    }

    // --- TOURNAMENTS ---
    async function loadTournaments() {
        try {
            const res = await fetch(\`\${API}/tournaments\`);
            if (!res.ok) throw new Error('Failed to load tournaments');
            const tournaments = await res.json();
            renderTournaments(tournaments);
        } catch (err) {
            console.error('Error loading tournaments:', err);
            const container = document.getElementById('tournament-list');
            container.innerHTML = '';
            const noTourney = document.createElement('div');
            noTourney.className = 'tournament-card';
            noTourney.style.cssText = 'text-align:center;padding:28px;color:#444;font-size:0.82rem;';
            noTourney.innerHTML = '<div style="font-size:2rem;margin-bottom:8px;opacity:0.3;">🏆</div>No active tournaments right now.<br><span style="font-size:0.72rem;color:#333;">Check back soon!</span>';
            container.appendChild(noTourney);
        }
    }

    function renderTournaments(tournaments) {
        const container = document.getElementById('tournament-list');
        container.innerHTML = '';
        if (!tournaments || tournaments.length === 0) {
            const noTourney = document.createElement('div');
            noTourney.className = 'tournament-card';
            noTourney.style.cssText = 'text-align:center;padding:28px;color:#444;font-size:0.82rem;';
            noTourney.innerHTML = '<div style="font-size:2rem;margin-bottom:8px;opacity:0.3;">🏆</div>No active tournaments right now.<br><span style="font-size:0.72rem;color:#333;">Check back soon!</span>';
            container.appendChild(noTourney);
            return;
        }
        tournaments.forEach(t => {
            const card = createElementSafe('div', { class: \`tournament-card \${t.status === 'live' ? 'live' : ''}\` });
            card.addEventListener('click', () => openChallengeModal(t.id, t.name, t.entry_fee));

            const headerDiv = createElementSafe('div', { class: 't-header' });
            const titleDiv = createElementSafe('div', {});
            titleDiv.appendChild(createElementSafe('div', { class: 't-name' }, t.name));
            const startTime = new Date(t.start_time).toLocaleDateString('en-KE', { weekday: 'short', hour: '2-digit', minute: '2-digit' });
            titleDiv.appendChild(createElementSafe('div', { class: 't-meta' }, \`Starts \${startTime}\`));
            headerDiv.appendChild(titleDiv);

            const badgeSpan = document.createElement('span');
            badgeSpan.className = \`t-badge \${t.status === 'live' ? 'live-badge' : 'soon-badge'}\`;
            if (t.status === 'live') {
                const pip = document.createElement('span');
                pip.className = 'live-pip';
                badgeSpan.appendChild(pip);
                badgeSpan.appendChild(document.createTextNode(' LIVE'));
            } else {
                badgeSpan.textContent = '🗓 SOON';
            }
            headerDiv.appendChild(badgeSpan);
            card.appendChild(headerDiv);

            const footerDiv = createElementSafe('div', { class: 't-footer' });
            const prizeDiv = createElementSafe('div', { class: 't-prize' });
            prizeDiv.appendChild(createElementSafe('small', {}, 'PRIZE POOL'));
            prizeDiv.appendChild(document.createTextNode(\`KES \${(t.prize_pool || 0).toLocaleString()}\`));
            footerDiv.appendChild(prizeDiv);

            const rightDiv = createElementSafe('div', { style: 'display:flex;flex-direction:column;align-items:flex-end;gap:8px;' });
            rightDiv.appendChild(createElementSafe('div', { class: 't-players' }, \`👥 \${t.current_players}/\${t.max_players}\`));
            const joinBtn = createElementSafe('button', { class: 'btn-join' }, \`KES \${t.entry_fee} →\`);
            rightDiv.appendChild(joinBtn);
            footerDiv.appendChild(rightDiv);
            card.appendChild(footerDiv);

            const pct = t.max_players > 0 ? Math.round((t.current_players / t.max_players) * 100) : 0;
            const progressDiv = createElementSafe('div', { class: 'progress-bar' });
            progressDiv.appendChild(createElementSafe('div', { class: 'progress-fill', style: \`width:\${pct}%\` }));
            card.appendChild(progressDiv);

            container.appendChild(card);
        });
    }

    // --- Modal Helpers ---
    function closeModal(modalId) {
        document.getElementById(modalId).classList.remove('open');
        if (modalId === 'deposit-modal' && pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        if (modalId === 'waiting-friend-modal' && friendMatchTimer) { clearInterval(friendMatchTimer); friendMatchTimer = null; }
        // FIX 8: Also stop match-status polling when the waiting modal is dismissed.
        // Without this a second call to startMatchStatusPolling (e.g. when joining
        // another match) stacks a competing interval on top of the first one.
        if (modalId === 'waiting-friend-modal') { stopMatchStatusPolling(); }
        if (modalId === 'report-result-modal') { currentReportMatch = null; resetReportModal(); }
    }

    // --- Deposit Flow ---
    function openDepositModal() {
        hideError('deposit-error');
        switchStep('deposit-modal', 1);
        document.getElementById('deposit-amount').value = '';
        document.getElementById('deposit-modal').classList.add('open');
    }
    function selectPreset(btn, amount) {
        document.querySelectorAll('#deposit-modal .preset-btn').forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
        document.getElementById('deposit-amount').value = amount;
    }
    async function processDeposit() {
        const amount = parseInt(document.getElementById('deposit-amount').value);
        const phone = document.getElementById('deposit-phone').value.trim();
        if (!amount || amount < 10) { showError('deposit-error', 'Minimum deposit is KES 10'); return; }
        if (!phone) { showError('deposit-error', 'Enter your M-PESA number'); return; }

        // FIX 6: Complete client-side phone normalisation + validation.
        // Previously only '0'-prefix numbers were handled; '7XX', '1XX', '+254'
        // and invalid lengths were silently passed to the server, returning a
        // confusing server-side error. Now we validate here and show a clear message.
        let cleanPhone = phone.replace(/[\\s\\-]/g, '');
        if (cleanPhone.startsWith('+254'))      cleanPhone = cleanPhone;          // already E.164
        else if (cleanPhone.startsWith('254'))  cleanPhone = '+' + cleanPhone;
        else if (cleanPhone.startsWith('0'))    cleanPhone = '+254' + cleanPhone.substring(1);
        else if (/^[71]/.test(cleanPhone))      cleanPhone = '+254' + cleanPhone; // 7XX / 1XX
        // Strip the leading '+' for the length check then re-add it
        const digits = cleanPhone.replace('+', '');
        if (!/^254[17]\\d{8}$/.test(digits)) {
            showError('deposit-error', 'Invalid M-PESA number. Use format 07XX XXX XXX or +254 7XX XXX XXX');
            return;
        }

        const btn = document.querySelector('#deposit-modal .btn-mpesa');
        btn.disabled = true; btn.textContent = 'Sending request...';
        try {
            const res = await fetchWithAuth('/wallet/deposit', {
                method: 'POST',
                body: JSON.stringify({ amount, phone: cleanPhone })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            currentCheckoutId = data.checkoutRequestId;
            switchStep('deposit-modal', 2);
            pollInterval = setInterval(() => checkDepositStatus(currentCheckoutId), 3000);
        } catch (err) {
            showError('deposit-error', err.message);
        } finally {
            btn.disabled = false; btn.textContent = 'PAY WITH M-PESA 📲';
        }
    }
    async function checkDepositStatus(checkoutId) {
        try {
            const res = await fetchWithAuth(\`/wallet/deposit/status?checkoutId=\${checkoutId}\`, {}, 5000);
            if (!res) return;
            const data = await res.json();
            if (data.status === 'completed') {
                clearInterval(pollInterval); pollInterval = null;
                closeModal('deposit-modal');
                await refreshBalance();
                alert('✅ Deposit successful! Your balance has been updated.');
            } else if (data.status === 'failed') {
                clearInterval(pollInterval); pollInterval = null;
                switchStep('deposit-modal', 1);
                showError('deposit-error', 'Payment failed or cancelled. Try again.');
            }
        } catch (err) { /* keep polling */ }
    }

    // --- Withdraw Flow ---
    function openWithdrawModal() {
        hideError('withdraw-error');
        document.getElementById('withdraw-amount').value = '';
        document.getElementById('withdraw-modal').classList.add('open');
    }
    async function processWithdraw() {
        const amount = parseInt(document.getElementById('withdraw-amount').value);
        const phone = document.getElementById('withdraw-phone').value.trim();
        if (!amount || amount < 50) { showError('withdraw-error', 'Minimum withdrawal is KES 50'); return; }
        if (amount > currentBalance) { showError('withdraw-error', 'Insufficient balance'); return; }
        if (!phone) { showError('withdraw-error', 'Enter your M-PESA number'); return; }

        // FIX 6: Same complete normalisation as processDeposit.
        let cleanPhone = phone.replace(/[\\s\\-]/g, '');
        if (cleanPhone.startsWith('+254'))      cleanPhone = cleanPhone;
        else if (cleanPhone.startsWith('254'))  cleanPhone = '+' + cleanPhone;
        else if (cleanPhone.startsWith('0'))    cleanPhone = '+254' + cleanPhone.substring(1);
        else if (/^[71]/.test(cleanPhone))      cleanPhone = '+254' + cleanPhone;
        const _wDigits = cleanPhone.replace('+', '');
        if (!/^254[17]\\d{8}$/.test(_wDigits)) {
            showError('withdraw-error', 'Invalid M-PESA number. Use format 07XX XXX XXX or +254 7XX XXX XXX');
            return;
        }

        const btn = document.querySelector('#withdraw-modal .btn-mpesa');
        btn.disabled = true; btn.textContent = 'Processing...';
        try {
            const res = await fetchWithAuth('/wallet/withdraw', {
                method: 'POST',
                body: JSON.stringify({ amount, phone: cleanPhone })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            closeModal('withdraw-modal');
            await refreshBalance();
            alert(\`✅ Withdrawal of KES \${amount} submitted! You'll receive an M-PESA shortly.\`);
        } catch (err) {
            showError('withdraw-error', err.message);
        } finally {
            btn.disabled = false; btn.textContent = 'WITHDRAW NOW →';
        }
    }

    // --- Tournament/Challenge Flow ---
    function openChallengeModal(tournamentId, name, fee) {
        currentTournamentId = tournamentId;
        currentTournamentFee = fee;
        currentTournamentName = name;
        document.getElementById('challenge-name').textContent = escapeHtml(name);
        document.getElementById('challenge-fee').textContent = \`KES \${fee}\`;
        hideError('challenge-error');
        switchStep('challenge-modal', 1);
        document.getElementById('challenge-modal').classList.add('open');
    }
    async function confirmChallenge(method) {
        if (!currentTournamentId) return;

        if (method === 'wallet' && currentBalance < currentTournamentFee) {
            showError('challenge-error', 'Insufficient balance. Please deposit first.');
            return;
        }

        if (method === 'mpesa') {
            switchStep('challenge-modal', 2);
            try {
                const payRes = await fetchWithAuth('/wallet/deposit', {
                    method: 'POST',
                    body: JSON.stringify({ amount: currentTournamentFee, phone: '+254' + currentPhone.replace(/^0/, '') })
                }, 10000);
                const payData = await payRes.json();
                if (!payRes.ok) { switchStep('challenge-modal', 1); showError('challenge-error', payData.error); return; }
                currentCheckoutId = payData.checkoutRequestId;
                pollInterval = setInterval(async () => {
                    try {
                        const sRes = await fetchWithAuth(\`/wallet/deposit/status?checkoutId=\${currentCheckoutId}\`, {}, 5000);
                        if (!sRes) return;
                        const sData = await sRes.json();
                        if (sData.status === 'completed') {
                            clearInterval(pollInterval); pollInterval = null;
                            await doJoinTournament('mpesa', currentCheckoutId);
                        } else if (sData.status === 'failed') {
                            clearInterval(pollInterval); pollInterval = null;
                            switchStep('challenge-modal', 1);
                            showError('challenge-error', 'M-PESA payment failed.');
                        }
                    } catch(e) {}
                }, 3000);
            } catch(err) {
                switchStep('challenge-modal', 1);
                showError('challenge-error', err.message);
            }
            return;
        }

        await doJoinTournament('wallet', null);
    }
    async function doJoinTournament(paymentMethod, checkoutId) {
        try {
            console.log('📝 Joining tournament:', currentTournamentId, 'Payment:', paymentMethod);
            const res = await fetchWithAuth('/tournament/join', {
                method: 'POST',
                body: JSON.stringify({
                    tournamentId: currentTournamentId,
                    entryFee: currentTournamentFee,
                    paymentMethod,
                    checkoutId
                })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            
            console.log('✅ Tournament joined successfully');
            
            closeModal('challenge-modal');
            
            // CRITICAL FIX: Always refresh balance from server after tournament join
            await refreshBalance(3);
            console.log('💰 Balance refreshed after tournament join:', currentBalance);
            
            if (data.roomCode) {
                document.getElementById('room-code-display').textContent = data.roomCode;
                document.getElementById('room-modal').classList.add('open');
            } else {
                alert(\`✅ \${data.message || 'Umejiunga!'}\`);
            }
            await loadTournaments();
        } catch (err) {
            switchStep('challenge-modal', 1);
            showError('challenge-error', err.message);
        }
    }

    // --- Friend Match Functions ---
    function openCreateMatchModal() {
        if (!currentTeam) {
            alert('Please set your team name in profile before creating a match.');
            openProfileModal();
            return;
        }
        document.getElementById('friend-wager-input').value = 200;
        updateFriendBreakdown();
        hideError('create-friend-error');
        document.getElementById('create-friend-modal').classList.add('open');
    }
    function openJoinMatchModal() {
        if (!currentTeam) {
            alert('Please set your team name in profile before joining a match.');
            openProfileModal();
            return;
        }
        document.getElementById('join-friend-code').value = '';
        hideError('join-friend-error');
        document.getElementById('join-friend-modal').classList.add('open');
    }
    function selectFriendPreset(btn, amount) {
        document.querySelectorAll('#create-friend-modal .preset-btn').forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
        document.getElementById('friend-wager-input').value = amount;
        updateFriendBreakdown();
    }
    function updateFriendBreakdown() {
        const wager = parseInt(document.getElementById('friend-wager-input').value) || 100;
        const platformFee = Math.floor(wager * 2 * 0.10);
        const winnerPrize = (wager * 2) - platformFee;
        document.getElementById('friend-your-stake').textContent = wager;
        document.getElementById('friend-opp-stake').textContent = wager;
        document.getElementById('friend-total-pot').textContent = wager * 2;
        document.getElementById('friend-platform-fee').textContent = platformFee;
        document.getElementById('friend-winner-prize').textContent = winnerPrize;
        document.getElementById('create-friend-amount').textContent = wager;
    }
    async function createFriendMatch() {
        const wagerAmount = parseInt(document.getElementById('friend-wager-input').value);
        const efootballCode = document.getElementById('friend-efootball-code').value.trim().toUpperCase();
        const errorEl = document.getElementById('create-friend-error');
        const btn = document.getElementById('create-friend-btn');

        // Validate inputs
        if (!efootballCode) { showError('create-friend-error', 'Please enter your eFootball room code'); return; }
        if (wagerAmount < 50) { showError('create-friend-error', 'Minimum wager is KES 50'); return; }
        if (wagerAmount > currentBalance) { showError('create-friend-error', 'Insufficient balance'); return; }

        btn.disabled = true;
        btn.textContent = 'Creating...';
        try {
            console.log('📝 Creating friend match with eFootball code:', efootballCode, 'wager:', wagerAmount);
            const res = await fetchWithAuth('/friends/create-match', {
                method: 'POST',
                body: JSON.stringify({ wagerAmount, efootballCode })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);

            console.log('✅ Match created successfully');

            currentFriendMatch = data;

            // CRITICAL FIX: Always refresh balance from server after create
            await refreshBalance(3);
            console.log('💰 Balance refreshed after create:', currentBalance);

            document.getElementById('friend-match-code').textContent = data.efootballCode;
            document.getElementById('waiting-stake-display').textContent = wagerAmount;
            document.getElementById('waiting-prize-display').textContent = data.winnerPrize;
            startFriendTimer(data.expiresAt);
            closeModal('create-friend-modal');
            document.getElementById('waiting-friend-modal').classList.add('open');
            startMatchStatusPolling(data.matchId);
            await loadMyFriendMatches();
        } catch (err) {
            console.error('❌ Error creating match:', err);
            showError('create-friend-error', err.message);
            // Also refresh balance on error in case deduction happened
            await refreshBalance(3);
        } finally {
            btn.disabled = false;
            // Safely rebuild button text
            btn.textContent = '';
            btn.appendChild(document.createTextNode('CREATE CHALLENGE (Pay KES '));
            const _amtSpan = document.createElement('span');
            _amtSpan.id = 'create-friend-amount';
            _amtSpan.textContent = String(wagerAmount);
            btn.appendChild(_amtSpan);
            btn.appendChild(document.createTextNode(')'));
        }
    }
    async function joinFriendMatch() {
        const efootballCode = document.getElementById('join-friend-code').value.trim().toUpperCase();
        const errorEl = document.getElementById('join-friend-error');
        if (!efootballCode) { showError('join-friend-error', 'Please enter your opponent\\'s eFootball room code'); return; }
        try {
            console.log('📝 Joining friend match with eFootball code:', efootballCode);
            const res = await fetchWithAuth('/friends/join-match', {
                method: 'POST',
                body: JSON.stringify({ efootballCode })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);

            console.log('✅ Match joined successfully');

            // CRITICAL FIX: Always refresh balance from server after join
            await refreshBalance(3);
            console.log('💰 Balance refreshed after join:', currentBalance);

            currentFriendMatch = data;
            closeModal('join-friend-modal');
            openWarRoom({
                matchId:         data.matchId,
                efootballCode:   data.efootballCode,
                creatorTeam:     data.creatorTeam,
                creatorUsername: data.creatorUsername,
                joinerTeam:      currentTeam,
                joinerUsername:  currentUsername,
                wagerAmount:     data.wagerAmount,
                winnerPrize:     data.winnerPrize,
                startedAt:       new Date().toISOString(),
                currentUserId:   currentUser.id,
                creatorId:       data.creatorId
            });
            // loadMyFriendMatches called on dashboard return
        } catch (err) {
            console.error('❌ Error joining match:', err);
            showError('join-friend-error', err.message);
            // Also refresh balance on error in case deduction happened
            await refreshBalance(3);
        }
    }
    async function cancelFriendMatch() {
        if (!confirm('Are you sure you want to cancel? You\\'ll get your wager back.')) return;
        stopMatchStatusPolling();
        try {
            console.log('📝 Cancelling friend match');
            const res = await fetchWithAuth('/friends/cancel-match', {
                method: 'POST',
                body: JSON.stringify({ matchId: currentFriendMatch.matchId })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            
            console.log('✅ Match cancelled, refund:', data.refundedAmount);
            
            // CRITICAL FIX: Always refresh balance from server after cancel
            await refreshBalance(3);
            console.log('💰 Balance refreshed after cancel:', currentBalance);
            
            if (friendMatchTimer) { clearInterval(friendMatchTimer); friendMatchTimer = null; }
            closeModal('waiting-friend-modal');
            showToast('info', 'Match Cancelled', \`KES \${data.refundedAmount} refunded to your wallet.\`, 5000);
            await loadMyFriendMatches();
        } catch (err) {
            console.error('❌ Error cancelling match:', err);
            showToast('error', 'Cancellation Failed', err.message, 5000);
            // Refresh balance anyway
            await refreshBalance(3);
        }
    }
    function shareFriendCode() {
        const code = document.getElementById('friend-match-code').textContent;
        const wager = parseInt(document.getElementById('waiting-stake-display').textContent);
        const prize = parseInt(document.getElementById('waiting-prize-display').textContent);
        const text = encodeURIComponent(
            \`🎮 Challenge me on Vumbua eFootball!\\n\\nMatch Code: \${code}\\nWager: KES \${wager}\\nWinner gets: KES \${prize}\\n\\nJoin here: https://vumbua.app\`
        );
        window.open(\`https://wa.me/?text=\${text}\`, '_blank');
    }
    function startFriendTimer(expiresAt) {
        if (friendMatchTimer) clearInterval(friendMatchTimer);
        friendMatchTimer = setInterval(() => {
            const now = new Date();
            const expires = new Date(expiresAt);
            const diff = Math.max(0, expires - now);
            const minutes = Math.floor(diff / 60000);
            const seconds = Math.floor((diff % 60000) / 1000);
            document.getElementById('friend-match-timer').textContent = 
                \`Expires in \${minutes}:\${seconds.toString().padStart(2, '0')}\`;
            if (diff === 0) {
                clearInterval(friendMatchTimer);
                closeModal('waiting-friend-modal');
                showToast('info', 'Match Expired', 'No one joined in time. Your wager has been refunded.', 6000);
                refreshBalance();
                loadMyFriendMatches();
            }
        }, 1000);
    }

    // --- My Matches & Result Reporting ---
    async function loadMyFriendMatches() {
        try {
            const res = await fetchWithAuth('/friends/my-matches', {}, 8000);
            if (!res) return;
            const matches = await res.json();
            renderMyMatches(matches);
            // Show floating banner if any match needs our response
            checkAndShowConfirmBanner(matches);
        } catch (e) {
            console.warn('loadMyFriendMatches failed:', e);
        }
    }

    function renderMyMatches(matches) {
        const container = document.getElementById('my-matches-list');
        container.innerHTML = '';
        if (!matches || matches.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'empty-state';
            emptyDiv.innerHTML = \`
                <div class="empty-state-icon">⚽</div>
                <div class="empty-state-text">No matches yet.<br>Challenge a friend to win KES!</div>
                <button class="empty-state-cta" onclick="openCreateMatchModal()">⚔️ Create Challenge</button>
            \`;
            container.appendChild(emptyDiv);
            return;
        }

        const displayMatches = matches.slice(0, 3);
        if (matches.length > 3) {
            const moreEl = createElementSafe('div', { class: 'friend-info', style: 'text-align:center;font-size:0.75rem;margin-bottom:8px;' }, \`Showing 3 of \${matches.length} matches\`);
            container.appendChild(moreEl);
        }

        displayMatches.forEach(m => {
            const item = createElementSafe('div', { class: 'match-item' });
            const isCreator = m.creator_id === currentUser.id;
            const opponentName = isCreator
                ? (m.joiner?.username || 'Waiting...')
                : (m.creator?.username || 'Unknown');
            const opponentInitial = opponentName.charAt(0).toUpperCase();
            const myTeam   = isCreator ? (m.creator_team || 'My Team') : (m.joiner_team || 'My Team');
            const oppTeam  = isCreator ? (m.joiner_team  || 'Opponent') : (m.creator_team || 'Opponent');

            // ── Header: code + status badge ───────────────────────────────
            const headerDiv = createElementSafe('div', { class: 'match-header' });
            const codeDisplay = m.match_code ? m.match_code.replace('VUM-', '') : '—';
            headerDiv.appendChild(createElementSafe('span', { class: 'match-code' }, codeDisplay));

            // Friendly status labels
            const _completedYouWon = m.status === 'completed' && m.winner_id === currentUser.id;
            const statusLabels = {
                pending:               'Waiting',
                active:                'Live',
                awaiting_confirmation: m.declared_score_by === currentUser.id ? 'Confirming…' : 'Respond!',
                penalty_shootout:      'Penalties',
                disputed:              'Disputed',
                completed:             _completedYouWon ? '🏆 Won' : '😔 Lost',
                cancelled:             'Cancelled',
            };
            const statusCssMap = {
                pending:               'status-pending',
                active:                'status-live',
                awaiting_confirmation: m.declared_score_by === currentUser.id ? 'status-live' : 'status-disputed',
                penalty_shootout:      'status-pending',
                disputed:              'status-disputed',
                completed:             _completedYouWon ? 'status-won' : 'status-lost',
                cancelled:             'status-closed',
            };
            const statusSpan = createElementSafe('span', { class: \`match-status \${statusCssMap[m.status] || 'status-closed'}\` }, statusLabels[m.status] || m.status);
            headerDiv.appendChild(statusSpan);
            item.appendChild(headerDiv);

            // ── Sub-info row ───────────────────────────────────────────────
            item.appendChild(createElementSafe('div', { class: 'match-detail' }, \`KES \${m.wager_amount} wager · Prize KES \${m.winner_prize}\`));

            // ── State-specific rich cards ──────────────────────────────────
            if (m.status === 'pending' && isCreator) {
                // Pending: waiting for someone to join
                const actionsDiv = createElementSafe('div', { class: 'match-actions' });
                const cancelBtn = createElementSafe('button', { class: 'btn btn-red' }, 'Cancel & Refund');
                cancelBtn.addEventListener('click', e => { e.stopPropagation(); cancelPendingMatch(m.id); });
                actionsDiv.appendChild(cancelBtn);
                item.appendChild(actionsDiv);

            } else if (m.status === 'active') {
                // ── ACTIVE: Both joined, results not yet posted ────────────
                const stateCard = document.createElement('div');
                stateCard.className = 'match-state-waiting-results';

                // Opponent avatar with spinning ring
                const headerRow = document.createElement('div');
                headerRow.className = 'waiting-results-header';

                const avatarRing = document.createElement('div');
                avatarRing.className = 'opponent-avatar-ring';
                avatarRing.innerHTML = \`
                    <svg viewBox="0 0 38 38" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="19" cy="19" r="16" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="2.5"/>
                        <circle cx="19" cy="19" r="16" fill="none" stroke="rgba(100,100,100,0.4)" stroke-width="2.5"
                            stroke-dasharray="25 75" stroke-linecap="round"
                            style="transform-origin:center;animation:ringRotate 2s linear infinite;"/>
                    </svg>
                    <div class="opponent-avatar-inner">\${escapeHtml(opponentInitial)}</div>\`;

                const textGroup = document.createElement('div');
                textGroup.className = 'waiting-results-text';
                const opLabel = createElementSafe('div', { class: 'waiting-results-label' }, 'Playing against');
                const opNameEl = document.createElement('div');
                opNameEl.className = 'waiting-results-name';
                opNameEl.textContent = opponentName;
                const opSub = document.createElement('div');
                opSub.className = 'waiting-results-sub';
                opSub.innerHTML = \`Waiting for results<span class="waiting-dots"><span></span><span></span><span></span></span>\`;

                textGroup.appendChild(opLabel);
                textGroup.appendChild(opNameEl);
                textGroup.appendChild(opSub);
                headerRow.appendChild(avatarRing);
                headerRow.appendChild(textGroup);
                stateCard.appendChild(headerRow);

                // ── Declare CTA — or Pending Payout if screenshot already uploaded ──
                const declareCta = document.createElement('div');
                declareCta.className = 'declare-cta';

                if (m.screenshot_url) {
                    // Screenshot already submitted — show pending payout state
                    declareCta.innerHTML = \`
                        <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:rgba(255,180,0,0.08);border:1px solid rgba(255,180,0,0.2);border-radius:10px;">
                            <span style="font-size:1.3rem;">⏳</span>
                            <div>
                                <div style="font-size:0.82rem;font-weight:700;color:#ffb400;letter-spacing:0.5px;">Pending Payout</div>
                                <div style="font-size:0.72rem;color:#888;margin-top:2px;">Screenshot received — admin is verifying your result</div>
                            </div>
                        </div>\`;
                } else {
                    // No screenshot yet — show report button
                    const ctaText = document.createElement('div');
                    ctaText.className = 'declare-cta-text';
                    ctaText.innerHTML = \`Match done? <strong>Post your result</strong>\`;
                    const ctaBtn = createElementSafe('button', { class: 'declare-cta-btn' }, '⚽ Report Result');
                    ctaBtn.addEventListener('click', e => { e.stopPropagation(); openReportResultModal(m.id); });
                    declareCta.appendChild(ctaText);
                    declareCta.appendChild(ctaBtn);
                }

                stateCard.appendChild(declareCta);
                item.appendChild(stateCard);

            } else if (m.status === 'awaiting_confirmation') {
                const iDeclared = m.declared_score_by === currentUser.id;
                const myScore  = isCreator ? m.declared_score_creator : m.declared_score_joiner;
                const oppScore = isCreator ? m.declared_score_joiner  : m.declared_score_creator;
                const deadline = m.score_confirm_deadline;
                const totalMs  = 30 * 60 * 1000; // 30 min window

                if (iDeclared) {
                    // ── CONFIRMING STATE: I declared, waiting for opponent ─
                    const stateCard = document.createElement('div');
                    stateCard.className = 'match-state-confirming';

                    const inner = document.createElement('div');
                    inner.className = 'confirming-inner';

                    // Top row: ring icon + text
                    const topRow = document.createElement('div');
                    topRow.className = 'confirming-top';

                    const iconWrap = document.createElement('div');
                    iconWrap.className = 'confirming-icon-wrap';
                    // SVG ring — progress updated by tickAllClocks
                    const circumference = 2 * Math.PI * 17.5; // r=17.5
                    iconWrap.innerHTML = \`
                        <svg class="confirming-ring-svg" viewBox="0 0 42 42" xmlns="http://www.w3.org/2000/svg">
                            <circle class="confirming-ring-track" cx="21" cy="21" r="17.5"/>
                            <circle class="confirming-ring-progress" cx="21" cy="21" r="17.5"
                                stroke-dasharray="\${circumference.toFixed(1)}"
                                stroke-dashoffset="\${circumference.toFixed(1)}"
                                style="transform:rotate(-90deg);transform-origin:center;"/>
                        </svg>
                        <div class="confirming-icon-center">⏳</div>\`;
                    // Set deadline after innerHTML so it's never escaped
                    const ringEl = iconWrap.querySelector('.confirming-ring-progress');
                    if (ringEl && deadline) {
                        ringEl.setAttribute('data-deadline', deadline);
                        ringEl.setAttribute('data-total', String(totalMs));
                    }

                    const textGroup = document.createElement('div');
                    textGroup.className = 'confirming-text';
                    const badge = document.createElement('div');
                    badge.className = 'confirming-badge';
                    badge.innerHTML = \`<span class="confirming-badge-dot"></span> CONFIRMING\`;
                    const title = createElementSafe('div', { class: 'confirming-title' }, \`Waiting for \${opponentName}\`);
                    const sub = createElementSafe('div', { class: 'confirming-sub' }, \`They have 30 min to confirm or dispute\`);
                    textGroup.appendChild(badge);
                    textGroup.appendChild(title);
                    textGroup.appendChild(sub);

                    topRow.appendChild(iconWrap);
                    topRow.appendChild(textGroup);
                    inner.appendChild(topRow);

                    // Score display
                    const scoreDisplay = document.createElement('div');
                    scoreDisplay.className = 'confirming-score-display';
                    scoreDisplay.innerHTML = \`
                        <div class="confirming-score-team">
                            <div class="confirming-score-team-name">\${escapeHtml(myTeam)}</div>
                            <div class="confirming-score-num my">\${myScore ?? '?'}</div>
                        </div>
                        <div class="confirming-score-sep">—</div>
                        <div class="confirming-score-team">
                            <div class="confirming-score-team-name">\${escapeHtml(oppTeam)}</div>
                            <div class="confirming-score-num opp">\${oppScore ?? '?'}</div>
                        </div>\`;
                    inner.appendChild(scoreDisplay);

                    // Big clock countdown block — built via DOM (not innerHTML) so deadline isn't escaped/corrupted
                    const clockBlock = document.createElement('div');
                    clockBlock.className = 'confirming-clock-block';

                    const clockLabel = document.createElement('div');
                    clockLabel.className = 'confirming-clock-label';
                    clockLabel.textContent = '⏳ Time left for opponent to respond';
                    clockBlock.appendChild(clockLabel);

                    const clockDigits = document.createElement('div');
                    clockDigits.className = 'confirming-clock-digits';

                    // MIN unit
                    const minUnit = document.createElement('div');
                    minUnit.className = 'clock-unit';
                    const minNum = document.createElement('span');
                    minNum.className = 'clock-num';
                    minNum.setAttribute('data-clock-part', 'min');
                    if (deadline) minNum.setAttribute('data-deadline', deadline);
                    minNum.textContent = deadline ? '--' : '??';
                    const minLabel = document.createElement('div');
                    minLabel.className = 'clock-unit-label';
                    minLabel.textContent = 'min';
                    minUnit.appendChild(minNum);
                    minUnit.appendChild(minLabel);

                    const sep = document.createElement('span');
                    sep.className = 'clock-sep';
                    sep.textContent = ':';

                    // SEC unit
                    const secUnit = document.createElement('div');
                    secUnit.className = 'clock-unit';
                    const secNum = document.createElement('span');
                    secNum.className = 'clock-num';
                    secNum.setAttribute('data-clock-part', 'sec');
                    if (deadline) secNum.setAttribute('data-deadline', deadline);
                    secNum.textContent = deadline ? '--' : '??';
                    const secLabel = document.createElement('div');
                    secLabel.className = 'clock-unit-label';
                    secLabel.textContent = 'sec';
                    secUnit.appendChild(secNum);
                    secUnit.appendChild(secLabel);

                    clockDigits.appendChild(minUnit);
                    clockDigits.appendChild(sep);
                    clockDigits.appendChild(secUnit);
                    clockBlock.appendChild(clockDigits);

                    // Progress bar
                    const barWrap = document.createElement('div');
                    barWrap.className = 'confirming-countdown-bar';
                    const barFill = document.createElement('div');
                    barFill.className = 'confirming-countdown-fill';
                    if (deadline) {
                        barFill.setAttribute('data-deadline', deadline);
                        barFill.setAttribute('data-total', String(totalMs));
                    }
                    barFill.style.width = '100%';
                    barWrap.appendChild(barFill);
                    clockBlock.appendChild(barWrap);

                    const autoWinNote = document.createElement('div');
                    autoWinNote.className = 'confirming-auto-win-note';
                    autoWinNote.innerHTML = '⚡ You <strong>auto-win</strong> when this hits zero';
                    clockBlock.appendChild(autoWinNote);

                    inner.appendChild(clockBlock);

                    stateCard.appendChild(inner);
                    item.appendChild(stateCard);

                } else {
                    // ── URGENT STATE: Opponent declared, I need to respond ─
                    const stateCard = document.createElement('div');
                    stateCard.className = 'match-state-urgent';

                    const inner = document.createElement('div');
                    inner.className = 'urgent-inner';

                    // Header
                    const urgHeader = document.createElement('div');
                    urgHeader.className = 'urgent-header';

                    const alarm = document.createElement('div');
                    alarm.className = 'urgent-alarm';
                    alarm.textContent = '⚠️';

                    const urgText = document.createElement('div');
                    urgText.className = 'urgent-text-group';
                    const urgLabel = createElementSafe('div', { class: 'urgent-label' }, '⚡ Action required');
                    const urgTitle = createElementSafe('div', { class: 'urgent-title' }, \`\${opponentName} posted results\`);
                    const urgSub   = createElementSafe('div', { class: 'urgent-sub' }, 'Confirm or dispute before time runs out');
                    urgText.appendChild(urgLabel);
                    urgText.appendChild(urgTitle);
                    urgText.appendChild(urgSub);

                    urgHeader.appendChild(alarm);
                    urgHeader.appendChild(urgText);
                    inner.appendChild(urgHeader);

                    // Score display — opponent's declared perspective (from my view)
                    const iWinning = m.declared_winner_id && m.declared_winner_id !== currentUser.id;
                    const scoreDisplay = document.createElement('div');
                    scoreDisplay.className = 'urgent-score-display';
                    scoreDisplay.innerHTML = \`
                        <div class="urgent-score-team">
                            <div class="urgent-score-team-name">\${escapeHtml(myTeam)}</div>
                            <div class="urgent-score-num \${iWinning ? '' : 'winning'}">\${myScore ?? '?'}</div>
                        </div>
                        <div class="urgent-score-sep">—</div>
                        <div class="urgent-score-team">
                            <div class="urgent-score-team-name">\${escapeHtml(oppTeam)}</div>
                            <div class="urgent-score-num \${iWinning ? 'winning' : ''}">\${oppScore ?? '?'}</div>
                        </div>\`;
                    inner.appendChild(scoreDisplay);

                    // Big red clock — built via DOM so deadline string is never escaped/corrupted
                    const urgClockBlock = document.createElement('div');
                    urgClockBlock.className = 'urgent-clock-block';

                    const urgClockLabel = document.createElement('div');
                    urgClockLabel.className = 'urgent-clock-label';
                    urgClockLabel.textContent = '⚠️ Time left to respond';
                    urgClockBlock.appendChild(urgClockLabel);

                    const urgClockDigits = document.createElement('div');
                    urgClockDigits.className = 'urgent-clock-digits';

                    const urgMinUnit = document.createElement('div');
                    urgMinUnit.className = 'clock-unit';
                    const urgMinNum = document.createElement('span');
                    urgMinNum.className = 'clock-num urgent-red';
                    urgMinNum.setAttribute('data-clock-part', 'min');
                    if (deadline) urgMinNum.setAttribute('data-deadline', deadline);
                    urgMinNum.textContent = deadline ? '--' : '??';
                    const urgMinLabel = document.createElement('div');
                    urgMinLabel.className = 'clock-unit-label';
                    urgMinLabel.style.color = '#883333';
                    urgMinLabel.textContent = 'min';
                    urgMinUnit.appendChild(urgMinNum);
                    urgMinUnit.appendChild(urgMinLabel);

                    const urgSepEl = document.createElement('span');
                    urgSepEl.className = 'urgent-clock-sep';
                    urgSepEl.textContent = ':';

                    const urgSecUnit = document.createElement('div');
                    urgSecUnit.className = 'clock-unit';
                    const urgSecNum = document.createElement('span');
                    urgSecNum.className = 'clock-num urgent-red';
                    urgSecNum.setAttribute('data-clock-part', 'sec');
                    if (deadline) urgSecNum.setAttribute('data-deadline', deadline);
                    urgSecNum.textContent = deadline ? '--' : '??';
                    const urgSecLabel = document.createElement('div');
                    urgSecLabel.className = 'clock-unit-label';
                    urgSecLabel.style.color = '#883333';
                    urgSecLabel.textContent = 'sec';
                    urgSecUnit.appendChild(urgSecNum);
                    urgSecUnit.appendChild(urgSecLabel);

                    urgClockDigits.appendChild(urgMinUnit);
                    urgClockDigits.appendChild(urgSepEl);
                    urgClockDigits.appendChild(urgSecUnit);
                    urgClockBlock.appendChild(urgClockDigits);

                    const urgBarWrap = document.createElement('div');
                    urgBarWrap.className = 'urgent-bar';
                    const urgBarFill = document.createElement('div');
                    urgBarFill.className = 'urgent-bar-fill';
                    if (deadline) {
                        urgBarFill.setAttribute('data-deadline', deadline);
                        urgBarFill.setAttribute('data-total', String(totalMs));
                    }
                    urgBarFill.style.width = '100%';
                    urgBarWrap.appendChild(urgBarFill);
                    urgClockBlock.appendChild(urgBarWrap);

                    const urgAutoLoseNote = document.createElement('div');
                    urgAutoLoseNote.className = 'urgent-auto-lose-note';
                    urgAutoLoseNote.innerHTML = "If you don't respond, you <strong>automatically lose</strong>";
                    urgClockBlock.appendChild(urgAutoLoseNote);

                    inner.appendChild(urgClockBlock);

                    // Action button
                    const actionBtn = document.createElement('button');
                    actionBtn.className = 'urgent-action-btn';
                    actionBtn.innerHTML = '⚡ Confirm or Dispute Now';
                    actionBtn.addEventListener('click', e => { e.stopPropagation(); openReportResultModal(m.id); });
                    inner.appendChild(actionBtn);

                    stateCard.appendChild(inner);
                    item.appendChild(stateCard);
                }

            } else if (m.status === 'penalty_shootout') {
                const actionsDiv = createElementSafe('div', { class: 'match-actions' });
                const penaltyEl = createElementSafe('div', { style: 'font-size:0.82rem;color:#ffb400;padding:6px 0;line-height:1.5;' }, '');
                penaltyEl.innerHTML = \`⚽ <strong>Penalty Shootout!</strong><br><span style="color:#888;font-size:0.75rem;">Go to eFootball → create a new Friends room → play Penalties → upload result here</span>\`;
                actionsDiv.appendChild(penaltyEl);
                if (m.screenshot_url) {
                    const pendingEl = document.createElement('div');
                    pendingEl.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(255,180,0,0.08);border:1px solid rgba(255,180,0,0.2);border-radius:10px;margin-top:6px;';
                    pendingEl.innerHTML = \`<span style="font-size:1.1rem;">⏳</span><div><div style="font-size:0.8rem;font-weight:700;color:#ffb400;">Pending Payout</div><div style="font-size:0.7rem;color:#888;margin-top:1px;">Admin is reviewing your penalty result</div></div>\`;
                    actionsDiv.appendChild(pendingEl);
                } else {
                    const penBtn = createElementSafe('button', { class: 'btn btn-green' }, '📸 Upload Penalty Result');
                    penBtn.addEventListener('click', e => { e.stopPropagation(); openReportResultModal(m.id); });
                    actionsDiv.appendChild(penBtn);
                }
                item.appendChild(actionsDiv);

            } else if (m.status === 'disputed') {
                item.appendChild(createElementSafe('div', { style: 'font-size:0.8rem;color:#ff8888;padding:10px 0;' }, '⚖️ Disputed — an admin is reviewing. Usually resolved within 24 hours.'));

            } else if (m.status === 'completed') {
                const youWon = m.winner_id === currentUser.id;
                const isCreator = m.creator_id === currentUser.id;
                const myScore  = isCreator ? m.declared_score_creator : m.declared_score_joiner;
                const oppScore = isCreator ? m.declared_score_joiner  : m.declared_score_creator;
                const hasScore = myScore != null && oppScore != null;
                const oppName  = isCreator
                    ? (m.joiner?.username  || 'Opponent')
                    : (m.creator?.username || 'Opponent');

                const settlementLabels = {
                    'dual_upload_auto':    'AI verified',
                    'dual_upload_gemini':  'AI arbitrated',
                    'gemini_arbitration':  'AI arbitrated',
                    'mutual_confirmation': 'Both confirmed',
                    'auto_declaration':    'Auto-settled',
                    'challenge_timeout':   'Challenge expired',
                    'opponent_no_upload':  'Opponent forfeited',
                    'forfeit':             'Opponent forfeited',
                    'admin_override':      'Admin decision',
                    'admin_approved':      'Admin approved',
                    'penalty_shootout':    'Penalty shootout',
                };
                const settlementLabel = settlementLabels[m.settlement_method] || 'Settled';

                const card = document.createElement('div');
                card.style.cssText = \`
                    margin-top:12px;
                    border-radius:14px;
                    overflow:hidden;
                    border:1px solid \${youWon ? 'rgba(0,255,65,0.25)' : 'rgba(255,255,255,0.07)'};
                    background:\${youWon ? 'linear-gradient(135deg,rgba(0,255,65,0.07),rgba(0,255,65,0.02))' : 'rgba(255,255,255,0.02)'};
                \`;

                // Top row: emoji + result label + settlement method
                const topRow = document.createElement('div');
                topRow.style.cssText = 'display:flex;align-items:center;gap:10px;padding:14px 16px 10px;';

                const emoji = document.createElement('div');
                emoji.style.cssText = \`font-size:1.8rem;line-height:1;flex-shrink:0;\`;
                emoji.textContent = youWon ? '🏆' : '😔';

                const textGroup = document.createElement('div');
                textGroup.style.cssText = 'flex:1;min-width:0;';

                const resultLabel = document.createElement('div');
                resultLabel.style.cssText = \`font-size:1rem;font-weight:800;color:\${youWon ? 'var(--neon)' : '#888'};\`;
                resultLabel.textContent = youWon ? 'You won!' : \`\${escapeHtml(oppName)} won\`;

                const settleBadge = document.createElement('div');
                settleBadge.style.cssText = 'font-size:0.62rem;letter-spacing:1px;text-transform:uppercase;color:#444;margin-top:2px;';
                settleBadge.textContent = settlementLabel;

                textGroup.appendChild(resultLabel);
                textGroup.appendChild(settleBadge);
                topRow.appendChild(emoji);
                topRow.appendChild(textGroup);

                if (youWon && m.winner_prize) {
                    const prizeTag = document.createElement('div');
                    prizeTag.style.cssText = 'background:rgba(0,255,65,0.1);border:1px solid rgba(0,255,65,0.2);border-radius:8px;padding:5px 10px;text-align:center;flex-shrink:0;';
                    prizeTag.innerHTML = \`<div style="font-size:0.55rem;letter-spacing:1.5px;text-transform:uppercase;color:#3a7a3a;">Won</div><div style="font-family:'Bebas Neue',sans-serif;font-size:1.1rem;color:var(--neon);letter-spacing:1px;">KES \${m.winner_prize}</div>\`;
                    topRow.appendChild(prizeTag);
                }

                card.appendChild(topRow);

                // Score strip (if available)
                if (hasScore) {
                    const scoreStrip = document.createElement('div');
                    scoreStrip.style.cssText = 'display:flex;align-items:center;justify-content:center;gap:12px;padding:10px 16px 14px;border-top:1px solid rgba(255,255,255,0.05);';

                    const myScoreEl = document.createElement('div');
                    myScoreEl.style.cssText = 'text-align:center;flex:1;';
                    myScoreEl.innerHTML = \`<div style="font-size:0.55rem;letter-spacing:1.5px;text-transform:uppercase;color:#333;margin-bottom:3px;">\${escapeHtml(myTeam || 'You')}</div><div style="font-family:'Bebas Neue',sans-serif;font-size:2rem;color:\${youWon ? 'var(--neon)' : '#666'};line-height:1;">\${myScore}</div>\`;

                    const sepEl = document.createElement('div');
                    sepEl.style.cssText = 'font-family:"Bebas Neue",sans-serif;font-size:1.4rem;color:#2a2a2a;';
                    sepEl.textContent = '—';

                    const oppScoreEl = document.createElement('div');
                    oppScoreEl.style.cssText = 'text-align:center;flex:1;';
                    oppScoreEl.innerHTML = \`<div style="font-size:0.55rem;letter-spacing:1.5px;text-transform:uppercase;color:#333;margin-bottom:3px;">\${escapeHtml(oppTeam || oppName)}</div><div style="font-family:'Bebas Neue',sans-serif;font-size:2rem;color:\${!youWon ? '#cc4444' : '#666'};line-height:1;">\${oppScore}</div>\`;

                    scoreStrip.appendChild(myScoreEl);
                    scoreStrip.appendChild(sepEl);
                    scoreStrip.appendChild(oppScoreEl);
                    card.appendChild(scoreStrip);
                }

                item.appendChild(card);
            }

            container.appendChild(item);
        });

        // After rendering, update ring progress immediately
        tickAllClocks();
    }

    // ── Master tick: drives ALL countdown clocks every second ──────────────
    function tickAllClocks() {
        const now = Date.now();

        // 1. SVG ring (confirming card)
        document.querySelectorAll('.confirming-ring-progress[data-deadline]').forEach(ring => {
            const deadline  = new Date(ring.dataset.deadline);
            const total     = parseFloat(ring.dataset.total) || (30 * 60 * 1000);
            const remaining = Math.max(0, deadline - now);
            const pct       = remaining / total;
            const circ      = parseFloat(ring.getAttribute('stroke-dasharray')) || 110;
            ring.style.strokeDashoffset = (circ * (1 - pct)).toFixed(2);
            if (remaining < 5 * 60 * 1000) {
                ring.style.stroke = '#ff4444';
                ring.style.filter = 'drop-shadow(0 0 3px rgba(255,68,68,0.6))';
            }
        });

        // 2. Green progress bar (confirming)
        document.querySelectorAll('.confirming-countdown-fill[data-deadline]').forEach(bar => {
            const deadline  = new Date(bar.dataset.deadline);
            const total     = parseFloat(bar.dataset.total) || (30 * 60 * 1000);
            const remaining = Math.max(0, deadline - now);
            bar.style.width  = ((remaining / total) * 100).toFixed(1) + '%';
            if (remaining < 5 * 60 * 1000)
                bar.style.background = 'linear-gradient(90deg,#ff4444,rgba(255,68,68,0.5))';
        });

        // 3. Red progress bar (urgent)
        document.querySelectorAll('.urgent-bar-fill[data-deadline]').forEach(bar => {
            const deadline  = new Date(bar.dataset.deadline);
            const total     = parseFloat(bar.dataset.total) || (30 * 60 * 1000);
            const remaining = Math.max(0, deadline - now);
            bar.style.width  = ((remaining / total) * 100).toFixed(1) + '%';
        });

        // 4. Big clock digits  [data-clock-part="min|sec"]
        document.querySelectorAll('[data-clock-part][data-deadline]').forEach(el => {
            const raw = el.getAttribute('data-deadline');
            if (!raw) return;
            const deadline  = new Date(raw);
            const remaining = Math.max(0, deadline - now);
            const totalSecs = Math.floor(remaining / 1000);
            const mins = Math.floor(totalSecs / 60);
            const secs = totalSecs % 60;
            const part = el.getAttribute('data-clock-part');
            el.textContent = part === 'min'
                ? String(mins).padStart(2, '0')
                : String(secs).padStart(2, '0');
            // Last 5 min → turn red
            if (remaining < 5 * 60 * 1000 && !el.classList.contains('urgent-red')) {
                el.style.color      = '#ff4444';
                el.style.textShadow = '0 0 24px rgba(255,68,68,0.5)';
            }
            // Last 60 sec → pulse
            if (remaining < 60 * 1000) el.style.animation = 'pulse 0.5s infinite';
        });

        // 5. Legacy .countdown-timer[data-deadline] spans (modal step-3, etc.)
        document.querySelectorAll('.countdown-timer[data-deadline]').forEach(el => {
            const raw = el.getAttribute('data-deadline');
            if (!raw) return;
            const deadline  = new Date(raw);
            const remaining = deadline - now;
            if (remaining <= 0) {
                el.textContent  = 'any moment now';
                el.style.color  = '#ff4444';
            } else {
                const totalSecs = Math.floor(remaining / 1000);
                const m = Math.floor(totalSecs / 60);
                const s = totalSecs % 60;
                el.textContent = m > 0 ? \`\${m}m \${String(s).padStart(2,'0')}s\` : \`\${s}s\`;
                if (remaining < 5 * 60 * 1000) el.style.color = '#ff6666';
            }
        });
    }

    setInterval(tickAllClocks, 1000);
    tickAllClocks(); // run immediately on load

    // ══════════════════════════════════════════════════════════════
    // CONFIRM-ACTION BANNER — shows when opponent has declared and
    // it's the current player's turn to confirm or dispute.
    // ══════════════════════════════════════════════════════════════
    let _bannerMatchId     = null;
    let _bannerDeadline    = null;
    let _bannerTotalMs     = 30 * 60 * 1000;
    let _bannerDismissed   = false;
    let _bannerVisible     = false;

    function showConfirmBanner({ matchId, deadline, myTeam, oppTeam, myScore, oppScore, iWon }) {
        _bannerMatchId   = matchId;
        _bannerDeadline  = new Date(deadline);
        _bannerDismissed = false;
        _bannerVisible   = true;

        // Populate score
        document.getElementById('banner-my-team').textContent  = (myTeam  || 'YOU').toUpperCase().slice(0, 14);
        document.getElementById('banner-opp-team').textContent = (oppTeam || 'OPP').toUpperCase().slice(0, 14);
        document.getElementById('banner-my-score').textContent  = myScore  ?? '?';
        document.getElementById('banner-opp-score').textContent = oppScore ?? '?';

        const resultEl = document.getElementById('banner-result-line');
        if (iWon === true) {
            resultEl.textContent = '🏆 They say YOU won — confirm to collect';
            resultEl.className   = 'banner-result-line win';
        } else if (iWon === false) {
            resultEl.textContent = '😔 They say they won — dispute if incorrect';
            resultEl.className   = 'banner-result-line lose';
        } else {
            resultEl.textContent = '🤝 They declared a draw';
            resultEl.className   = 'banner-result-line';
        }

        // Wire buttons (re-bind each time to avoid stale matchId closure)
        const confirmBtn = document.getElementById('banner-confirm-btn');
        const disputeBtn = document.getElementById('banner-dispute-btn');
        confirmBtn.onclick = () => { hideConfirmBanner(); openReportResultModal(matchId); };
        disputeBtn.onclick = () => { hideConfirmBanner(); openReportResultModal(matchId); };

        // Dismiss button just hides for this session
        document.getElementById('banner-dismiss-btn').onclick = () => {
            _bannerDismissed = true;
            hideConfirmBanner();
        };

        document.getElementById('confirm-action-banner').classList.remove('expired');
        document.getElementById('confirm-action-banner').classList.add('visible');

        // Kick the clock immediately
        tickBannerClock();
    }

    function hideConfirmBanner() {
        _bannerVisible = false;
        document.getElementById('confirm-action-banner').classList.remove('visible');
    }

    function tickBannerClock() {
        const banner = document.getElementById('confirm-action-banner');
        if (!_bannerVisible || !_bannerDeadline) return;

        const now       = Date.now();
        const remaining = Math.max(0, _bannerDeadline - now);
        const totalSecs = Math.floor(remaining / 1000);
        const mins      = Math.floor(totalSecs / 60);
        const secs      = totalSecs % 60;

        const minEl  = document.getElementById('banner-min');
        const secEl  = document.getElementById('banner-sec');
        const fillEl = document.getElementById('banner-progress-fill');

        if (minEl) minEl.textContent = String(mins).padStart(2, '0');
        if (secEl) secEl.textContent = String(secs).padStart(2, '0');

        if (fillEl) {
            const pct = (remaining / _bannerTotalMs) * 100;
            fillEl.style.width = Math.max(0, pct).toFixed(1) + '%';
        }

        // Under 5 minutes — intensify
        if (remaining < 5 * 60 * 1000 && remaining > 0) {
            if (minEl) minEl.style.textShadow = '0 0 28px rgba(255,68,68,0.8)';
            if (secEl) secEl.style.textShadow = '0 0 28px rgba(255,68,68,0.8)';
        }

        // Under 60 seconds — pulse
        if (remaining < 60 * 1000 && remaining > 0) {
            if (minEl) minEl.style.animation = 'pulse 0.5s infinite';
            if (secEl) secEl.style.animation = 'pulse 0.5s infinite';
        }

        // Expired
        if (remaining === 0) {
            if (minEl) minEl.textContent = '00';
            if (secEl) secEl.textContent = '00';
            banner.classList.add('expired');
        }
    }

    // Plug banner tick into the master 1-second interval
    const _origTickAllClocks = tickAllClocks;
    // We do it by extending the interval — call tickBannerClock every second too
    setInterval(tickBannerClock, 1000);

    // ── Check matches and show banner if needed ──────────────────
    // Called after loadMyFriendMatches() resolves
    function checkAndShowConfirmBanner(matches) {
        if (!matches || !Array.isArray(matches)) return;
        if (_bannerDismissed) return;

        // Find the first match where I need to respond (opponent declared, not me)
        const urgent = matches.find(m =>
            m.status === 'awaiting_confirmation' &&
            m.declared_score_by &&
            m.declared_score_by !== currentUser.id &&
            m.score_confirm_deadline
        );

        if (!urgent) {
            hideConfirmBanner();
            return;
        }

        // Already showing for same match? Just update clock
        if (_bannerVisible && _bannerMatchId === urgent.id) return;

        const isCreator = urgent.creator_id === currentUser.id;
        const myTeam    = isCreator ? urgent.creator_team : urgent.joiner_team;
        const oppTeam   = isCreator ? urgent.joiner_team  : urgent.creator_team;
        const myScore   = isCreator ? urgent.declared_score_creator : urgent.declared_score_joiner;
        const oppScore  = isCreator ? urgent.declared_score_joiner  : urgent.declared_score_creator;
        const iWon      = urgent.declared_winner_id
            ? urgent.declared_winner_id === currentUser.id
            : null;
        const oppName   = isCreator
            ? (urgent.joiner?.username  || 'Opponent')
            : (urgent.creator?.username || 'Opponent');

        document.getElementById('banner-title').textContent = \`\${oppName} posted results\`;
        document.getElementById('banner-sub').textContent   = 'Confirm or dispute before time runs out';

        showConfirmBanner({
            matchId:  urgent.id,
            deadline: urgent.score_confirm_deadline,
            myTeam,
            oppTeam,
            myScore,
            oppScore,
            iWon
        });
    }

    async function cancelPendingMatch(matchId) {
        if (!confirm('Cancel this pending match? Your wager will be refunded.')) return;
        try {
            console.log('📝 Cancelling pending match:', matchId);
            const res = await fetchWithAuth('/friends/cancel-match', {
                method: 'POST',
                body: JSON.stringify({ matchId })
            }, 10000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            
            console.log('✅ Pending match cancelled, refund:', data.refundedAmount);
            
            // CRITICAL FIX: Always refresh balance from server after cancel
            await refreshBalance(3);
            console.log('💰 Balance refreshed after cancel:', currentBalance);
            
            await loadMyFriendMatches();
        } catch (err) {
            console.error('❌ Error cancelling pending match:', err);
            alert(err.message);
            // Refresh balance anyway
            await refreshBalance(3);
        }
    }

    // ── Toast notification system ──────────────────────────────
    let _toastTimeout = null;
    function showToast(type, title, msg, duration = 4000) {
        const toast = document.getElementById('global-toast');
        const iconEl = document.getElementById('toast-icon');
        const titleEl = document.getElementById('toast-title');
        const msgEl = document.getElementById('toast-msg');
        const icons = { success: '✅', error: '❌', info: '⏳' };
        toast.className = \`modal-toast \${type}\`;
        iconEl.textContent = icons[type] || '💬';
        titleEl.textContent = title;
        msgEl.textContent = msg || '';
        void toast.offsetWidth;
        toast.classList.add('show');
        if (_toastTimeout) clearTimeout(_toastTimeout);
        _toastTimeout = setTimeout(() => toast.classList.remove('show'), duration);
    }

    // ── Screenshot guide toggle ────────────────────────────────
    // ═══════════════════════════════════════════════════════════════
    // SCORE DECLARATION SYSTEM
    // ═══════════════════════════════════════════════════════════════
    let _declareMyScore = 0, _declareOppScore = 0;
    let _declareUploadedUrl = null, _declareUploadedObjectUrl = null;
    let _confirmUploadedUrl = null;
    let _disputeUploadedUrl = null;
    let _disputeMyScore = 0, _disputeOppScore = 0;

    function adjustScore(side, delta) {
        if (side === 'my') { _declareMyScore = Math.max(0, Math.min(20, _declareMyScore + delta)); document.getElementById('my-score-display').textContent = _declareMyScore; }
        else { _declareOppScore = Math.max(0, Math.min(20, _declareOppScore + delta)); document.getElementById('opp-score-display').textContent = _declareOppScore; }
        const lbl = document.getElementById('score-result-label');
        if (lbl) lbl.textContent = _declareMyScore > _declareOppScore ? '🏆 You won!' : _declareOppScore > _declareMyScore ? '😔 You lost' : '🤝 Draw';
    }
    function adjustDisputeScore(side, delta) {
        if (side === 'my') { _disputeMyScore = Math.max(0, Math.min(20, _disputeMyScore + delta)); document.getElementById('dispute-my-score').textContent = _disputeMyScore; }
        else { _disputeOppScore = Math.max(0, Math.min(20, _disputeOppScore + delta)); document.getElementById('dispute-opp-score').textContent = _disputeOppScore; }
    }
    function goToDeclareStep2() {
        const s = document.getElementById('score-summary-display');
        const r = document.getElementById('score-summary-result');
        if (s) s.textContent = \`\${_declareMyScore}  —  \${_declareOppScore}\`;
        if (r) r.textContent = _declareMyScore > _declareOppScore ? '🏆 You win' : _declareOppScore > _declareMyScore ? '😔 You lose' : '🤝 Draw';
        switchStep('report-result-modal', 2);
    }
    function resetReportModal() {
        _declareMyScore = 0; _declareOppScore = 0;
        _declareUploadedUrl = null; _confirmUploadedUrl = null; _disputeUploadedUrl = null;
        if (_declareUploadedObjectUrl) { URL.revokeObjectURL(_declareUploadedObjectUrl); _declareUploadedObjectUrl = null; }
        ['my-score-display','opp-score-display'].forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '0'; });
        const lbl = document.getElementById('score-result-label'); if (lbl) lbl.textContent = 'Draw';
        const icon = document.getElementById('upload-icon'); if (icon) icon.textContent = '📲';
        const label = document.getElementById('upload-label'); if (label) label.innerHTML = '<strong>Tap to upload screenshot</strong><br><span style="font-size:0.78rem;color:#555;">Take it directly from eFootball</span>';
        const thumb = document.getElementById('screenshot-thumb'); if (thumb) { thumb.classList.remove('visible'); thumb.src = ''; }
        const progress = document.getElementById('upload-progress'); if (progress) progress.classList.remove('visible');
        const fi = document.getElementById('screenshot-file-input'); if (fi) fi.value = '';
        const err1 = document.getElementById('declare-error-1'); if (err1) err1.style.display = 'none';
        const err2 = document.getElementById('declare-error-2'); if (err2) err2.style.display = 'none';
        switchStep('report-result-modal', 2);
    }
    async function handleScreenshotSelected(file) {
        if (!file || !currentReportMatch) return;
        if (!['image/jpeg','image/png','image/webp'].includes(file.type)) { showError('declare-error-2', 'Please upload a JPEG, PNG or WebP image.'); return; }
        if (file.size > 10*1024*1024) { showError('declare-error-2', 'File too large. Max 10MB.'); return; }
        if (_declareUploadedObjectUrl) URL.revokeObjectURL(_declareUploadedObjectUrl);
        _declareUploadedObjectUrl = URL.createObjectURL(file);
        const thumb = document.getElementById('screenshot-thumb');
        const icon = document.getElementById('upload-icon');
        const label = document.getElementById('upload-label');
        if (thumb) { thumb.src = _declareUploadedObjectUrl; thumb.classList.add('visible'); }
        if (icon) icon.textContent = '⏳';
        if (label) label.innerHTML = '<strong>Uploading...</strong>';
        _declareUploadedUrl = null;
        const progress = document.getElementById('upload-progress');
        if (progress) progress.classList.add('visible');
        try {
            const formData = new FormData();
            formData.append('screenshot', file);
            formData.append('matchId', currentReportMatch.id);

            const res = await fetchWithAuth('/screenshots/upload-and-verify', { method: 'POST', body: formData, headers: {} }, 100000);
            if (progress) progress.classList.remove('visible');

            // Always parse JSON regardless of status
            let data = {};
            try { data = await res.json(); } catch (_) {}

            // 422: Gemini couldn't read score → sent to admin review
            if (res.status === 422) {
                if (icon) icon.textContent = '📋';
                if (label) label.innerHTML = '<strong style="color:#ffaa00">📋 Sent for admin review</strong><br><span style="font-size:0.75rem;color:#aaa;">' + (data.instruction || 'An admin will review and settle the match.') + '</span>';
                showError('declare-error-2', data.error || 'Could not read score. Sent to admin for review.');
                showToast('info', '📋 Sent for Review', data.instruction || 'An admin will review your screenshot and settle the match.', 8000);
                _declareUploadedUrl = 'pending_review';
                return;
            }

            // 409 pendingPayout: already uploaded, waiting for admin
            if (res.status === 409 && data.pendingPayout) {
                if (icon) icon.textContent = '⏳';
                if (label) label.innerHTML = '<strong style="color:#ffb400">⏳ Pending Payout</strong><br><span style="font-size:0.75rem;color:#aaa;">Your screenshot is already submitted. Admin is reviewing.</span>';
                closeModal('report-result-modal');
                showToast('info', '⏳ Already Submitted', 'Your screenshot is pending admin review. Do not resubmit.', 7000);
                await loadMyFriendMatches();
                return;
            }

            // Other errors (409 duplicate hash, 400 bad file, etc.)
            if (!res.ok) {
                const msg = data.error || 'Upload failed. Please try again.';
                if (icon) icon.textContent = '❌';
                if (label) label.innerHTML = '<strong style="color:#ff4455">❌ Upload failed</strong><br><span style="font-size:0.75rem;color:#aaa;">' + msg + '</span>';
                showError('declare-error-2', msg);
                return;
            }

            _declareUploadedUrl = data.screenshotUrl || null;

            // Auto-settled: Gemini read score + winner paid
            if (data.autoSettled) {
                if (icon) icon.textContent = '🏆';
                if (label) label.innerHTML = '<strong style="color:var(--neon)">🏆 Match settled!</strong><br><span style="font-size:0.75rem;color:#aaa;">Gemini detected the score. Winner has been paid.</span>';
                closeModal('report-result-modal');
                await loadMyFriendMatches();
                await refreshBalance(3);
                const s = data.ocrResult;
                showToast('success', '🏆 Match Settled!', 'Score ' + (s?.score1 ?? '?') + '–' + (s?.score2 ?? '?') + ' detected. Winner paid!', 7000);
                return;
            }

            // Score read, waiting for opponent to confirm
            if (data.ocrResult && data.ocrResult.score1 !== null && data.ocrResult.score1 !== undefined) {
                const s = data.ocrResult;
                if (icon) icon.textContent = '✅';
                if (label) label.innerHTML = '<strong style="color:var(--neon)">✅ Score read: ' + s.score1 + '–' + s.score2 + '</strong><br><span style="font-size:0.75rem;color:#aaa;">Opponent has 2 hours to confirm.</span>';
                const recap = document.getElementById('declared-score-recap');
                const resultRecap = document.getElementById('declared-result-recap');
                if (recap) recap.textContent = s.score1 + '  —  ' + s.score2;
                if (resultRecap) {
                    const isCreator = currentReportMatch.creator_id === currentUser.id;
                    const myScore  = isCreator ? s.score1 : s.score2;
                    const oppScore = isCreator ? s.score2 : s.score1;
                    if (myScore > oppScore)      { resultRecap.textContent = '🏆 You won!'; resultRecap.style.color = 'var(--neon)'; }
                    else if (myScore < oppScore) { resultRecap.textContent = '😔 You lost'; resultRecap.style.color = '#ff6666'; }
                    else                         { resultRecap.textContent = '🤝 Draw'; resultRecap.style.color = '#ffb400'; }
                }
                const countdownEl = document.getElementById('declare-countdown');
                if (countdownEl && data.confirmDeadline) { countdownEl.setAttribute('data-deadline', data.confirmDeadline); tickAllClocks(); }
                setTimeout(async () => {
                    switchStep('report-result-modal', 3);
                    await loadMyFriendMatches();
                    showToast('info', '⏳ Score Declared', 'Score ' + s.score1 + '–' + s.score2 + ' detected. Waiting for opponent.', 7000);
                }, 1200);
                return;
            }

            // Fallback: response OK but no actionable score
            if (icon) icon.textContent = '⚠️';
            if (label) label.innerHTML = '<strong style="color:#ffaa00">⚠️ Unclear result</strong><br><span style="font-size:0.75rem;color:#aaa;">Try uploading a clearer screenshot.</span>';

        } catch (err) {
            if (progress) progress.classList.remove('visible');
            if (icon) icon.textContent = '❌';
            const errMsg = err.message || 'Upload failed. Please try again.';
            if (label) label.innerHTML = '<strong style="color:#ff4455">❌ Error</strong><br><span style="font-size:0.75rem;color:#aaa;">' + errMsg + '</span>';
            showError('declare-error-2', errMsg);
        }
    }
    async function _uploadHelper(file, onSuccess) {
        if (!file) return;
        try {
            const formData = new FormData();
            formData.append('screenshot', file);
            formData.append('matchId', currentReportMatch.id);
            const res = await fetchWithAuth('/screenshots/upload-and-verify', { method: 'POST', body: formData, headers: {} }, 30000);
            if (res && res.ok) { const d = await res.json(); onSuccess(d.screenshotUrl || d.url || d.publicUrl); }
        } catch (e) {}
    }
    async function handleConfirmScreenshot(file) {
        if (!file) return;
        const thumb = document.getElementById('confirm-screenshot-thumb');
        const lbl = document.getElementById('confirm-upload-label');
        if (thumb) { thumb.src = URL.createObjectURL(file); thumb.classList.add('visible'); }
        await _uploadHelper(file, url => {
            _confirmUploadedUrl = url;
            if (lbl) lbl.innerHTML = '<strong style="color:var(--neon)">✅ Screenshot uploaded</strong>';
        });
    }
    async function handleDisputeScreenshot(file) {
        if (!file) return;
        const thumb = document.getElementById('dispute-screenshot-thumb');
        if (thumb) { thumb.src = URL.createObjectURL(file); thumb.classList.add('visible'); }
        await _uploadHelper(file, url => { _disputeUploadedUrl = url; });
    }
    async function submitScoreDeclaration() {
        if (!currentReportMatch) return;
        const btn = document.getElementById('declare-submit-btn');
        showError('declare-error-2', '');
        // Screenshot optional — don't block submission if skipped or timed out
        btn.disabled = true; btn.textContent = 'Declaring...';
        try {
            const res = await fetchWithAuth('/friends/declare-score', {
                method: 'POST',
                body: JSON.stringify({ matchId: currentReportMatch.id, myScore: _declareMyScore, opponentScore: _declareOppScore, screenshotUrl: (_declareUploadedUrl && _declareUploadedUrl !== 'skipped') ? _declareUploadedUrl : null })
            }, 15000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);

            // Draw → penalty shootout — show special message then close
            if (data.isDraw) {
                closeModal('report-result-modal');
                await loadMyFriendMatches();
                showToast('info', '🤝 It\\'s a Draw!',
                    'Go to eFootball → create a new Friends Match room → play a Penalty Shootout → come back and upload the result.',
                    8000);
                return;
            }

            // Non-draw → show waiting screen with countdown
            const recap = document.getElementById('declared-score-recap');
            const resultRecap = document.getElementById('declared-result-recap');
            if (recap) recap.textContent = \`\${_declareMyScore}  —  \${_declareOppScore}\`;
            if (resultRecap) {
                if (_declareMyScore > _declareOppScore) { resultRecap.textContent = '🏆 You declared a WIN'; resultRecap.style.color = 'var(--neon)'; }
                else { resultRecap.textContent = '😔 You declared a LOSS'; resultRecap.style.color = '#ff6666'; }
            }
            // Show auto-win countdown on step 3
            const countdownEl = document.getElementById('declare-countdown');
            if (countdownEl && data.confirmDeadline) {
                countdownEl.setAttribute('data-deadline', data.confirmDeadline);
                tickAllClocks();
            }
            switchStep('report-result-modal', 3);
            await loadMyFriendMatches();
        } catch (err) {
            showError('declare-error-2', err.message || 'Failed to declare. Try again.');
        } finally { btn.disabled = false; btn.textContent = '✅ DECLARE MY SCORE'; }
    }
    function showDisputeForm() {
        _disputeMyScore = 0; _disputeOppScore = 0;
        document.getElementById('dispute-my-score').textContent = '0';
        document.getElementById('dispute-opp-score').textContent = '0';
        switchStep('report-result-modal', 'dispute');
    }
    async function confirmOpponentScore() {
        if (!currentReportMatch) return;
        showError('confirm-error', '');
        try {
            const res = await fetchWithAuth('/friends/confirm-score', {
                method: 'POST', body: JSON.stringify({ matchId: currentReportMatch.id, screenshotUrl: _confirmUploadedUrl || null })
            }, 15000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            closeModal('report-result-modal');
            await refreshBalance(3);
            await loadMyFriendMatches();
            showToast(data.youWon ? 'success' : 'info', data.youWon ? '🏆 You Won!' : 'Match Confirmed',
                data.youWon ? \`KES \${data.prizePaid} added to your wallet!\` : 'Result confirmed. Better luck next time!', 6000);
        } catch (err) { showError('confirm-error', err.message || 'Failed to confirm. Try again.'); }
    }
    async function submitDispute() {
        if (!currentReportMatch) return;
        showError('dispute-error', '');
        if (!_disputeUploadedUrl) { showError('dispute-error', 'Please upload your screenshot as evidence.'); return; }
        try {
            const res = await fetchWithAuth('/friends/dispute-score', {
                method: 'POST', body: JSON.stringify({ matchId: currentReportMatch.id, screenshotUrl: _disputeUploadedUrl, myScore: _disputeMyScore, opponentScore: _disputeOppScore })
            }, 15000);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            closeModal('report-result-modal');
            await loadMyFriendMatches();
            showToast('info', '⚖️ Dispute Raised', 'An admin will review both screenshots within 24 hours.', 7000);
        } catch (err) { showError('dispute-error', err.message || 'Failed to raise dispute.'); }
    }

    // switchStep extended to support named steps (declare-step-confirm, declare-step-dispute)
    function switchStep(modalId, stepNum) {
        const modal = document.getElementById(modalId);
        if (!modal) return;
        modal.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        let target;
        if (stepNum === 'confirm') target = modal.querySelector('#declare-step-confirm');
        else if (stepNum === 'dispute') target = modal.querySelector('#declare-step-dispute');
        else {
            const steps = modal.querySelectorAll('.step');
            if (steps[stepNum - 1]) target = steps[stepNum - 1];
        }
        if (target) target.classList.add('active');
    }

    function openReportResultModal(matchId) {
        fetchWithAuth('/friends/my-matches', {}, 8000).then(async res => {
            const matches = await res.json();
            const match = matches.find(m => m.id === matchId);
            if (!match) { showToast('error', 'Match Not Found', 'Could not load match details.', 4000); return; }
            currentReportMatch = match;
            resetReportModal();
            const isCreator = match.creator_id === currentUser.id;
            const myTeam = isCreator ? match.creator_team : match.joiner_team;
            const oppTeam = isCreator ? match.joiner_team : match.creator_team;
            const disputeMyLabel = document.getElementById('dispute-my-label');
            if (disputeMyLabel) disputeMyLabel.textContent = myTeam || 'MY GOALS';
            // Populate details in both possible containers
            const detailsHtml = \`
                <div class="match-detail-row"><span class="match-detail-label">Wager</span><span class="match-detail-value">KES \${match.wager_amount}</span></div>
                <div class="match-detail-row"><span class="match-detail-label">Winner prize</span><span class="match-detail-value neon">KES \${match.winner_prize}</span></div>
                <div class="match-detail-row"><span class="match-detail-label">Your team</span><span class="match-detail-value" style="color:#ccc;">\${escapeHtml(myTeam || '—')}</span></div>
                <div class="match-detail-row"><span class="match-detail-label">Opponent</span><span class="match-detail-value" style="color:#ccc;">\${escapeHtml(oppTeam || '—')}</span></div>\`;
            document.querySelectorAll('#report-match-details').forEach(el => { el.innerHTML = detailsHtml; });
            // Show confirmation step if opponent has already uploaded/declared
            if (match.status === 'awaiting_confirmation' && match.declared_score_by !== currentUser.id) {
                const myDeclared  = isCreator ? match.declared_score_creator : match.declared_score_joiner;
                const oppDeclared = isCreator ? match.declared_score_joiner  : match.declared_score_creator;
                const cd = document.getElementById('confirm-score-display');
                const cr = document.getElementById('confirm-result-display');
                if (cd) cd.textContent = \`\${myDeclared ?? '?'}  —  \${oppDeclared ?? '?'}\`;
                if (cr) {
                    if (match.declared_winner_id === currentUser.id) { cr.textContent = '🏆 They say YOU won'; cr.style.color = 'var(--neon)'; }
                    else if (match.declared_winner_id) { cr.textContent = '😔 They say they won'; cr.style.color = '#ff6666'; }
                    else { cr.textContent = '🤝 Draw declared'; cr.style.color = '#ffb400'; }
                }
                switchStep('report-result-modal', 'confirm');
                document.getElementById('report-result-modal').classList.add('open');
                return;
            }
            // Default: go straight to screenshot upload (step 2) — Gemini reads the score
            switchStep('report-result-modal', 2);
            document.getElementById('report-result-modal').classList.add('open');
        });
    }
    function openChallengeUploadModal(matchId) { openReportResultModal(matchId); }

    // tickCountdowns replaced by tickAllClocks above
    // ─────────────────────────────────────────────────────────────────────────

    // --- Real-time match status polling (unchanged) ---
    function startMatchStatusPolling(matchId) {
        if (matchStatusPollInterval) {
            clearInterval(matchStatusPollInterval);
        }
        console.log('🔄 Started polling match status for:', matchId);
        matchStatusPollInterval = setInterval(async () => {
            try {
                const res = await fetchWithAuth(\`/friends/match-status/\${matchId}\`, {}, 5000);
                if (!res || !res.ok) return;
                const data = await res.json();
                console.log('📊 Match status:', data.status);
                if (data.status === 'active') {
                    stopMatchStatusPolling();
                    onMatchBecameActive(data);
                } else if (data.status === 'expired' || data.status === 'cancelled') {
                    stopMatchStatusPolling();
                    onMatchExpiredOrCancelled(data);
                }
            } catch (err) {
                console.error('Poll error:', err);
            }
        }, 3000);
    }

    function stopMatchStatusPolling() {
        if (matchStatusPollInterval) {
            clearInterval(matchStatusPollInterval);
            matchStatusPollInterval = null;
            console.log('⏹️  Stopped polling match status');
        }
    }

    function onMatchBecameActive(matchData) {
        if (friendMatchTimer) {
            clearInterval(friendMatchTimer);
            friendMatchTimer = null;
        }
        closeModal('waiting-friend-modal');
        openWarRoom({
            matchId:         currentFriendMatch?.matchId || matchData.matchId,
            matchCode:       currentFriendMatch?.matchCode || matchData.matchCode,
            creatorTeam:     currentTeam,
            creatorUsername: currentUsername,
            joinerTeam:      matchData.joinerTeam    || matchData.joinerUsername || 'Opponent FC',
            joinerUsername:  matchData.joinerUsername || 'Opponent',
            wagerAmount:     matchData.wagerAmount    || currentFriendMatch?.wagerAmount,
            winnerPrize:     matchData.winnerPrize,
            startedAt:       new Date().toISOString(),
            currentUserId:   currentUser.id,
            creatorId:       currentUser.id   // caller is always the creator here
        });
    }

    function onMatchExpiredOrCancelled(matchData) {
        if (friendMatchTimer) {
            clearInterval(friendMatchTimer);
            friendMatchTimer = null;
        }
        closeModal('waiting-friend-modal');
        if (matchData.status === 'expired') {
            showToast('info', '⏰ Match Expired', 'No one joined in time. Your wager has been refunded.', 6000);
        } else {
            showToast('info', '❌ Match Cancelled', 'Your wager has been refunded.', 5000);
        }
        refreshBalance();
        loadMyFriendMatches();
    }

    // --- Room Code Share ---
    function shareRoomCode() {
        const code = document.getElementById('room-code-display').innerText;
        const text = encodeURIComponent(\`Join my match on Vumbua eFootball! Room code: \${code}. Play here: https://vumbua.app\`);
        window.open(\`https://wa.me/?text=\${text}\`, '_blank');
    }

    // --- Profile Modal ---
    function openProfileModal() {
        document.getElementById('profile-username').value = escapeHtml(currentUsername);
        document.getElementById('profile-team').value = escapeHtml(currentTeam);
        document.getElementById('profile-error').style.display = 'none';
        document.getElementById('profile-modal').classList.add('open');
    }

    // --- Logout ---
    document.getElementById('logoutBtn').addEventListener('click', () => {
        console.log('🚪 Logging out user:', currentUser?.id);
        
        // Stop all background processes
        stopBalanceAutoRefresh(); // also removes realtime channel
        stopMatchStatusPolling();
        
        // Clean up realtime connection explicitly
        if (supabaseRealtime && realtimeChannel) {
            console.log('🧹 Cleaning up realtime subscription...');
            supabaseRealtime.removeChannel(realtimeChannel);
            realtimeChannel = null;
        }
        
        // Reset ALL global state
        currentBalance = 0;
        currentUser = null;
        currentUsername = '';
        currentPhone = '';
        currentTeam = '';
        authToken = null;
        currentCheckoutId = null;
        currentFriendMatch = null;
        currentTournamentId = null;
        currentTournamentFee = 0;
        currentTournamentName = '';
        supabaseRealtime = null; // Clear the client too
        
        // Clear localStorage
        sessionStorage.removeItem('supabaseToken');
        sessionStorage.removeItem('supabaseUser');
        
        console.log('✅ Logout complete, redirecting to login...');
        window.location.href = '/login';
    });

    // --- War Room Navigation ─────────────────────────────────────
    function openWarRoom(data) {
        sessionStorage.setItem('warRoomData', JSON.stringify(data));
        window.location.href = '/war-room';
    }

    // --- Initial load ---
    window.onload = () => {
        if (!authToken) { window.location.href = '/login'; return; }
        loadDashboard().then(() => {
            // If returning from War Room with a pending report, open the modal
            const reportId = sessionStorage.getItem('openReportMatchId');
            if (reportId) {
                sessionStorage.removeItem('openReportMatchId');
                sessionStorage.removeItem('warRoomData');
                // Small delay so matches list is rendered first
                setTimeout(() => openReportResultModal(reportId), 600);
            }
        });
    };

    // FIX 7: Clean up ALL polling intervals when the user closes/refreshes the
    // tab. Without this, setInterval callbacks keep firing in the background,
    // and currentCheckoutId becomes permanently orphaned in sessionStorage so
    // that the next page load still tries to poll a stale transaction.
    window.addEventListener('beforeunload', () => {
        if (pollInterval)            { clearInterval(pollInterval);            pollInterval = null; }
        if (friendMatchTimer)        { clearInterval(friendMatchTimer);        friendMatchTimer = null; }
        if (matchStatusPollInterval) { clearInterval(matchStatusPollInterval); matchStatusPollInterval = null; }
        if (balanceRefreshInterval)  { clearInterval(balanceRefreshInterval);  balanceRefreshInterval = null; }
        if (supabaseRealtime && realtimeChannel) {
            supabaseRealtime.removeChannel(realtimeChannel);
        }
    });
</script>
</body>
</html>`;

const HTML_ADMIN = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin | Vumbua eFootball</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #060608; color: #f0f0f0; font-family: 'Outfit', sans-serif; min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .login-box { max-width: 400px; margin: 100px auto; background: #111116; border: 1px solid rgba(255,255,255,0.06); border-radius: 24px; padding: 40px; text-align: center; }
        .login-box h1 { font-family: 'Bebas Neue', sans-serif; font-size: 2.5rem; color: #00ff41; letter-spacing: 2px; margin-bottom: 20px; }
        .login-box input { width: 100%; padding: 14px; background: #1a1a20; border: 1px solid #2a2a30; border-radius: 12px; color: white; font-size: 1rem; margin-bottom: 20px; }
        .login-box button { width: 100%; padding: 14px; background: #00ff41; color: black; border: none; border-radius: 12px; font-weight: 700; font-size: 1rem; cursor: pointer; transition: transform 0.15s, box-shadow 0.15s; }
        .login-box button:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,255,65,0.3); }
        .error { color: #ff4444; margin-top: 10px; display: none; }
        .dashboard { display: none; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; flex-wrap: wrap; gap: 20px; }
        .header h1 { font-family: 'Bebas Neue', sans-serif; font-size: 2.5rem; color: #00ff41; letter-spacing: 2px; }
        .header button { background: #ff4444; color: white; border: none; padding: 10px 20px; border-radius: 20px; font-weight: 600; cursor: pointer; }
        .tabs { display: flex; gap: 10px; margin-bottom: 30px; border-bottom: 1px solid #222; padding-bottom: 10px; }
        .tab { padding: 10px 20px; background: none; border: none; color: #888; font-weight: 600; cursor: pointer; font-size: 1rem; transition: color 0.2s; }
        .tab.active { color: #00ff41; border-bottom: 2px solid #00ff41; }
        .table-container { background: #111116; border: 1px solid #222; border-radius: 16px; overflow-x: auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px 8px; color: #888; font-weight: 600; font-size: 0.85rem; letter-spacing: 1px; text-transform: uppercase; border-bottom: 1px solid #222; }
        td { padding: 16px 8px; border-bottom: 1px solid #1a1a20; }
        tr:last-child td { border-bottom: none; }
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .status-pending { background: rgba(255,180,0,0.1); color: #ffb400; border: 1px solid rgba(255,180,0,0.2); }
        .status-paid { background: rgba(0,255,65,0.1); color: #00ff41; border: 1px solid rgba(0,255,65,0.2); }
        .status-rejected { background: rgba(255,68,68,0.1); color: #ff4444; border: 1px solid rgba(255,68,68,0.2); }
        .status-open { background: rgba(0,255,65,0.1); color: #00ff41; border: 1px solid rgba(0,255,65,0.2); }
        .status-live { background: rgba(255,180,0,0.1); color: #ffb400; border: 1px solid rgba(255,180,0,0.2); }
        .status-closed { background: rgba(255,68,68,0.1); color: #ff4444; border: 1px solid rgba(255,68,68,0.2); }
        .status-disputed { background: rgba(255,68,68,0.2); color: #ff8888; border: 1px solid #ff4444; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn { padding: 6px 12px; border-radius: 8px; font-size: 0.8rem; font-weight: 600; border: none; cursor: pointer; transition: opacity 0.2s; }
        .btn:hover { opacity: 0.8; }
        .btn-green { background: #00ff41; color: black; }
        .btn-red { background: #ff4444; color: white; }
        .btn-blue { background: #0088ff; color: white; }
        .btn-yellow { background: #ffb400; color: black; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; pointer-events: none; transition: opacity 0.25s; }
        .modal-overlay.open { opacity: 1; pointer-events: all; }
        .modal-content { background: #111116; border: 1px solid #222; border-radius: 24px; padding: 30px; width: 90%; max-width: 500px; max-height: 90vh; overflow-y: auto; }
        .modal-content h3 { font-family: 'Bebas Neue', sans-serif; font-size: 1.8rem; margin-bottom: 20px; color: #00ff41; }
        .modal-content input, .modal-content select, .modal-content textarea { width: 100%; padding: 12px; background: #1a1a20; border: 1px solid #2a2a30; border-radius: 10px; color: white; margin-bottom: 20px; }
        .modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .btn-create { background: #00ff41; color: black; padding: 10px 20px; border-radius: 20px; font-weight: 600; border: none; cursor: pointer; }
        /* ── Dispute panel ───────────────────────────────────────────── */
        #dispute-modal .modal-content { max-width: 820px; }
        .dispute-header { display:flex; align-items:center; gap:12px; margin-bottom:14px; }
        .dispute-header h3 { margin-bottom:0; }
        .dispute-badge { background:rgba(255,68,68,0.2); color:#ff8888; border:1px solid #ff4444; border-radius:20px; padding:3px 12px; font-size:0.72rem; font-weight:700; text-transform:uppercase; }
        /* Meta strip */
        .dispute-meta { background:#0d0d10; border:1px solid #1e1e28; border-radius:12px; padding:10px 16px; margin-bottom:12px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px; }
        .dispute-meta .mi label { font-size:0.58rem; color:#555; text-transform:uppercase; letter-spacing:1px; display:block; margin-bottom:2px; }
        .dispute-meta .mi span  { font-size:0.88rem; font-weight:700; }
        .dispute-meta .mi span.green { color:#00ff41; }
        /* Dispute reason banner */
        .dsp-reason-box { background:rgba(255,68,68,0.07); border:1px solid rgba(255,68,68,0.22); border-radius:10px; padding:9px 14px; margin-bottom:12px; font-size:0.8rem; color:#ffaaaa; }
        .dsp-reason-box strong { color:#ff6666; display:block; font-size:0.6rem; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:3px; }
        /* Score comparison bar */
        .score-compare { display:flex; align-items:stretch; background:#0d0d10; border:1px solid #1e1e28; border-radius:14px; overflow:hidden; margin-bottom:12px; }
        .sc-side { flex:1; padding:14px 10px; text-align:center; }
        .sc-side.creator { border-right:1px solid #1e1e28; }
        .sc-role-tag { font-size:0.54rem; font-weight:800; letter-spacing:2px; text-transform:uppercase; margin-bottom:3px; }
        .sc-side.creator .sc-role-tag { color:#4aadff; }
        .sc-side.joiner  .sc-role-tag { color:#ffaa44; }
        .sc-name { font-size:0.82rem; font-weight:700; color:#ccc; margin-bottom:3px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .sc-team { font-size:0.62rem; color:#444; margin-bottom:8px; }
        .sc-score-label { font-size:0.52rem; letter-spacing:1.5px; text-transform:uppercase; color:#333; margin-bottom:1px; }
        .sc-score-big { font-family:'Bebas Neue',sans-serif; font-size:2.8rem; line-height:1; display:block; }
        .sc-score-big.win  { color:#00ff41; text-shadow:0 0 18px rgba(0,255,65,0.35); }
        .sc-score-big.loss { color:#ff4444; text-shadow:0 0 18px rgba(255,68,68,0.3); }
        .sc-score-big.unk  { color:#333; }
        .sc-mid { padding:14px 10px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:4px; min-width:70px; }
        .sc-vs { font-family:'Bebas Neue',sans-serif; font-size:1.3rem; color:#2a2a2a; }
        .sc-verdict { font-size:0.6rem; font-weight:800; letter-spacing:1px; text-transform:uppercase; padding:3px 8px; border-radius:20px; }
        .sc-verdict.agree    { background:rgba(0,255,65,0.1); color:#00ff41; border:1px solid rgba(0,255,65,0.2); }
        .sc-verdict.disagree { background:rgba(255,68,68,0.12); color:#ff6666; border:1px solid rgba(255,68,68,0.25); }
        /* Player detail cards */
        .dispute-players { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:12px; }
        .dp-card { background:#0d0d10; border:1px solid #1e1e28; border-radius:12px; padding:12px; }
        .dp-card.creator { border-top:3px solid #0088ff; }
        .dp-card.joiner  { border-top:3px solid #ff8800; }
        .dp-role { font-size:0.56rem; font-weight:800; text-transform:uppercase; letter-spacing:1.5px; margin-bottom:3px; }
        .dp-card.creator .dp-role { color:#4aadff; }
        .dp-card.joiner  .dp-role { color:#ffaa44; }
        .dp-name { font-size:0.92rem; font-weight:700; margin-bottom:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .dp-team { font-size:0.66rem; color:#555; margin-bottom:10px; }
        /* Score rows inside card */
        .dp-score-row { display:flex; align-items:center; gap:8px; background:#141418; border-radius:8px; padding:7px 10px; margin-bottom:6px; }
        .dp-score-row-label { font-size:0.56rem; color:#444; text-transform:uppercase; letter-spacing:1px; flex:1; line-height:1.3; }
        .dp-score-val { font-family:'Bebas Neue',sans-serif; font-size:1.5rem; line-height:1; }
        .dp-score-val.win  { color:#00ff41; }
        .dp-score-val.loss { color:#ff4444; }
        .dp-score-val.unk  { color:#333; }
        .dp-badge { font-size:0.55rem; padding:2px 7px; border-radius:10px; font-weight:700; flex-shrink:0; }
        .dp-badge.declared { background:rgba(0,136,255,0.15); color:#4aadff; border:1px solid rgba(0,136,255,0.2); }
        .dp-badge.disputed { background:rgba(255,68,68,0.15); color:#ff8888; border:1px solid rgba(255,68,68,0.2); }
        /* Screenshot */
        .dp-ss-label { font-size:0.56rem; color:#444; text-transform:uppercase; letter-spacing:1px; margin-bottom:5px; }
        .dp-img { width:100%; border-radius:8px; max-height:160px; object-fit:cover; border:1px solid #2a2a30; cursor:zoom-in; transition:opacity 0.2s,transform 0.15s; display:block; }
        .dp-img:hover { opacity:0.88; transform:scale(1.01); }
        .dp-open-link { display:block; text-align:center; font-size:0.66rem; color:#4aadff; margin-top:4px; text-decoration:none; }
        .dp-open-link:hover { text-decoration:underline; }
        .dp-noimg { background:#141418; border:1px dashed #222; border-radius:8px; padding:14px; text-align:center; color:#333; font-size:0.75rem; }
        /* Timeline */
        .dsp-timeline { background:#0d0d10; border:1px solid #1e1e28; border-radius:12px; padding:12px 14px; margin-bottom:12px; }
        .dsp-timeline-title { font-size:0.58rem; letter-spacing:2px; text-transform:uppercase; color:#333; margin-bottom:8px; }
        .tl-row { display:flex; align-items:flex-start; gap:10px; margin-bottom:6px; }
        .tl-dot { width:7px; height:7px; border-radius:50%; margin-top:5px; flex-shrink:0; }
        .tl-dot.green  { background:#00ff41; }
        .tl-dot.blue   { background:#0088ff; }
        .tl-dot.red    { background:#ff4444; }
        .tl-dot.yellow { background:#ffb400; }
        .tl-dot.grey   { background:#333; }
        .tl-body { font-size:0.76rem; color:#888; line-height:1.4; flex:1; }
        .tl-body strong { color:#ccc; }
        .tl-time { font-size:0.62rem; color:#333; white-space:nowrap; flex-shrink:0; margin-top:3px; }
        /* Admin notes */
        .dsp-notes-label { font-size:0.6rem; letter-spacing:1.5px; text-transform:uppercase; color:#555; display:block; margin-bottom:5px; }
        .dsp-notes-input { width:100%; background:#0d0d10; border:1px solid #2a2a30; border-radius:10px; color:#ccc; padding:9px 12px; font-family:'Outfit',sans-serif; font-size:0.8rem; resize:vertical; min-height:56px; transition:border-color 0.2s; margin-bottom:12px; }
        .dsp-notes-input:focus { outline:none; border-color:rgba(0,255,65,0.35); }
        /* Verdict buttons */
        .dispute-actions { display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; }
        .da-btn { padding:13px; border-radius:10px; border:none; font-weight:700; font-size:0.82rem; cursor:pointer; transition:filter 0.2s,transform 0.15s; font-family:'Outfit',sans-serif; letter-spacing:0.3px; }
        .da-btn:hover:not(:disabled) { filter:brightness(1.18); transform:translateY(-2px); }
        .da-btn:disabled { opacity:0.35; cursor:not-allowed; transform:none; }
        .da-creator { background:linear-gradient(135deg,#0077dd,#0055aa); color:#fff; }
        .da-joiner  { background:linear-gradient(135deg,#dd6600,#aa4400); color:#fff; }
        .da-refund  { background:#1a1a22; color:#888; border:1px solid #2a2a30; }
        /* ── Evidence Lightbox ───────────────────────────────────── */
        #lightbox {
            position:fixed; inset:0; z-index:3000;
            background:rgba(0,0,0,0.97);
            opacity:0; pointer-events:none;
            transition:opacity 0.2s;
            display:flex; flex-direction:column;
            font-family:'Outfit',sans-serif;
        }
        #lightbox.open { opacity:1; pointer-events:all; }

        /* Top toolbar */
        .lb-toolbar {
            display:flex; align-items:center; gap:8px;
            padding:10px 16px;
            background:rgba(0,0,0,0.6);
            border-bottom:1px solid #1a1a22;
            flex-shrink:0;
            z-index:10;
        }
        .lb-title {
            font-size:0.72rem; font-weight:700;
            letter-spacing:1px; color:#aaa;
            flex:1;
        }
        .lb-mode-btns { display:flex; gap:4px; }
        .lb-mode-btn {
            padding:5px 12px; border-radius:7px;
            border:1px solid #2a2a30;
            background:transparent; color:#666;
            font-size:0.7rem; font-weight:600;
            cursor:pointer; font-family:'Outfit',sans-serif;
            transition:all 0.15s;
        }
        .lb-mode-btn.active { background:#1e1e28; color:#ccc; border-color:#444; }
        .lb-zoom-btns { display:flex; gap:4px; align-items:center; }
        .lb-zoom-btn {
            width:28px; height:28px; border-radius:6px;
            border:1px solid #2a2a30; background:transparent;
            color:#888; font-size:1rem; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:all 0.15s; font-family:monospace;
        }
        .lb-zoom-btn:hover { background:#1e1e28; color:#ccc; }
        .lb-zoom-level { font-size:0.68rem; color:#555; min-width:34px; text-align:center; }
        .lb-close-btn {
            width:32px; height:32px; border-radius:8px;
            border:1px solid #2a2a30; background:transparent;
            color:#888; font-size:1.1rem; cursor:pointer;
            display:flex; align-items:center; justify-content:center;
            transition:all 0.15s;
        }
        .lb-close-btn:hover { background:rgba(255,68,68,0.15); color:#ff6666; border-color:rgba(255,68,68,0.3); }

        /* Main image area */
        .lb-body {
            flex:1; display:flex; overflow:hidden; position:relative;
        }

        /* Single mode */
        .lb-single {
            flex:1; overflow:hidden; display:flex;
            align-items:center; justify-content:center;
            cursor:grab; position:relative;
        }
        .lb-single.grabbing { cursor:grabbing; }
        .lb-single img {
            max-width:none; max-height:none;
            border-radius:8px;
            box-shadow:0 20px 60px rgba(0,0,0,0.8);
            transform-origin:center center;
            transition:transform 0.15s ease;
            user-select:none; pointer-events:none;
            display:block;
        }

        /* Side-by-side compare mode */
        .lb-compare {
            flex:1; display:none; gap:2px;
        }
        .lb-compare.active { display:flex; }
        .lb-compare-pane {
            flex:1; overflow:hidden; display:flex;
            flex-direction:column; position:relative;
        }
        .lb-compare-label {
            font-size:0.6rem; font-weight:800; letter-spacing:2px;
            text-transform:uppercase; padding:6px 12px;
            background:rgba(0,0,0,0.5); flex-shrink:0;
        }
        .lb-compare-label.blue   { color:#4aadff; border-bottom:2px solid #0088ff; }
        .lb-compare-label.orange { color:#ffaa44; border-bottom:2px solid #ff8800; }
        .lb-compare-label.grey   { color:#888; border-bottom:2px solid #333; }
        .lb-compare-img-wrap {
            flex:1; overflow:hidden; display:flex;
            align-items:center; justify-content:center;
            cursor:grab; background:#050507;
        }
        .lb-compare-img-wrap.grabbing { cursor:grabbing; }
        .lb-compare-img-wrap img {
            max-width:100%; max-height:100%; object-fit:contain;
            border-radius:4px; user-select:none; pointer-events:none;
            transform-origin:center center;
        }
        .lb-no-img {
            flex:1; display:flex; align-items:center; justify-content:center;
            color:#2a2a2a; font-size:0.8rem;
        }

        /* Bottom hint bar */
        .lb-hint {
            padding:6px 16px; text-align:center;
            font-size:0.62rem; color:#2a2a2a; letter-spacing:1px;
            flex-shrink:0;
        }


        /* ── Override modal screenshot evidence panel ─────────────── */
        .ovr-evidence { margin-bottom:14px; }
        .ovr-evidence-title { font-size:0.6rem; letter-spacing:2px; text-transform:uppercase; color:#444; margin-bottom:8px; display:flex; align-items:center; gap:6px; }
        .ovr-evidence-title::after { content:''; flex:1; height:1px; background:#1e1e28; }
        .ovr-ss-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
        .ovr-ss-card { background:#0d0d10; border:1px solid #1e1e28; border-radius:10px; overflow:hidden; }
        .ovr-ss-card-label { font-size:0.56rem; font-weight:800; letter-spacing:1.5px; text-transform:uppercase; padding:6px 10px; border-bottom:1px solid #1a1a22; display:flex; align-items:center; justify-content:space-between; }
        .ovr-ss-card-label.blue   { color:#4aadff; }
        .ovr-ss-card-label.orange { color:#ffaa44; }
        .ovr-ss-card-label a { font-size:0.62rem; font-weight:400; color:#4aadff; text-decoration:none; letter-spacing:0; text-transform:none; }
        .ovr-ss-card-label a:hover { text-decoration:underline; }
        .ovr-ss-img-wrap { padding:6px; }
        .ovr-ss-img { width:100%; border-radius:6px; display:block; cursor:zoom-in; max-height:140px; object-fit:cover; transition:opacity 0.2s; }
        .ovr-ss-img:hover { opacity:0.88; }
        .ovr-ss-none { padding:18px 8px; text-align:center; color:#333; font-size:0.72rem; }
        .ovr-ss-tag { font-size:0.58rem; color:#555; padding:4px 10px 6px; }
        /* ── Admin Override / Force Winner modal ─────────────────── */
        #override-modal .modal-content { max-width: 500px; }
        .override-match-summary { background:#0d0d10; border:1px solid #1e1e28; border-radius:12px; padding:12px 16px; margin-bottom:14px; }
        .override-match-summary .oms-row { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; font-size:0.82rem; }
        .override-match-summary .oms-row:last-child { margin-bottom:0; }
        .oms-label { color:#555; font-size:0.62rem; text-transform:uppercase; letter-spacing:1px; }
        .oms-val   { font-weight:700; color:#ccc; }
        .oms-val.green { color:#00ff41; }
        .override-warn { background:rgba(255,180,0,0.07); border:1px solid rgba(255,180,0,0.25); border-radius:10px; padding:9px 14px; margin-bottom:14px; font-size:0.78rem; color:#ffcc66; }
        .override-warn strong { color:#ffb400; display:block; font-size:0.6rem; letter-spacing:1.5px; text-transform:uppercase; margin-bottom:3px; }
        .override-player-btns { display:flex; flex-direction:column; gap:8px; margin-bottom:14px; }
        .ovr-player-btn { display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:11px; border:1px solid #2a2a30; background:#0d0d10; cursor:pointer; transition:border-color 0.2s, background 0.2s; text-align:left; font-family:'Outfit',sans-serif; }
        .ovr-player-btn:hover { border-color:#555; background:#141418; }
        .ovr-player-btn.selected.blue  { border-color:#0088ff; background:rgba(0,136,255,0.1); }
        .ovr-player-btn.selected.orange{ border-color:#ff8800; background:rgba(255,136,0,0.1); }
        .ovr-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
        .ovr-dot.blue   { background:#0088ff; }
        .ovr-dot.orange { background:#ff8800; }
        .ovr-player-info { flex:1; }
        .ovr-player-name { font-size:0.88rem; font-weight:700; color:#ccc; }
        .ovr-player-team { font-size:0.68rem; color:#555; margin-top:2px; }
        .ovr-player-role { font-size:0.58rem; font-weight:700; letter-spacing:1.5px; text-transform:uppercase; }
        .ovr-player-role.blue   { color:#4aadff; }
        .ovr-player-role.orange { color:#ffaa44; }
        .ovr-check { font-size:1.1rem; margin-left:auto; opacity:0; transition:opacity 0.2s; }
        .ovr-player-btn.selected .ovr-check { opacity:1; }
        .ovr-draw-btn { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:11px; border:1px dashed #2a2a30; background:transparent; cursor:pointer; font-family:'Outfit',sans-serif; color:#888; font-size:0.82rem; transition:border-color 0.2s, color 0.2s; }
        .ovr-draw-btn:hover { border-color:#555; color:#aaa; }
        .ovr-draw-btn.selected { border-color:#ffb400; color:#ffb400; background:rgba(255,180,0,0.06); }
        .override-notes-label { font-size:0.6rem; letter-spacing:1.5px; text-transform:uppercase; color:#555; display:block; margin-bottom:5px; }
        .override-notes-input { width:100%; background:#0d0d10; border:1px solid #2a2a30; border-radius:10px; color:#ccc; padding:9px 12px; font-family:'Outfit',sans-serif; font-size:0.8rem; resize:vertical; min-height:52px; transition:border-color 0.2s; margin-bottom:14px; }
        .override-notes-input:focus { outline:none; border-color:rgba(255,180,0,0.4); }
        .override-submit-btn { width:100%; padding:13px; border-radius:11px; border:none; background:linear-gradient(135deg,#cc8800,#aa6600); color:#fff; font-weight:800; font-size:0.88rem; font-family:'Outfit',sans-serif; cursor:pointer; transition:filter 0.2s, transform 0.15s; letter-spacing:0.3px; }
        .override-submit-btn:hover:not(:disabled) { filter:brightness(1.15); transform:translateY(-1px); }
        .override-submit-btn:disabled { opacity:0.35; cursor:not-allowed; transform:none; }
        .btn-orange { background: #cc7700; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Admin Login -->
        <div id="login-section" class="login-box">
            <h1>VUMBUA ADMIN</h1>
            <input type="password" id="admin-key" placeholder="Enter Admin Key">
            <button onclick="login()">Access Dashboard</button>
            <div id="login-error" class="error">Invalid key</div>
        </div>

        <!-- Dashboard -->
        <div id="dashboard" class="dashboard">
            <div class="header">
                <h1>Admin Dashboard</h1>
                <button onclick="logout()">Logout</button>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" data-tab="withdrawals">Withdrawals</button>
                <button class="tab" data-tab="tournaments">Tournaments</button>
                <button class="tab" data-tab="friend-matches">Friend Matches</button>
                <button class="tab" data-tab="analytics">📊 Analytics</button>
            </div>

            <!-- Withdrawals Tab -->
            <div id="withdrawals-tab" class="tab-pane active">
                <div class="top-bar" style="margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;">
                    <div style="display:flex;gap:10px;align-items:center;">
                        <select id="wd-status-filter" style="background:#1a1a20;border:1px solid #2a2a30;color:#fff;padding:8px 14px;border-radius:10px;font-size:0.85rem;" onchange="loadWithdrawals()">
                            <option value="pending">Pending</option>
                            <option value="paid">Paid</option>
                            <option value="rejected">Rejected</option>
                        </select>
                        <button onclick="loadWithdrawals()" class="btn btn-blue" style="padding:8px 16px;">&#8635; Refresh</button>
                    </div>
                    <div id="wd-summary" style="font-size:0.85rem;color:#888;"></div>
                </div>
                <div id="withdrawal-cards" style="display:grid;gap:14px;"></div>
                <table id="withdrawals-table" style="display:none"><thead><tr><th>ID</th><th>User</th><th>Amount</th><th>Phone</th><th>Name</th><th>Status</th><th>Actions</th></tr></thead><tbody></tbody></table>
            </div>

            <!-- Tournaments Tab -->
            <div id="tournaments-tab" class="tab-pane" style="display: none;">
                <div class="top-bar">
                    <h2>Tournaments</h2>
                    <button class="btn-create" onclick="openTournamentModal()">+ Create Tournament</button>
                </div>
                <div class="table-container">
                    <table id="tournaments-table">
                        <thead>
                            <tr><th>Name</th><th>Entry Fee</th><th>Start Time</th><th>Max Players</th><th>Room Code</th><th>Status</th><th>Actions</th></tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>

            <!-- Friend Matches Tab -->
            <div id="friend-matches-tab" class="tab-pane" style="display: none;">
                <div class="top-bar">
                    <h2>Friend Matches</h2>
                    <div style="display:flex;gap:10px;align-items:center;">
                        <select id="fm-status-filter" style="background:#1a1a20;color:white;border:1px solid #2a2a30;border-radius:8px;padding:6px 12px;">
                            <option value="all">All</option>
                            <option value="pending">Pending</option>
                            <option value="active">Active</option>
                            <option value="awaiting_confirmation">Awaiting Confirm</option>
                            <option value="disputed">Disputed</option>
                            <option value="completed">Completed</option>
                            <option value="cancelled">Cancelled</option>
                            <option value="expired">Expired</option>
                        </select>
                        <button onclick="loadFriendMatches()" class="btn btn-blue" style="padding:6px 14px;">🔄 Refresh</button>
                    </div>
                </div>
                <div id="fm-loading" style="text-align:center;padding:14px;color:#888;display:none;">⏳ Loading...</div>
                <div class="table-container">
                    <table id="friend-matches-table">
                        <thead>
                            <tr><th>Code</th><th>Creator</th><th>Joiner</th><th>Score</th><th>Wager</th><th>Prize</th><th>Status</th><th>Date</th><th>Actions</th></tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

            <!-- Analytics Tab -->
            <div id="analytics-tab" class="tab-pane" style="display:none;">
                <div id="analytics-content">
                    <div style="text-align:center;padding:60px 20px;color:#555;">
                        <div style="font-size:2rem;margin-bottom:12px;">📊</div>
                        <div>Loading analytics...</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Tournament Modal -->
    <div id="tournament-modal" class="modal-overlay" onclick="if(event.target === this) closeModal('tournament-modal')">
        <div class="modal-content">
            <h3 id="tournament-modal-title">Create Tournament</h3>
            <input type="text" id="tournament-name" placeholder="Tournament Name">
            <input type="number" id="tournament-fee" placeholder="Entry Fee (KES)">
            <input type="datetime-local" id="tournament-start" placeholder="Start Time">
            <input type="number" id="tournament-max" placeholder="Max Players">
            <input type="text" id="tournament-room" placeholder="Room Code (optional)">
            <select id="tournament-status">
                <option value="open">Open</option>
                <option value="live">Live</option>
                <option value="closed">Closed</option>
            </select>
            <div class="modal-actions">
                <button class="btn btn-green" id="tournament-save" onclick="saveTournament()">Save</button>
                <button class="btn btn-red" onclick="closeModal('tournament-modal')">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Delete Tournament Modal -->
    <div id="delete-modal" class="modal-overlay" onclick="if(event.target === this) closeModal('delete-modal')">
        <div class="modal-content">
            <h3>Confirm Delete</h3>
            <p>Are you sure you want to delete this tournament?</p>
            <div class="modal-actions">
                <button class="btn btn-red" onclick="confirmDelete()">Delete</button>
                <button class="btn" onclick="closeModal('delete-modal')">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Screenshot Lightbox -->
    <!-- ══════════════════════════════════════════════════════════
         EVIDENCE LIGHTBOX — zoom, pan, side-by-side compare
    ══════════════════════════════════════════════════════════ -->
    <div id="lightbox">
        <!-- Toolbar -->
        <div class="lb-toolbar">
            <div class="lb-title" id="lb-title">Screenshot Evidence</div>
            <div class="lb-mode-btns">
                <button class="lb-mode-btn active" id="lb-btn-single" onclick="lbSetMode('single')">Single</button>
                <button class="lb-mode-btn" id="lb-btn-compare" onclick="lbSetMode('compare')">Compare ⇔</button>
            </div>
            <div class="lb-zoom-btns">
                <button class="lb-zoom-btn" onclick="lbZoom(-0.25)" title="Zoom out">−</button>
                <div class="lb-zoom-level" id="lb-zoom-label">100%</div>
                <button class="lb-zoom-btn" onclick="lbZoom(+0.25)" title="Zoom in">+</button>
                <button class="lb-zoom-btn" onclick="lbResetZoom()" title="Reset zoom" style="font-size:0.7rem;width:auto;padding:0 7px;">Reset</button>
            </div>
            <button class="lb-close-btn" onclick="lbClose()" title="Close (Esc)">✕</button>
        </div>

        <!-- Image area -->
        <div class="lb-body">
            <!-- Single view -->
            <div class="lb-single" id="lb-single">
                <img id="lightbox-img" src="" alt="Screenshot evidence" draggable="false">
            </div>

            <!-- Side-by-side compare -->
            <div class="lb-compare" id="lb-compare">
                <div class="lb-compare-pane">
                    <div class="lb-compare-label blue" id="lb-cmp-left-label">🔵 Creator</div>
                    <div class="lb-compare-img-wrap" id="lb-cmp-left-wrap">
                        <div class="lb-no-img">No screenshot</div>
                    </div>
                </div>
                <div style="width:2px;background:#111;flex-shrink:0;"></div>
                <div class="lb-compare-pane">
                    <div class="lb-compare-label orange" id="lb-cmp-right-label">🟠 Joiner</div>
                    <div class="lb-compare-img-wrap" id="lb-cmp-right-wrap">
                        <div class="lb-no-img">No screenshot</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="lb-hint">Scroll to zoom · Drag to pan · ESC to close · C to compare</div>
    </div>

    <!-- Dispute Resolution Modal -->
    <!-- ══════════════════════════════════════════════════════════
         ADMIN FORCE-WINNER OVERRIDE MODAL
         Works on any active / stuck / disputed match
    ══════════════════════════════════════════════════════════ -->
    <div id="override-modal" class="modal-overlay" onclick="if(event.target===this)closeModal('override-modal')">
        <div class="modal-content">
            <div class="dispute-header">
                <h3>⚡ FORCE WINNER</h3>
                <span class="dispute-badge" style="background:rgba(255,180,0,0.15);color:#ffcc44;border-color:rgba(255,180,0,0.4);">Admin Override</span>
            </div>

            <!-- Match summary -->
            <div class="override-match-summary">
                <div class="oms-row"><span class="oms-label">Match</span><span class="oms-val" id="ovr-code">—</span></div>
                <div class="oms-row"><span class="oms-label">Status</span><span class="oms-val" id="ovr-status">—</span></div>
                <div class="oms-row"><span class="oms-label">Declared Score</span><span class="oms-val" id="ovr-score">—</span></div>
                <div class="oms-row"><span class="oms-label">Prize Pot</span><span class="oms-val green">KES <span id="ovr-prize">—</span></span></div>
            </div>

            <div class="override-warn">
                <strong>⚠️ Admin Override</strong>
                This will immediately settle the match and credit the winner's wallet.
                The action is logged in the audit trail and cannot be undone.
            </div>

            <!-- Screenshot evidence -->
            <div class="ovr-evidence" id="ovr-evidence-section">
                <div class="ovr-evidence-title">📸 Screenshot Evidence
                    <button onclick="lbOpenFromOverride()" style="margin-left:auto;padding:3px 10px;border-radius:6px;border:1px solid #2a2a30;background:#0d0d10;color:#4aadff;font-size:0.65rem;cursor:pointer;font-family:'Outfit',sans-serif;" title="Open full evidence viewer">⛶ Compare</button>
                </div>
                <div class="ovr-ss-grid">
                    <div class="ovr-ss-card">
                        <div class="ovr-ss-card-label blue">
                            🔵 Creator <a id="ovr-ss-c-link" href="#" target="_blank" style="display:none">↗ Full</a>
                        </div>
                        <div class="ovr-ss-img-wrap" id="ovr-ss-c-wrap">
                            <div class="ovr-ss-none">No screenshot</div>
                        </div>
                        <div class="ovr-ss-tag" id="ovr-ss-c-tag"></div>
                    </div>
                    <div class="ovr-ss-card">
                        <div class="ovr-ss-card-label orange">
                            🟠 Joiner <a id="ovr-ss-j-link" href="#" target="_blank" style="display:none">↗ Full</a>
                        </div>
                        <div class="ovr-ss-img-wrap" id="ovr-ss-j-wrap">
                            <div class="ovr-ss-none">No screenshot</div>
                        </div>
                        <div class="ovr-ss-tag" id="ovr-ss-j-tag"></div>
                    </div>
                </div>
            </div>

            <!-- Player selection -->
            <div class="override-player-btns" id="ovr-player-btns">
                <button class="ovr-player-btn" id="ovr-btn-creator" onclick="selectOverrideWinner('creator')">
                    <div class="ovr-dot blue"></div>
                    <div class="ovr-player-info">
                        <div class="ovr-player-role blue">🔵 Creator</div>
                        <div class="ovr-player-name" id="ovr-cname">—</div>
                        <div class="ovr-player-team" id="ovr-cteam">—</div>
                    </div>
                    <span class="ovr-check">✅</span>
                </button>
                <button class="ovr-player-btn" id="ovr-btn-joiner" onclick="selectOverrideWinner('joiner')">
                    <div class="ovr-dot orange"></div>
                    <div class="ovr-player-info">
                        <div class="ovr-player-role orange">🟠 Joiner</div>
                        <div class="ovr-player-name" id="ovr-jname">—</div>
                        <div class="ovr-player-team" id="ovr-jteam">—</div>
                    </div>
                    <span class="ovr-check">✅</span>
                </button>
                <button class="ovr-draw-btn" id="ovr-btn-draw" onclick="selectOverrideWinner('draw')">
                    ↩ <span>Refund Both (Draw / No Contest)</span>
                    <span class="ovr-check" style="margin-left:auto;">✅</span>
                </button>
            </div>

            <!-- Admin notes -->
            <label class="override-notes-label">Reason / Evidence (required)</label>
            <textarea class="override-notes-input" id="ovr-notes" placeholder="e.g. Player A's screenshot clearly shows final score 3–1. Confirmed via video evidence shared in support chat."></textarea>

            <button class="override-submit-btn" id="ovr-submit-btn" onclick="submitOverride()" disabled>
                Select a winner above to continue
            </button>
            <div style="text-align:center;margin-top:10px;">
                <button class="btn" onclick="closeModal('override-modal')" style="background:#1a1a22;color:#555;padding:8px 20px;border-radius:9px;">Cancel</button>
            </div>
        </div>
    </div>

    <div id="dispute-modal" class="modal-overlay" onclick="if(event.target===this)closeModal('dispute-modal')">
        <div class="modal-content">
            <div class="dispute-header">
                <h3>RESOLVE DISPUTE</h3>
                <span class="dispute-badge" id="dsp-status-badge">⚠️ Disputed</span>
            </div>
            <div id="dsp-loading" style="text-align:center;padding:20px;color:#888;">Loading...</div>
            <div id="dsp-body" style="display:none">

                <!-- ① Match meta strip -->
                <div class="dispute-meta">
                    <div class="mi"><label>Match Code</label><span id="dsp-code">—</span></div>
                    <div class="mi"><label>Wager Each</label><span>KES <span id="dsp-wager">—</span></span></div>
                    <div class="mi"><label>Winner Prize</label><span class="green">KES <span id="dsp-prize">—</span></span></div>
                    <div class="mi"><label>Settlement</label><span id="dsp-method">—</span></div>
                    <div class="mi"><label>Disputed At</label><span id="dsp-time">—</span></div>
                </div>

                <!-- ② Dispute reason -->
                <div class="dsp-reason-box" id="dsp-reason-box">
                    <strong>Dispute Reason</strong>
                    <span id="dsp-reason-text">—</span>
                </div>

                <!-- ③ Score comparison — the key decision block -->
                <div class="score-compare">
                    <div class="sc-side creator">
                        <div class="sc-role-tag">🔵 Creator</div>
                        <div class="sc-name" id="sc-cname">—</div>
                        <div class="sc-team" id="sc-cteam">—</div>
                        <div class="sc-score-label" id="sc-clabel">Declared Score</div>
                        <span class="sc-score-big unk" id="sc-cscore">?</span>
                    </div>
                    <div class="sc-mid">
                        <div class="sc-vs">VS</div>
                        <div class="sc-verdict" id="sc-verdict">—</div>
                    </div>
                    <div class="sc-side joiner">
                        <div class="sc-role-tag">🟠 Joiner</div>
                        <div class="sc-name" id="sc-jname">—</div>
                        <div class="sc-team" id="sc-jteam">—</div>
                        <div class="sc-score-label" id="sc-jlabel">Declared Score</div>
                        <span class="sc-score-big unk" id="sc-jscore">?</span>
                    </div>
                </div>

                <!-- ④ Player detail cards with scores + screenshots -->
                <div class="dispute-players">
                    <!-- Creator card -->
                    <div class="dp-card creator">
                        <div class="dp-role">🔵 Creator</div>
                        <div class="dp-name" id="dsp-cname">—</div>
                        <div class="dp-team" id="dsp-cteam">—</div>
                        <div class="dp-score-row">
                            <div class="dp-score-row-label">Declared<br>Score</div>
                            <span class="dp-score-val unk" id="dsp-cscore">?</span>
                            <span class="dp-badge declared" id="dsp-c-declared-badge" style="display:none">Declared</span>
                        </div>
                        <div class="dp-ss-label">Screenshot</div>
                        <div id="dsp-cimg"><div class="dp-noimg">No screenshot provided</div></div>
                        <a id="dsp-cimg-link" href="#" target="_blank" class="dp-open-link" style="display:none">↗ Open full size</a>
                    </div>
                    <!-- Joiner card -->
                    <div class="dp-card joiner">
                        <div class="dp-role">🟠 Joiner</div>
                        <div class="dp-name" id="dsp-jname">—</div>
                        <div class="dp-team" id="dsp-jteam">—</div>
                        <div class="dp-score-row">
                            <div class="dp-score-row-label">Claimed<br>Score</div>
                            <span class="dp-score-val unk" id="dsp-jscore">?</span>
                            <span class="dp-badge disputed" id="dsp-j-disputed-badge" style="display:none">Disputed</span>
                        </div>
                        <div class="dp-ss-label">Screenshot</div>
                        <div id="dsp-jimg"><div class="dp-noimg">No screenshot provided</div></div>
                        <a id="dsp-jimg-link" href="#" target="_blank" class="dp-open-link" style="display:none">↗ Open full size</a>
                    </div>
                </div>

                <!-- ⑤ Timeline -->
                <div class="dsp-timeline">
                    <div class="dsp-timeline-title">📋 Match Timeline</div>
                    <div id="dsp-timeline-rows"></div>
                </div>

                <!-- ⑥ Admin notes -->
                <label class="dsp-notes-label">Admin Notes (saved with resolution)</label>
                <textarea class="dsp-notes-input" id="dsp-admin-notes" placeholder="e.g. Screenshot A clearly shows 2-1. Creator's claim is correct."></textarea>

                <!-- ⑦ Verdict buttons -->
                <div class="dispute-actions">
                    <button class="da-btn da-creator" id="dsp-btn-c" onclick="resolveDispute('creator')">🔵 <span id="dsp-btn-c-label">Creator</span> Wins</button>
                    <button class="da-btn da-refund"  onclick="resolveDispute('draw')">↩ Refund Both</button>
                    <button class="da-btn da-joiner"  id="dsp-btn-j" onclick="resolveDispute('joiner')">🟠 <span id="dsp-btn-j-label">Joiner</span> Wins</button>
                </div>
                <div style="text-align:center;margin-top:10px;">
                    <button class="btn" onclick="closeModal('dispute-modal')" style="background:#1a1a22;color:#555;padding:8px 20px;border-radius:9px;">Cancel</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Paid / Reject Modals -->
    <div id="paid-modal" class="modal-overlay" onclick="if(event.target === this) closeModal('paid-modal')">
        <div class="modal-content">
            <h3>Mark as Paid</h3>
            <input type="text" id="mpesa-code" placeholder="M-PESA Transaction Code">
            <div class="modal-actions">
                <button class="btn btn-green" onclick="submitPaid()">Confirm</button>
                <button class="btn btn-red" onclick="closeModal('paid-modal')">Cancel</button>
            </div>
        </div>
    </div>
    <div id="reject-modal" class="modal-overlay" onclick="if(event.target === this) closeModal('reject-modal')">
        <div class="modal-content">
            <h3>Reject Withdrawal</h3>
            <textarea id="reject-reason" placeholder="Reason for rejection (optional)" rows="3"></textarea>
            <div class="modal-actions">
                <button class="btn btn-red" onclick="submitReject()">Reject</button>
                <button class="btn" onclick="closeModal('reject-modal')">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        // --- Escape function for XSS prevention ---
        function escapeHtml(unsafe) {
            if (unsafe === null || unsafe === undefined) return '';
            return String(unsafe)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // --- Helper to safely create elements with text content ---
        function createElementSafe(tag, attributes = {}, textContent = '') {
            const el = document.createElement(tag);
            Object.entries(attributes).forEach(([key, value]) => el.setAttribute(key, value));
            if (textContent) el.textContent = escapeHtml(textContent);
            return el;
        }

        // --- State ---
        let adminKey = localStorage.getItem('adminKey');
        let currentWithdrawalId = null;
        let currentTournamentId = null;
        let currentFriendMatchId = null;

        // Check login
        if (adminKey) {
            document.getElementById('login-section').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            loadWithdrawals();
            loadFriendMatches();
        }

        // --- Tab switching ---
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                const tabName = tab.dataset.tab;
                document.querySelectorAll('.tab-pane').forEach(pane => pane.style.display = 'none');
                document.getElementById(tabName + '-tab').style.display = 'block';
                if (tabName === 'withdrawals') loadWithdrawals();
                else if (tabName === 'tournaments') loadTournaments();
                else if (tabName === 'analytics') loadAnalytics();
                else loadFriendMatches();
            });
        });

        // --- Login ---
        function login() {
            const key = document.getElementById('admin-key').value;
            if (!key) return;
            adminKey = key;
            localStorage.setItem('adminKey', key);
            // Test the key by fetching withdrawals
            fetchWithdrawals('pending').then(data => {
                if (data.error) throw new Error(data.error);
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                loadWithdrawals();
            }).catch(() => {
                document.getElementById('login-error').style.display = 'block';
                localStorage.removeItem('adminKey');
                adminKey = null;
            });
        }

        function logout() {
            localStorage.removeItem('adminKey');
            adminKey = null;
            document.getElementById('login-section').style.display = 'block';
            document.getElementById('dashboard').style.display = 'none';
        }

        // Auto-detect: Use localhost for local dev, Koyeb URL for production
        const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
        const API = isLocal 
            ? 'http://localhost:3000' 
            : '/api';
        console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
        console.log('🔍 API URL:', API);

        async function adminFetch(url, options = {}) {
            const headers = {
                'Content-Type': 'application/json',
                'x-admin-key': adminKey,
                ...options.headers
            };
            const fullUrl = url.startsWith('http') ? url : \`\${API}\${url}\`;
            const res = await fetch(fullUrl, { ...options, headers });
            if (res.status === 403) {
                alert('Session expired');
                logout();
                return null;
            }
            return res;
        }

        // ========== WITHDRAWALS ==========
        async function fetchWithdrawals(status = 'pending') {
            const res = await adminFetch(\`/admin/withdrawals?status=\${status}\`);
            return res ? await res.json() : [];
        }

        async function loadWithdrawals() {
            const status = document.getElementById('wd-status-filter')?.value || 'pending';
            const data = await fetchWithdrawals(status);
            if (data) renderWithdrawals(data, status);
        }

        function renderWithdrawals(withdrawals, status = 'pending') {
            const container = document.getElementById('withdrawal-cards');
            container.innerHTML = '';
            if (!withdrawals || withdrawals.length === 0) {
                container.innerHTML = '<div style="text-align:center;padding:40px;color:#555;background:#111116;border:1px solid #1a1a20;border-radius:16px;"><div style="font-size:2rem;margin-bottom:8px;">📭</div><div>No ' + status + ' withdrawals</div></div>';
                document.getElementById('wd-summary').textContent = '';
                return;
            }
            const total = withdrawals.reduce((s, w) => s + parseFloat(w.amount), 0);
            document.getElementById('wd-summary').textContent = withdrawals.length + ' request' + (withdrawals.length !== 1 ? 's' : '') + ' · Total: KES ' + total.toLocaleString();
            withdrawals.forEach(w => {
                const card = document.createElement('div');
                card.style.cssText = 'background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:20px;display:grid;grid-template-columns:1fr auto;gap:16px;align-items:center;';
                const info = document.createElement('div');
                const topRow = document.createElement('div');
                topRow.style.cssText = 'display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;';
                const nameEl = document.createElement('span');
                nameEl.style.cssText = 'font-family:"Bebas Neue",sans-serif;font-size:1.4rem;letter-spacing:2px;color:#f0f0f0;';
                nameEl.textContent = w.name || 'Unknown';
                const amountEl = document.createElement('span');
                amountEl.style.cssText = 'font-family:"Bebas Neue",sans-serif;font-size:1.6rem;color:#00ff41;letter-spacing:1px;';
                amountEl.textContent = 'KES ' + parseFloat(w.amount).toLocaleString();
                topRow.appendChild(nameEl);
                topRow.appendChild(amountEl);
                info.appendChild(topRow);
                const phoneRow = document.createElement('div');
                phoneRow.style.cssText = 'display:flex;align-items:center;gap:16px;flex-wrap:wrap;';
                const phoneCopy = document.createElement('span');
                phoneCopy.style.cssText = 'font-size:1.1rem;font-weight:700;color:#fff;background:#1a1a20;padding:6px 14px;border-radius:8px;letter-spacing:1px;cursor:pointer;';
                phoneCopy.textContent = w.phone;
                phoneCopy.title = 'Click to copy';
                phoneCopy.addEventListener('click', () => {
                    navigator.clipboard.writeText(w.phone);
                    phoneCopy.style.background = 'rgba(0,255,65,0.2)';
                    setTimeout(() => phoneCopy.style.background = '#1a1a20', 1000);
                });
                phoneRow.appendChild(phoneCopy);
                const timeEl = document.createElement('span');
                timeEl.style.cssText = 'font-size:0.75rem;color:#555;';
                timeEl.textContent = new Date(w.created_at).toLocaleString('en-KE');
                phoneRow.appendChild(timeEl);
                info.appendChild(phoneRow);
                card.appendChild(info);
                const actions = document.createElement('div');
                actions.style.cssText = 'display:flex;flex-direction:column;gap:8px;align-items:flex-end;';
                if (status === 'pending') {
                    const waBtn = document.createElement('a');
                    const msg = encodeURIComponent('Vumbua withdrawal: KES ' + w.amount + ' to ' + w.phone + ' for ' + w.name);
                    waBtn.href = 'https://wa.me/?text=' + msg;
                    waBtn.target = '_blank';
                    waBtn.style.cssText = 'background:#25d366;color:#000;padding:8px 16px;border-radius:10px;font-weight:700;font-size:0.8rem;text-decoration:none;text-align:center;';
                    waBtn.textContent = '📲 WhatsApp Note';
                    actions.appendChild(waBtn);
                    const paidBtn = document.createElement('button');
                    paidBtn.className = 'btn btn-green';
                    paidBtn.style.cssText = 'padding:8px 20px;font-size:0.85rem;';
                    paidBtn.textContent = '✅ Mark Paid';
                    paidBtn.addEventListener('click', () => openPaidModal(w.id));
                    actions.appendChild(paidBtn);
                    const rejectBtn = document.createElement('button');
                    rejectBtn.className = 'btn btn-red';
                    rejectBtn.style.cssText = 'padding:8px 20px;font-size:0.85rem;';
                    rejectBtn.textContent = '✗ Reject';
                    rejectBtn.addEventListener('click', () => openRejectModal(w.id));
                    actions.appendChild(rejectBtn);
                } else {
                    const statusBadge = document.createElement('span');
                    statusBadge.className = 'status-badge status-' + status;
                    statusBadge.textContent = status;
                    actions.appendChild(statusBadge);
                    if (w.mpesa_code) {
                        const codeEl = document.createElement('div');
                        codeEl.style.cssText = 'font-size:0.75rem;color:#555;';
                        codeEl.textContent = 'Code: ' + w.mpesa_code;
                        actions.appendChild(codeEl);
                    }
                }
                card.appendChild(actions);
                container.appendChild(card);
            });
        }

        function openPaidModal(id) { currentWithdrawalId = id; document.getElementById('mpesa-code').value = ''; document.getElementById('paid-modal').classList.add('open'); }
        async function submitPaid() {
            const mpesaCode = document.getElementById('mpesa-code').value.trim();
            if (!mpesaCode) return alert('Enter M-PESA code');
            const res = await adminFetch(\`/admin/withdrawals/\${currentWithdrawalId}/paid\`, { method: 'PATCH', body: JSON.stringify({ mpesaCode }) });
            if (res && res.ok) { closeModal('paid-modal'); loadWithdrawals(); } else alert('Failed');
        }
        function openRejectModal(id) { currentWithdrawalId = id; document.getElementById('reject-reason').value = ''; document.getElementById('reject-modal').classList.add('open'); }
        async function submitReject() {
            const reason = document.getElementById('reject-reason').value.trim();
            const res = await adminFetch(\`/admin/withdrawals/\${currentWithdrawalId}/reject\`, { method: 'PATCH', body: JSON.stringify({ reason }) });
            if (res && res.ok) { closeModal('reject-modal'); loadWithdrawals(); } else alert('Failed');
        }

        // ========== TOURNAMENTS ==========
        async function loadTournaments() {
            const res = await adminFetch('/admin/tournaments');
            if (!res) return;
            const data = await res.json();
            renderTournaments(data);
        }

        function renderTournaments(tournaments) {
            const tbody = document.querySelector('#tournaments-table tbody');
            tbody.innerHTML = '';
            if (!tournaments || tournaments.length === 0) {
                const row = document.createElement('tr');
                const td = createElementSafe('td', { colspan: '7', style: 'text-align:center; color:#888;' }, 'No tournaments');
                row.appendChild(td);
                tbody.appendChild(row);
                return;
            }
            tournaments.forEach(t => {
                const row = document.createElement('tr');
                row.appendChild(createElementSafe('td', {}, t.name));
                row.appendChild(createElementSafe('td', {}, \`KES \${t.entry_fee}\`));
                const start = new Date(t.start_time).toLocaleString();
                row.appendChild(createElementSafe('td', {}, start));
                row.appendChild(createElementSafe('td', {}, t.max_players));
                row.appendChild(createElementSafe('td', {}, t.room_code || '—'));
                const statusTd = document.createElement('td');
                const statusClass = t.status === 'open' ? 'status-open' : t.status === 'live' ? 'status-live' : 'status-closed';
                const badge = createElementSafe('span', { class: \`status-badge \${statusClass}\` }, t.status);
                statusTd.appendChild(badge);
                row.appendChild(statusTd);
                const actionsTd = document.createElement('td');
                actionsTd.className = 'actions';
                const editBtn = createElementSafe('button', { class: 'btn btn-yellow' }, 'Edit');
                editBtn.addEventListener('click', () => editTournament(t.id));
                actionsTd.appendChild(editBtn);
                const deleteBtn = createElementSafe('button', { class: 'btn btn-red' }, 'Delete');
                deleteBtn.addEventListener('click', () => openDeleteModal(t.id));
                actionsTd.appendChild(deleteBtn);
                row.appendChild(actionsTd);
                tbody.appendChild(row);
            });
        }

        function openTournamentModal() {
            currentTournamentId = null;
            document.getElementById('tournament-modal-title').innerText = 'Create Tournament';
            document.getElementById('tournament-name').value = '';
            document.getElementById('tournament-fee').value = '';
            document.getElementById('tournament-start').value = '';
            document.getElementById('tournament-max').value = '';
            document.getElementById('tournament-room').value = '';
            document.getElementById('tournament-status').value = 'open';
            document.getElementById('tournament-modal').classList.add('open');
        }

        async function editTournament(id) {
            currentTournamentId = id;
            const res = await adminFetch(\`/admin/tournaments/\${id}\`);
            if (!res) return;
            const t = await res.json();
            document.getElementById('tournament-modal-title').innerText = 'Edit Tournament';
            document.getElementById('tournament-name').value = t.name;
            document.getElementById('tournament-fee').value = t.entry_fee;
            const start = new Date(t.start_time);
            const year = start.getFullYear();
            const month = String(start.getMonth() + 1).padStart(2, '0');
            const day = String(start.getDate()).padStart(2, '0');
            const hours = String(start.getHours()).padStart(2, '0');
            const mins = String(start.getMinutes()).padStart(2, '0');
            document.getElementById('tournament-start').value = \`\${year}-\${month}-\${day}T\${hours}:\${mins}\`;
            document.getElementById('tournament-max').value = t.max_players;
            document.getElementById('tournament-room').value = t.room_code || '';
            document.getElementById('tournament-status').value = t.status;
            document.getElementById('tournament-modal').classList.add('open');
        }

        async function saveTournament() {
            const name = document.getElementById('tournament-name').value.trim();
            const fee = parseFloat(document.getElementById('tournament-fee').value);
            const start = document.getElementById('tournament-start').value;
            const max = parseInt(document.getElementById('tournament-max').value);
            const room = document.getElementById('tournament-room').value.trim();
            const status = document.getElementById('tournament-status').value;

            if (!name || !fee || !start || !max) return alert('Please fill all required fields');

            const payload = {
                name,
                entry_fee: fee,
                start_time: new Date(start).toISOString(),
                max_players: max,
                room_code: room || null,
                status
            };

            let res;
            if (currentTournamentId) {
                res = await adminFetch(\`/admin/tournaments/\${currentTournamentId}\`, {
                    method: 'PATCH',
                    body: JSON.stringify(payload)
                });
            } else {
                res = await adminFetch('/admin/tournaments', {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
            }

            if (res && res.ok) {
                closeModal('tournament-modal');
                loadTournaments();
            } else {
                alert('Save failed');
            }
        }

        function openDeleteModal(id) {
            currentTournamentId = id;
            document.getElementById('delete-modal').classList.add('open');
        }

        async function confirmDelete() {
            const res = await adminFetch(\`/admin/tournaments/\${currentTournamentId}\`, { method: 'DELETE' });
            if (res && res.ok) {
                closeModal('delete-modal');
                loadTournaments();
            } else {
                alert('Delete failed');
            }
        }

        // ========== FRIEND MATCHES ==========
        let _dspCreatorId = null, _dspJoinerId = null;

        async function loadFriendMatches() {
            const status = document.getElementById('fm-status-filter').value;
            const url = status === 'all' ? '/admin/friend-matches' : '/admin/friend-matches?status=' + encodeURIComponent(status);
            const loading = document.getElementById('fm-loading');
            if (loading) loading.style.display = 'block';
            try {
                const res = await adminFetch(url);
                if (!res) return;
                if (!res.ok) {
                    const e = await res.json().catch(() => ({}));
                    renderFriendMatches(null, (e.error || 'Server error ' + res.status));
                    return;
                }
                const data = await res.json();
                renderFriendMatches(Array.isArray(data) ? data : []);
            } catch(e) {
                renderFriendMatches(null, 'Network error: ' + e.message);
            } finally {
                if (loading) loading.style.display = 'none';
            }
        }

        function renderFriendMatches(matches, errorMsg) {
            const tbody = document.querySelector('#friend-matches-table tbody');
            tbody.innerHTML = '';
            const cols = 9;
            if (errorMsg) {
                const row = document.createElement('tr');
                row.appendChild(createElementSafe('td', { colspan: String(cols), style: 'text-align:center;color:#ff4444;padding:20px;' }, '⚠️ ' + errorMsg));
                tbody.appendChild(row);
                return;
            }
            if (!matches || matches.length === 0) {
                const row = document.createElement('tr');
                row.appendChild(createElementSafe('td', { colspan: String(cols), style: 'text-align:center;color:#888;padding:24px;' }, 'No matches found'));
                tbody.appendChild(row);
                return;
            }
            matches.forEach(m => {
                const row = document.createElement('tr');
                row.appendChild(createElementSafe('td', { style: 'font-family:monospace;font-size:0.78rem;color:#aaa;' }, m.match_code || '—'));
                const cname = m.creator?.username || (m.creator_id ? m.creator_id.substring(0,8)+'…' : '—');
                const jname = m.joiner?.username  || (m.joiner_id  ? m.joiner_id.substring(0,8)+'…'  : '—');
                row.appendChild(createElementSafe('td', {}, cname));
                row.appendChild(createElementSafe('td', {}, jname));
                const hasScore = m.declared_score_creator !== null && m.declared_score_creator !== undefined
                              && m.declared_score_joiner  !== null && m.declared_score_joiner  !== undefined;
                const scoreStr = hasScore ? (m.declared_score_creator + ' – ' + m.declared_score_joiner) : '—';
                row.appendChild(createElementSafe('td', { style: 'font-weight:700;' }, scoreStr));
                row.appendChild(createElementSafe('td', {}, 'KES ' + (m.wager_amount || 0)));
                row.appendChild(createElementSafe('td', { style: 'color:#00ff41;font-weight:600;' }, 'KES ' + (m.winner_prize || 0)));
                const statusTd = document.createElement('td');
                const sc = m.status === 'pending' ? 'status-pending'
                         : m.status === 'active'  ? 'status-live'
                         : m.status === 'awaiting_confirmation' ? 'status-pending'
                         : m.status === 'disputed' ? 'status-disputed'
                         : 'status-closed';
                statusTd.appendChild(createElementSafe('span', { class: 'status-badge ' + sc }, m.status || '—'));
                row.appendChild(statusTd);
                const ca = m.created_at ? new Date(m.created_at).toLocaleString('en-KE', { dateStyle: 'short', timeStyle: 'short' }) : '—';
                row.appendChild(createElementSafe('td', { style: 'font-size:0.72rem;color:#666;' }, ca));
                const actionsTd = document.createElement('td');
                actionsTd.className = 'actions';
                if (m.status === 'disputed') {
                    const btn = createElementSafe('button', { class: 'btn btn-yellow' }, '⚖️ Resolve');
                    btn.addEventListener('click', () => openDisputeModal(m));
                    actionsTd.appendChild(btn);
                } else if (m.status === 'awaiting_confirmation') {
                    const btn = createElementSafe('button', { class: 'btn btn-blue' }, '👁 View');
                    btn.addEventListener('click', () => openDisputeModal(m));
                    actionsTd.appendChild(btn);
                }
                // ⚡ Override button — shown on all non-terminal matches
                if (!['completed','cancelled','expired'].includes(m.status)) {
                    const ovrBtn = createElementSafe('button', { class: 'btn btn-orange', style: 'margin-left:4px;' }, '⚡ Override');
                    ovrBtn.addEventListener('click', () => openOverrideModal(m));
                    actionsTd.appendChild(ovrBtn);
                }
                if (['completed','cancelled','expired'].includes(m.status) && m.status !== 'disputed' && m.status !== 'awaiting_confirmation') {
                    if (!actionsTd.hasChildNodes()) actionsTd.appendChild(createElementSafe('span', { style: 'color:#333;' }, '—'));
                }
                row.appendChild(actionsTd);
                tbody.appendChild(row);
            });
        }

        function openDisputeModal(m) {
            currentFriendMatchId = m.id;
            _dspCreatorId = m.creator_id;
            _dspJoinerId  = m.joiner_id;
            document.getElementById('dsp-loading').style.display = 'block';
            document.getElementById('dsp-body').style.display = 'none';
            document.getElementById('dispute-modal').classList.add('open');

            const fmt = dt => dt ? new Date(dt).toLocaleString('en-KE',{dateStyle:'short',timeStyle:'short'}) : '—';
            const cname = m.creator?.username || (m.creator_id ? m.creator_id.substring(0,8)+'…' : 'Creator');
            const jname = m.joiner?.username  || (m.joiner_id  ? m.joiner_id.substring(0,8)+'…'  : 'Joiner');
            const cteam = m.creator_team || '—';
            const jteam = m.joiner_team  || '—';

            // ① Meta strip
            document.getElementById('dsp-code').textContent   = m.match_code || '—';
            document.getElementById('dsp-wager').textContent  = m.wager_amount || '—';
            document.getElementById('dsp-prize').textContent  = m.winner_prize || '—';
            document.getElementById('dsp-method').textContent = m.settlement_method || 'manual';
            document.getElementById('dsp-time').textContent   = fmt(m.disputed_at || m.created_at);
            document.getElementById('dsp-btn-c-label').textContent = cname;
            document.getElementById('dsp-btn-j-label').textContent = jname;

            // ② Dispute reason
            const reasonBox = document.getElementById('dsp-reason-box');
            const reasonTxt = m.dispute_reason || 'No reason recorded';
            document.getElementById('dsp-reason-text').textContent = reasonTxt;
            // Who disputed?
            let whoDisputed = '';
            if (m.disputer_id === m.creator_id) whoDisputed = cname + ' (Creator) raised this dispute';
            else if (m.disputer_id === m.joiner_id) whoDisputed = jname + ' (Joiner) raised this dispute';
            if (whoDisputed) {
                const who = document.createElement('div');
                who.style.cssText = 'font-size:0.7rem;color:#888;margin-top:5px;';
                who.textContent = '👤 ' + whoDisputed;
                reasonBox.appendChild(who);
            }

            // ③ Score comparison block
            // Declarers score (from declared_score_creator / declared_score_joiner)
            const cs = m.declared_score_creator, cj = m.declared_score_joiner;
            // Disputer's counter-claim (may be null if they didn't provide one)
            const dc = m.disputer_declared_creator, dj = m.disputer_declared_joiner;

            // Determine who declared (and therefore whose score is "official claim")
            const declarerId = m.declared_score_by;
            const creatorDeclared = declarerId === m.creator_id;

            // Official declared score
            const offC = cs, offJ = cj;   // always from declared_score_* fields
            // Counter score — from disputer if they submitted one
            const cntC = dc !== null && dc !== undefined ? dc : null;
            const cntJ = dj !== null && dj !== undefined ? dj : null;

            // Score compare
            const scC = document.getElementById('sc-cscore');
            const scJ = document.getElementById('sc-jscore');
            document.getElementById('sc-cname').textContent = cname;
            document.getElementById('sc-jname').textContent = jname;
            document.getElementById('sc-cteam').textContent = cteam;
            document.getElementById('sc-jteam').textContent = jteam;

            // Show declared score perspective
            if (offC !== null && offC !== undefined && offJ !== null && offJ !== undefined) {
                scC.textContent = offC; scC.className = 'sc-score-big ' + (offC > offJ ? 'win' : offC < offJ ? 'loss' : 'unk');
                scJ.textContent = offJ; scJ.className = 'sc-score-big ' + (offJ > offC ? 'win' : offJ < offC ? 'loss' : 'unk');
                document.getElementById('sc-clabel').textContent = creatorDeclared ? 'Declared (Creator)' : 'Declared (Joiner)';
                document.getElementById('sc-jlabel').textContent = creatorDeclared ? 'Declared (Joiner)' : 'Declared (Creator)';
            } else {
                scC.textContent = '?'; scC.className = 'sc-score-big unk';
                scJ.textContent = '?'; scJ.className = 'sc-score-big unk';
            }

            // Agree / Disagree verdict tag
            const verdictEl = document.getElementById('sc-verdict');
            if (cntC !== null && cntJ !== null && offC !== null && offJ !== null) {
                const scoresMatch = String(cntC) === String(offC) && String(cntJ) === String(offJ);
                verdictEl.textContent  = scoresMatch ? '✓ Agree' : '✗ Disagree';
                verdictEl.className    = 'sc-verdict ' + (scoresMatch ? 'agree' : 'disagree');
            } else {
                verdictEl.textContent = 'No counter';
                verdictEl.className   = 'sc-verdict';
                verdictEl.style.color = '#333';
            }

            // ④ Player cards
            document.getElementById('dsp-cname').textContent = cname;
            document.getElementById('dsp-jname').textContent = jname;
            document.getElementById('dsp-cteam').textContent = cteam;
            document.getElementById('dsp-jteam').textContent = jteam;

            // Creator card score
            const cScoreEl = document.getElementById('dsp-cscore');
            if (offC !== null && offC !== undefined && offJ !== null && offJ !== undefined) {
                cScoreEl.textContent = offC + ' — ' + offJ;
                cScoreEl.className = 'dp-score-val ' + (offC > offJ ? 'win' : offC < offJ ? 'loss' : 'unk');
            } else { cScoreEl.textContent = '?'; cScoreEl.className = 'dp-score-val unk'; }
            const cBadge = document.getElementById('dsp-c-declared-badge');
            if (creatorDeclared) { cBadge.style.display = ''; cBadge.className = 'dp-badge declared'; cBadge.textContent = 'Declared'; }
            else                 { cBadge.style.display = ''; cBadge.className = 'dp-badge'; cBadge.textContent = 'Opponent declared'; cBadge.style.cssText += 'color:#888;background:rgba(255,255,255,0.04);border:1px solid #2a2a2a;'; }

            // Joiner card score — show their counter-claim if provided, else declared from their POV
            const jScoreEl = document.getElementById('dsp-jscore');
            if (cntC !== null && cntJ !== null) {
                jScoreEl.textContent = cntC + ' — ' + cntJ;
                jScoreEl.className = 'dp-score-val ' + (cntJ > cntC ? 'win' : cntJ < cntC ? 'loss' : 'unk');
                const jBadge = document.getElementById('dsp-j-disputed-badge');
                jBadge.style.display = '';
                jBadge.className = 'dp-badge disputed';
                jBadge.textContent = 'Counter-claim';
            } else if (offC !== null && offC !== undefined) {
                jScoreEl.textContent = offC + ' — ' + offJ;
                jScoreEl.className = 'dp-score-val unk';
                const jBadge = document.getElementById('dsp-j-disputed-badge');
                jBadge.style.display = '';
                jBadge.className = 'dp-badge';
                jBadge.textContent = 'No counter submitted';
                jBadge.style.cssText += 'color:#555;background:transparent;border:1px solid #222;';
            } else { jScoreEl.textContent = '?'; jScoreEl.className = 'dp-score-val unk'; }

            // Screenshots
            const cImg = m.creator_screenshot_url || m.declared_screenshot_url || m.screenshot_url
                      || m.confirmer_screenshot_url || m.draw_screenshot_url || m.penalty_screenshot_url || null;
            const jImg = m.joiner_screenshot_url || m.disputer_screenshot_url || m.challenge_screenshot_url || null;
            const cImgDiv = document.getElementById('dsp-cimg');
            const jImgDiv = document.getElementById('dsp-jimg');
            const cLink = document.getElementById('dsp-cimg-link');
            const jLink = document.getElementById('dsp-jimg-link');

            if (cImg) {
                const img = document.createElement('img');
                img.className = 'dp-img'; img.src = cImg; img.title = 'Click to open evidence viewer';
                img.addEventListener('click', () => openLightboxCompare(cImg, jImg,
                    '🔵 ' + cname + ' (Creator)', '🟠 ' + jname + ' (Joiner)'));
                cImgDiv.innerHTML = ''; cImgDiv.appendChild(img);
                cLink.href = cImg; cLink.style.display = 'block';
            } else {
                cImgDiv.innerHTML = '<div class="dp-noimg">No screenshot provided</div>';
                cLink.style.display = 'none';
            }
            if (jImg) {
                const img = document.createElement('img');
                img.className = 'dp-img'; img.src = jImg; img.title = 'Click to open evidence viewer';
                img.addEventListener('click', () => openLightboxCompare(cImg, jImg,
                    '🔵 ' + cname + ' (Creator)', '🟠 ' + jname + ' (Joiner)'));
                jImgDiv.innerHTML = ''; jImgDiv.appendChild(img);
                jLink.href = jImg; jLink.style.display = 'block';
            } else {
                jImgDiv.innerHTML = '<div class="dp-noimg">No screenshot provided</div>';
                jLink.style.display = 'none';
            }

            // ⑤ Timeline
            const tlContainer = document.getElementById('dsp-timeline-rows');
            tlContainer.innerHTML = '';
            const tlEvents = [
                { dot:'green',  time: m.created_at,   text: '<strong>Match created</strong> by ' + cname },
                { dot:'blue',   time: m.started_at,   text: '<strong>' + jname + '</strong> joined — match started' },
                m.declared_score_by ? { dot:'yellow', time: m.declared_at || m.score_declared_at,
                    text: '<strong>Score declared</strong> (' + offC + '–' + offJ + ') by ' +
                          (declarerId === m.creator_id ? cname : jname) } : null,
                m.disputed_at ? { dot:'red', time: m.disputed_at,
                    text: '<strong>Dispute raised</strong>' + (reasonTxt !== 'No reason recorded' ? ': "' + reasonTxt + '"' : '') } : null,
            ].filter(Boolean);
            tlEvents.forEach(ev => {
                const row = document.createElement('div');
                row.className = 'tl-row';
                const dot = document.createElement('div');
                dot.className = 'tl-dot ' + ev.dot;
                const body = document.createElement('div');
                body.className = 'tl-body'; body.innerHTML = ev.text;
                const time = document.createElement('div');
                time.className = 'tl-time'; time.textContent = fmt(ev.time);
                row.appendChild(dot); row.appendChild(body); row.appendChild(time);
                tlContainer.appendChild(row);
            });

            // ⑥ Clear notes field
            document.getElementById('dsp-admin-notes').value = '';

            document.getElementById('dsp-loading').style.display = 'none';
            document.getElementById('dsp-body').style.display = 'block';
        }

        // ══════════════════════════════════════════════════════════════
        // EVIDENCE LIGHTBOX — zoom, pan, side-by-side compare
        // ══════════════════════════════════════════════════════════════
        const _lb = {
            scale: 1, minScale: 0.25, maxScale: 8,
            panX: 0, panY: 0,
            dragging: false, lastX: 0, lastY: 0,
            mode: 'single',   // 'single' | 'compare'
            leftSrc: null, rightSrc: null,
            leftLabel: '🔵 Creator', rightLabel: '🟠 Joiner'
        };

        function openLightbox(src, title) {
            _lb.leftSrc  = null;
            _lb.rightSrc = null;
            lbSetMode('single');
            document.getElementById('lightbox-img').src = src;
            document.getElementById('lb-title').textContent = title || 'Screenshot Evidence';
            lbResetZoom();
            document.getElementById('lightbox').classList.add('open');
        }

        // Called from override and dispute modals — passes both screenshots
        function openLightboxCompare(leftSrc, rightSrc, leftLabel, rightLabel) {
            _lb.leftSrc    = leftSrc  || null;
            _lb.rightSrc   = rightSrc || null;
            _lb.leftLabel  = leftLabel  || '🔵 Creator';
            _lb.rightLabel = rightLabel || '🟠 Joiner';

            // Populate compare panes
            const lWrap = document.getElementById('lb-cmp-left-wrap');
            const rWrap = document.getElementById('lb-cmp-right-wrap');
            document.getElementById('lb-cmp-left-label').textContent  = leftLabel  || '🔵 Creator';
            document.getElementById('lb-cmp-right-label').textContent = rightLabel || '🟠 Joiner';

            lWrap.innerHTML = leftSrc
                ? '<img src="' + escapeHtml(leftSrc)  + '" draggable="false" style="max-width:100%;max-height:100%;object-fit:contain;">'
                : '<div class="lb-no-img">No screenshot</div>';
            rWrap.innerHTML = rightSrc
                ? '<img src="' + escapeHtml(rightSrc) + '" draggable="false" style="max-width:100%;max-height:100%;object-fit:contain;">'
                : '<div class="lb-no-img">No screenshot</div>';

            // Default: if both screenshots exist open compare, else single
            if (leftSrc && rightSrc) {
                lbSetMode('compare');
                document.getElementById('lightbox-img').src = leftSrc;
            } else {
                document.getElementById('lightbox-img').src = leftSrc || rightSrc || '';
                lbSetMode('single');
            }
            document.getElementById('lb-title').textContent = 'Screenshot Evidence';
            lbResetZoom();
            document.getElementById('lightbox').classList.add('open');
        }

        function lbClose() {
            document.getElementById('lightbox').classList.remove('open');
            document.getElementById('lightbox-img').src = '';
        }

        function lbSetMode(mode) {
            _lb.mode = mode;
            const singleEl  = document.getElementById('lb-single');
            const compareEl = document.getElementById('lb-compare');
            const btnS = document.getElementById('lb-btn-single');
            const btnC = document.getElementById('lb-btn-compare');
            if (mode === 'compare') {
                singleEl.style.display  = 'none';
                compareEl.classList.add('active');
                btnS.classList.remove('active');
                btnC.classList.add('active');
            } else {
                singleEl.style.display  = '';
                compareEl.classList.remove('active');
                btnS.classList.add('active');
                btnC.classList.remove('active');
            }
        }

        function lbApplyTransform() {
            const img = document.getElementById('lightbox-img');
            img.style.transform = \`translate(\${_lb.panX}px, \${_lb.panY}px) scale(\${_lb.scale})\`;
            document.getElementById('lb-zoom-label').textContent = Math.round(_lb.scale * 100) + '%';
        }

        function lbZoom(delta) {
            _lb.scale = Math.min(_lb.maxScale, Math.max(_lb.minScale, _lb.scale + delta));
            lbApplyTransform();
        }

        function lbResetZoom() {
            _lb.scale = 1; _lb.panX = 0; _lb.panY = 0;
            lbApplyTransform();
        }

        // Scroll to zoom
        document.getElementById('lightbox').addEventListener('wheel', e => {
            if (_lb.mode !== 'single') return;
            e.preventDefault();
            const delta = e.deltaY > 0 ? -0.15 : 0.15;
            _lb.scale = Math.min(_lb.maxScale, Math.max(_lb.minScale, _lb.scale + delta));
            lbApplyTransform();
        }, { passive: false });

        // Drag to pan
        const lbSingle = document.getElementById('lb-single');
        lbSingle.addEventListener('mousedown', e => {
            if (e.button !== 0) return;
            _lb.dragging = true; _lb.lastX = e.clientX; _lb.lastY = e.clientY;
            lbSingle.classList.add('grabbing');
        });
        window.addEventListener('mousemove', e => {
            if (!_lb.dragging) return;
            _lb.panX += e.clientX - _lb.lastX;
            _lb.panY += e.clientY - _lb.lastY;
            _lb.lastX = e.clientX; _lb.lastY = e.clientY;
            lbApplyTransform();
        });
        window.addEventListener('mouseup', () => {
            _lb.dragging = false;
            lbSingle.classList.remove('grabbing');
        });

        // Keyboard shortcuts
        window.addEventListener('keydown', e => {
            if (!document.getElementById('lightbox').classList.contains('open')) return;
            if (e.key === 'Escape') lbClose();
            if (e.key === '+' || e.key === '=') lbZoom(+0.25);
            if (e.key === '-') lbZoom(-0.25);
            if (e.key === '0') lbResetZoom();
            if (e.key === 'c' || e.key === 'C') lbSetMode(_lb.mode === 'compare' ? 'single' : 'compare');
        });

        async function resolveDispute(side) {
            const adminNotes = (document.getElementById('dsp-admin-notes').value || '').trim();
            const body = side === 'draw'
                ? { resolution: 'draw', adminNotes }
                : { winnerId: side === 'creator' ? _dspCreatorId : _dspJoinerId, adminNotes };
            const label = side === 'creator' ? 'Creator wins' : side === 'joiner' ? 'Joiner wins' : 'Refund both';
            if (!confirm(label + ' — are you sure?')) return;
            document.querySelectorAll('.da-btn').forEach(b => b.disabled = true);
            const res = await adminFetch('/admin/resolve-dispute/' + currentFriendMatchId, {
                method: 'POST', body: JSON.stringify(body)
            });
            if (res && res.ok) {
                closeModal('dispute-modal');
                loadFriendMatches();
            } else {
                alert('Failed to resolve. Check server logs.');
                document.querySelectorAll('.da-btn').forEach(b => b.disabled = false);
            }
        }

        // ========== UI Helpers ==========
        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('open');
            if (modalId === 'paid-modal' || modalId === 'reject-modal') currentWithdrawalId = null;
            if (modalId === 'tournament-modal') currentTournamentId = null;
            if (modalId === 'dispute-modal') currentFriendMatchId = null;
        }

        // Attach filter change listener
        document.getElementById('fm-status-filter').addEventListener('change', loadFriendMatches);

        // ══════════════════════════════════════════════════════════════
        // FORCE WINNER OVERRIDE — admin modal JS
        // ══════════════════════════════════════════════════════════════
        let _ovrMatch       = null;
        let _ovrSelection   = null;  // 'creator' | 'joiner' | 'draw'

        function lbOpenFromOverride() {
            if (!_ovrMatch) return;
            const m = _ovrMatch;
            const cImg = m.creator_screenshot_url || m.declared_screenshot_url || m.screenshot_url
                      || m.confirmer_screenshot_url || m.draw_screenshot_url || m.penalty_screenshot_url || null;
            const jImg = m.joiner_screenshot_url || m.disputer_screenshot_url || m.challenge_screenshot_url || null;
            const cname = (m.creator?.username || 'Creator') + ' (Creator)';
            const jname = (m.joiner?.username  || 'Joiner')  + ' (Joiner)';
            openLightboxCompare(cImg, jImg, '🔵 ' + cname, '🟠 ' + jname);
        }

        function openOverrideModal(m) {
            _ovrMatch     = m;
            _ovrSelection = null;

            // Populate summary
            document.getElementById('ovr-code').textContent   = m.match_code || '—';
            document.getElementById('ovr-status').textContent = m.status || '—';
            document.getElementById('ovr-prize').textContent  = m.winner_prize || '—';

            const cs = m.declared_score_creator, cj = m.declared_score_joiner;
            document.getElementById('ovr-score').textContent =
                (cs !== null && cs !== undefined && cj !== null && cj !== undefined)
                ? cs + ' — ' + cj : 'Not declared yet';

            // Player names / teams
            const cname = m.creator?.username || (m.creator_id ? m.creator_id.substring(0,8)+'…' : 'Creator');
            const jname = m.joiner?.username  || (m.joiner_id  ? m.joiner_id.substring(0,8)+'…'  : 'Joiner (not joined yet)');
            document.getElementById('ovr-cname').textContent = cname;
            document.getElementById('ovr-jname').textContent = jname;
            document.getElementById('ovr-cteam').textContent = m.creator_team || '—';
            document.getElementById('ovr-jteam').textContent = m.joiner_team  || '—';

            // Disable joiner button if match has no joiner yet
            const joinerBtn = document.getElementById('ovr-btn-joiner');
            if (!m.joiner_id) {
                joinerBtn.disabled = true;
                joinerBtn.style.opacity = '0.3';
                joinerBtn.title = 'No joiner yet';
            } else {
                joinerBtn.disabled = false;
                joinerBtn.style.opacity = '';
                joinerBtn.title = '';
            }

            // ── Populate screenshots ──────────────────────────────────
            // All these columns come back in the match object from select('*')
            const ssFields = [
                { url: m.creator_screenshot_url,     tag: 'Creator upload (dual)',  side: 'c' },
                { url: m.declared_screenshot_url,    tag: 'Declared result',        side: 'c' },
                { url: m.screenshot_url,             tag: 'Original upload',        side: 'c' },
                { url: m.confirmer_screenshot_url,   tag: 'Confirmer screenshot',   side: 'c' },
                { url: m.first_upload_screenshot_url,tag: 'First OCR upload',       side: 'c' },
                { url: m.draw_screenshot_url,        tag: 'Draw screenshot',        side: 'c' },
                { url: m.penalty_screenshot_url,     tag: 'Penalty result',         side: 'c' },
            ];
            const ssFieldsJ = [
                { url: m.joiner_screenshot_url,      tag: 'Joiner upload (dual)',   side: 'j' },
                { url: m.disputer_screenshot_url,    tag: 'Disputer screenshot',    side: 'j' },
                { url: m.challenge_screenshot_url,   tag: 'Challenge screenshot',   side: 'j' },
            ];

            // ── Show OCR data beneath each screenshot if available ────
            function ocrBadge(ocrRaw) {
                if (!ocrRaw) return '';
                try {
                    const d = JSON.parse(ocrRaw);
                    const score = (d.score1 != null && d.score2 != null) ? \`\${d.score1}–\${d.score2}\` : '?–?';
                    const conf  = d.confidence != null ? d.confidence + '%' : '?';
                    const fraud = d.fraudScore  != null ? d.fraudScore      : '?';
                    const fraudColor = fraud >= 60 ? '#ff4444' : fraud >= 30 ? '#ffaa44' : '#00ff41';
                    return \`<div style="padding:5px 8px 7px;font-size:0.65rem;color:#888;display:flex;gap:10px;flex-wrap:wrap;">
                        <span>⚽ Score: <b style="color:#fff">\${score}</b></span>
                        <span>🎯 Conf: <b style="color:#4aadff">\${conf}</b></span>
                        <span>🚨 Fraud: <b style="color:\${fraudColor}">\${fraud}</b></span>
                    </div>\`;
                } catch { return ''; }
            }

            function populateSsCard(fields, wrapId, linkId, tagId, ocrRaw) {
                const wrap = document.getElementById(wrapId);
                const link = document.getElementById(linkId);
                const tag  = document.getElementById(tagId);
                const found = fields.find(f => f.url);
                if (found) {
                    const img = document.createElement('img');
                    img.className = 'ovr-ss-img';
                    img.src = found.url;
                    img.title = 'Click to enlarge';
                    img.addEventListener('click', () => openLightbox(found.url));
                    img.onerror = () => { wrap.innerHTML = '<div class="ovr-ss-none" style="color:#ff6644">⚠️ Image failed to load</div>'; };
                    wrap.innerHTML = '';
                    wrap.appendChild(img);
                    link.href = found.url;
                    link.style.display = '';
                    tag.textContent = found.tag;
                    // OCR badge — show score/confidence/fraud under image
                    if (ocrRaw) {
                        try {
                            const d = JSON.parse(ocrRaw);
                            const score = (d.score1 != null && d.score2 != null) ? d.score1 + '\\u2013' + d.score2 : '?\\u2013?';
                            const conf  = d.confidence != null ? d.confidence + '%' : '?';
                            const fraud = d.fraudScore  != null ? d.fraudScore      : '?';
                            const fc    = fraud >= 60 ? '#ff4444' : fraud >= 30 ? '#ffaa44' : '#00ff41';
                            const badge = document.createElement('div');
                            badge.style.cssText = 'padding:5px 8px 7px;font-size:0.65rem;color:#888;display:flex;gap:10px;flex-wrap:wrap;border-top:1px solid #1a1a22;';
                            badge.innerHTML = '<span>⚽ <b style="color:#fff">' + score + '</b></span><span>🎯 <b style="color:#4aadff">' + conf + '</b></span><span>🚨 Fraud: <b style="color:' + fc + '">' + fraud + '</b></span>';
                            wrap.parentElement.appendChild(badge);
                        } catch(e) {}
                    }
                } else {
                    wrap.innerHTML = '<div class="ovr-ss-none">No screenshot</div>';
                    link.style.display = 'none';
                    tag.textContent = '';
                }
            }
            populateSsCard(ssFields,  'ovr-ss-c-wrap', 'ovr-ss-c-link', 'ovr-ss-c-tag', m.creator_ocr_data);
            populateSsCard(ssFieldsJ, 'ovr-ss-j-wrap', 'ovr-ss-j-link', 'ovr-ss-j-tag', m.joiner_ocr_data);

            // Reset state
            ['ovr-btn-creator','ovr-btn-joiner','ovr-btn-draw'].forEach(id => {
                const el = document.getElementById(id);
                el.classList.remove('selected','blue','orange');
            });
            document.getElementById('ovr-notes').value = '';
            const submitBtn = document.getElementById('ovr-submit-btn');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Select a winner above to continue';

            document.getElementById('override-modal').classList.add('open');
        }

        function selectOverrideWinner(side) {
            _ovrSelection = side;

            // Reset all buttons
            document.getElementById('ovr-btn-creator').classList.remove('selected','blue','orange');
            document.getElementById('ovr-btn-joiner').classList.remove('selected','blue','orange');
            document.getElementById('ovr-btn-draw').classList.remove('selected');

            if (side === 'creator') {
                document.getElementById('ovr-btn-creator').classList.add('selected','blue');
            } else if (side === 'joiner') {
                document.getElementById('ovr-btn-joiner').classList.add('selected','orange');
            } else {
                document.getElementById('ovr-btn-draw').classList.add('selected');
            }

            const submitBtn = document.getElementById('ovr-submit-btn');
            submitBtn.disabled = false;

            if (side === 'draw') {
                submitBtn.textContent = '↩ Confirm: Refund Both Players';
                submitBtn.style.background = 'linear-gradient(135deg,#555,#333)';
            } else {
                const name = side === 'creator'
                    ? (document.getElementById('ovr-cname').textContent)
                    : (document.getElementById('ovr-jname').textContent);
                submitBtn.textContent = '⚡ Confirm: ' + name + ' Wins';
                submitBtn.style.background = side === 'creator'
                    ? 'linear-gradient(135deg,#0077dd,#0055aa)'
                    : 'linear-gradient(135deg,#dd6600,#aa4400)';
            }
        }

        async function submitOverride() {
            if (!_ovrMatch || !_ovrSelection) return;

            const notes = (document.getElementById('ovr-notes').value || '').trim();
            if (!notes) {
                alert('Please enter a reason / evidence note before submitting.');
                document.getElementById('ovr-notes').focus();
                return;
            }

            const sideLabel = _ovrSelection === 'draw' ? 'Refund both players'
                : _ovrSelection === 'creator' ? document.getElementById('ovr-cname').textContent + ' wins'
                : document.getElementById('ovr-jname').textContent + ' wins';

            if (!confirm('ADMIN OVERRIDE — ' + sideLabel + '\\n\\nThis is permanent and cannot be undone. Continue?')) return;

            const submitBtn = document.getElementById('ovr-submit-btn');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Processing…';

            const body = _ovrSelection === 'draw'
                ? { resolution: 'draw', adminNotes: notes }
                : {
                    winnerId:   _ovrSelection === 'creator' ? _ovrMatch.creator_id : _ovrMatch.joiner_id,
                    adminNotes: notes
                  };

            const res = await adminFetch('/admin/force-winner/' + _ovrMatch.id, {
                method: 'POST',
                body: JSON.stringify(body)
            });

            if (res && res.ok) {
                const data = await res.json();
                closeModal('override-modal');
                loadFriendMatches();
                alert('✅ Done! ' + (data.message || 'Override applied.'));
            } else {
                let errMsg = 'Failed to apply override. Check server logs.';
                try { const d = await res.json(); errMsg = d.error || errMsg; } catch(e) {}
                alert('❌ ' + errMsg);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Retry';
            }
        }

        // ========== ANALYTICS ==========
        let analyticsLoaded = false;

        async function loadAnalytics() {
            const container = document.getElementById('analytics-content');
            if (analyticsLoaded) return; // already loaded, don't re-fetch
            container.innerHTML = '<div style="text-align:center;padding:60px;color:#555;"><div style="font-size:2rem;margin-bottom:12px;animation:spin 1s linear infinite;display:inline-block;">⚙️</div><div style="margin-top:8px;">Crunching numbers...</div></div>';

            const res = await adminFetch('/admin/analytics');
            if (!res) return;
            const d = await res.json();
            if (d.error) {
                container.innerHTML = '<div style="color:#ff4444;padding:20px;">Error: ' + escapeHtml(d.error) + '</div>';
                return;
            }

            analyticsLoaded = true;
            renderAnalytics(d);
        }

        function fmt(n, decimals = 0) {
            if (n === null || n === undefined) return '—';
            return Number(n).toLocaleString('en-KE', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
        }

        function growthBadge(pct) {
            if (pct === null || pct === undefined) return '';
            const n = parseFloat(pct);
            const color = n >= 0 ? '#00ff41' : '#ff4444';
            const arrow = n >= 0 ? '▲' : '▼';
            return \`<span style="font-size:0.72rem;color:\${color};font-weight:700;margin-left:8px;">\${arrow} \${Math.abs(n)}% vs last mo.</span>\`;
        }

        function renderAnalytics(d) {
            const { revenue, matches, users, withdrawals, platform, dailyChart } = d;

            // Build chart SVG inline
            const chartHtml = buildBarChart(dailyChart);

            const html = \`
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px;">
                <div>
                    <div style="font-family:'Bebas Neue',sans-serif;font-size:2rem;color:#00ff41;letter-spacing:2px;">ANALYTICS</div>
                    <div style="font-size:0.72rem;color:#555;margin-top:2px;">Generated \${new Date(d.generatedAt).toLocaleString('en-KE')}</div>
                </div>
                <button onclick="analyticsLoaded=false;loadAnalytics();" style="background:#1a1a20;border:1px solid #2a2a30;color:#aaa;padding:8px 18px;border-radius:10px;cursor:pointer;font-size:0.8rem;">↻ Refresh</button>
            </div>

            <!-- ── TOP KPI GRID ── -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:28px;">

                \${kpiCard('💰', 'ALL-TIME REVENUE', 'KES ' + fmt(revenue.allTimeFees), null, '#00ff41')}
                \${kpiCard('📅', 'MTD REVENUE', 'KES ' + fmt(revenue.mtdFees), growthBadge(revenue.feesGrowthPct), '#00ff41')}
                \${kpiCard('🔄', 'ALL-TIME VOLUME', 'KES ' + fmt(revenue.allTimeVolume), null, '#aaa')}
                \${kpiCard('📈', 'MTD VOLUME', 'KES ' + fmt(revenue.mtdVolume), growthBadge(revenue.volumeGrowthPct), '#aaa')}
                \${kpiCard('⚽', 'TOTAL MATCHES', fmt(matches.totalCompleted), null, '#aaa')}
                \${kpiCard('📅', 'MATCHES THIS MONTH', fmt(matches.mtdCompleted), null, '#aaa')}
                \${kpiCard('👥', 'TOTAL USERS', fmt(users.total), null, '#aaa')}
                \${kpiCard('🆕', 'NEW TODAY', fmt(users.newToday), null, '#ffb400')}
                \${kpiCard('🔥', 'ACTIVE (7 DAYS)', fmt(users.active7Days), null, '#ffb400')}
                \${kpiCard('💎', 'AVG WAGER', 'KES ' + fmt(matches.avgWager, 0), null, '#aaa')}
                \${kpiCard('⚖️', 'DISPUTE RATE', matches.disputeRate + '%', null, parseFloat(matches.disputeRate) > 5 ? '#ff4444' : '#00ff41')}
                \${kpiCard('🏦', 'PLATFORM FLOAT', 'KES ' + fmt(platform.totalFloat), null, '#aaa')}
            </div>

            <!-- ── CHART ── -->
            <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:24px;margin-bottom:24px;">
                <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">DAILY VOLUME — LAST 30 DAYS (KES)</div>
                \${chartHtml}
            </div>

            <!-- ── SECOND ROW CARDS ── -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px;">

                <!-- Revenue breakdown -->
                <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:22px;">
                    <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">💰 REVENUE BREAKDOWN</div>
                    \${statRow('All-time fees collected', 'KES ' + fmt(revenue.allTimeFees, 2), '#00ff41')}
                    \${statRow('MTD fees', 'KES ' + fmt(revenue.mtdFees, 2), '#00ff41')}
                    \${statRow('Last month fees', 'KES ' + fmt(revenue.lastMonthFees, 2))}
                    \${statRow('MoM growth', revenue.feesGrowthPct !== null ? revenue.feesGrowthPct + '%' : '—', parseFloat(revenue.feesGrowthPct) >= 0 ? '#00ff41' : '#ff4444')}
                    \${statRow('Platform float (held)', 'KES ' + fmt(platform.totalFloat, 2))}
                    \${statRow('Wallets with balance', fmt(users.walletsWithFunds))}
                </div>

                <!-- Match stats -->
                <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:22px;">
                    <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">⚽ MATCH STATS</div>
                    \${statRow('Total completed', fmt(matches.totalCompleted))}
                    \${statRow('MTD completed', fmt(matches.mtdCompleted))}
                    \${statRow('Average wager', 'KES ' + fmt(matches.avgWager, 0))}
                    \${statRow('Dispute rate', matches.disputeRate + '%', parseFloat(matches.disputeRate) > 5 ? '#ff4444' : '#00ff41')}
                    \${statRow('Disputed (open)', fmt(matches.disputedCount))}
                    \${statRow('Auto-settled', fmt(matches.settlementMethods?.auto || 0))}
                    \${statRow('Challenge timeout', fmt(matches.settlementMethods?.challenge_timeout || 0))}
                    \${statRow('Penalty shootouts', fmt(matches.settlementMethods?.penalty_shootout || 0))}
                    \${statRow('Forfeits', fmt(matches.settlementMethods?.forfeit || 0))}
                </div>

                <!-- Withdrawal stats -->
                <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:22px;">
                    <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">💸 WITHDRAWALS</div>
                    \${statRow('All-time paid out', 'KES ' + fmt(withdrawals.allTimeVolume, 2))}
                    \${statRow('MTD paid out', 'KES ' + fmt(withdrawals.mtdVolume, 2))}
                    \${statRow('Pending count', fmt(withdrawals.pendingCount), withdrawals.pendingCount > 10 ? '#ff4444' : '#ffb400')}
                    \${statRow('Pending volume', 'KES ' + fmt(withdrawals.pendingVolume, 2), '#ffb400')}
                    \${statRow('Avg processing time', withdrawals.avgProcessingHrs !== null ? withdrawals.avgProcessingHrs + ' hrs' : '—')}
                </div>

                <!-- User stats -->
                <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:22px;">
                    <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">👥 USERS</div>
                    \${statRow('Total registered', fmt(users.total))}
                    \${statRow('New today', fmt(users.newToday), '#ffb400')}
                    \${statRow('New this month', fmt(users.newMtd))}
                    \${statRow('Active last 7 days', fmt(users.active7Days), '#00ff41')}
                    \${statRow('Wallets with balance', fmt(users.walletsWithFunds))}
                </div>

                <!-- Platform health -->
                <div style="background:#111116;border:1px solid #1e1e24;border-radius:16px;padding:22px;">
                    <div style="font-size:0.7rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:16px;">🏟️ PLATFORM HEALTH</div>
                    \${statRow('Active tournaments', fmt(platform.activeTournaments))}
                    \${statRow('Live pool value', 'KES ' + fmt(platform.livePoolValue, 2))}
                    \${statRow('Platform float', 'KES ' + fmt(platform.totalFloat, 2))}
                    <div style="margin-top:16px;padding-top:14px;border-top:1px solid #1e1e24;">
                        <div style="font-size:0.65rem;color:#555;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;">SETTLEMENT MIX</div>
                        \${renderSettlementBar(matches.settlementMethods, matches.totalCompleted)}
                    </div>
                </div>

            </div>
            \`;

            document.getElementById('analytics-content').innerHTML = html;
        }

        function kpiCard(icon, label, value, extra = null, valueColor = '#f0f0f0') {
            return \`<div style="background:#111116;border:1px solid #1e1e24;border-radius:14px;padding:20px;">
                <div style="font-size:0.62rem;letter-spacing:2px;text-transform:uppercase;color:#444;margin-bottom:8px;">\${icon} \${label}</div>
                <div style="font-family:'Bebas Neue',sans-serif;font-size:1.9rem;color:\${valueColor};letter-spacing:1px;line-height:1;">\${value}</div>
                \${extra ? '<div style="margin-top:4px;">' + extra + '</div>' : ''}
            </div>\`;
        }

        function statRow(label, value, valueColor = '#f0f0f0') {
            return \`<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #1a1a20;">
                <span style="font-size:0.78rem;color:#888;">\${label}</span>
                <span style="font-size:0.85rem;font-weight:700;color:\${valueColor};">\${value}</span>
            </div>\`;
        }

        function renderSettlementBar(methods, total) {
            if (!methods || total === 0) return '<div style="color:#555;font-size:0.75rem;">No data</div>';
            const colors = { auto: '#00ff41', challenge_timeout: '#ffb400', penalty_shootout: '#0088ff', forfeit: '#ff4444', draw_refund: '#aa88ff', manual: '#666' };
            const labels = { auto: 'Auto', challenge_timeout: 'Timeout', penalty_shootout: 'Pens', forfeit: 'Forfeit', draw_refund: 'Draw', manual: 'Manual' };
            let bars = '';
            let legend = '';
            for (const [key, count] of Object.entries(methods)) {
                const pct = ((count / total) * 100).toFixed(1);
                const color = colors[key] || '#666';
                bars += \`<div style="flex:\${pct};min-width:2px;background:\${color};height:100%;border-radius:2px;" title="\${labels[key]||key}: \${count} (\${pct}%)"></div>\`;
                legend += \`<div style="display:flex;align-items:center;gap:5px;font-size:0.68rem;color:#888;"><div style="width:8px;height:8px;background:\${color};border-radius:2px;flex-shrink:0;"></div>\${labels[key]||key} <span style="color:#aaa;font-weight:700;">\${count}</span></div>\`;
            }
            return \`
                <div style="display:flex;gap:3px;height:10px;border-radius:5px;overflow:hidden;margin-bottom:10px;">\${bars}</div>
                <div style="display:flex;flex-wrap:wrap;gap:8px;">\${legend}</div>\`;
        }

        function buildBarChart(dailyChart) {
            if (!dailyChart || dailyChart.length === 0) return '<div style="color:#555;text-align:center;padding:20px;">No data</div>';

            const maxVol = Math.max(...dailyChart.map(d => d.volume), 1);
            const barW = 100 / dailyChart.length;
            let bars = '';
            let xLabels = '';
            let tooltips = '';

            dailyChart.forEach((day, i) => {
                const heightPct = maxVol > 0 ? (day.volume / maxVol) * 100 : 0;
                const x = i * barW;
                const barColor = day.volume > 0 ? '#00ff41' : '#1a1a20';
                const opacity = day.volume > 0 ? '0.85' : '1';
                bars += \`<rect x="\${x + barW * 0.1}%" y="\${100 - heightPct}%" width="\${barW * 0.8}%" height="\${heightPct}%" fill="\${barColor}" opacity="\${opacity}" rx="2">
                    <title>\${day.date}: KES \${fmt(day.volume)} volume, \${day.matches} matches</title>
                </rect>\`;

                // Show label every 7 days
                if (i % 7 === 0 || i === dailyChart.length - 1) {
                    const label = day.date.substring(5); // MM-DD
                    xLabels += \`<text x="\${(x + barW / 2)}%" y="98%" text-anchor="middle" fill="#444" font-size="9" font-family="monospace">\${label}</text>\`;
                }
            });

            // Y-axis labels
            const yLabels = [0, 0.25, 0.5, 0.75, 1].map(pct => {
                const val = maxVol * pct;
                const y = 100 - pct * 100;
                return \`<text x="0" y="\${y}%" dominant-baseline="middle" fill="#333" font-size="9" font-family="monospace">KES \${val >= 1000 ? (val/1000).toFixed(0)+'k' : val.toFixed(0)}</text>\`;
            }).join('');

            // Grid lines
            const gridLines = [0.25, 0.5, 0.75, 1].map(pct => {
                const y = 100 - pct * 100;
                return \`<line x1="0" y1="\${y}%" x2="100%" y2="\${y}%" stroke="#1a1a20" stroke-width="1"/>\`;
            }).join('');

            return \`<div style="position:relative;width:100%;">
                <svg viewBox="0 0 600 180" preserveAspectRatio="none" style="width:100%;height:180px;overflow:visible;">
                    \${gridLines}
                    \${bars}
                    \${xLabels}
                </svg>
            </div>\`;
        }
    </script>
</body>
</html>`;

const HTML_WAR_ROOM = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>War Room | Vumbua eFootball</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⚔️</text></svg>">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon: #00ff41;
            --neon-dim: #00cc34;
            --neon-glow: rgba(0, 255, 65, 0.4);
            --bg: #060608;
            --card: rgba(14, 14, 18, 0.9);
            --border: rgba(255, 255, 255, 0.07);
            --text: #f0f0f0;
            --muted: #666;
            --gold: #ffd700;
            --gold-glow: rgba(255, 215, 0, 0.3);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        html, body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Outfit', sans-serif;
            min-height: 100%;
            -webkit-font-smoothing: antialiased;
            padding-bottom: env(safe-area-inset-bottom);
        }

        .arena-bg {
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background:
                radial-gradient(ellipse 80% 45% at 50% 0%, rgba(0,255,65,0.08) 0%, transparent 55%),
                radial-gradient(ellipse 60% 35% at 50% 100%, rgba(0,255,65,0.03) 0%, transparent 50%);
        }
        .grid-lines {
            position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: 0.03;
            background-image:
                repeating-linear-gradient(0deg, transparent, transparent 59px, rgba(0,255,65,1) 60px),
                repeating-linear-gradient(90deg, transparent, transparent 59px, rgba(0,255,65,1) 60px);
            animation: gridScroll 18s linear infinite;
        }
        @keyframes gridScroll { to { transform: translateY(60px); } }
        .scanlines {
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.1) 2px, rgba(0,0,0,0.1) 4px);
        }

        .war-room {
            position: relative; z-index: 1;
            width: 100%; max-width: 480px;
            margin: 0 auto;
            padding: 16px 16px 32px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            animation: arenaIn 0.6s cubic-bezier(0.16,1,0.3,1) both;
        }
        @keyframes arenaIn {
            from { opacity: 0; transform: translateY(16px); }
            to   { opacity: 1; transform: translateY(0); }
        }

        /* Header */
        .wr-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: env(safe-area-inset-top, 8px);
        }
        .wr-logo-wrap { display: flex; flex-direction: column; }
        .wr-logo { font-family: 'Bebas Neue', sans-serif; font-size: 0.75rem; letter-spacing: 4px; color: var(--muted); }
        .wr-title {
            font-family: 'Bebas Neue', sans-serif; font-size: 2.2rem; letter-spacing: 6px;
            color: var(--neon); text-shadow: 0 0 30px var(--neon-glow); line-height: 1;
            animation: titleFlicker 5s ease-in-out infinite;
        }
        @keyframes titleFlicker {
            0%, 88%, 100% { opacity: 1; }
            90% { opacity: 0.8; }
            92% { opacity: 1; }
        }

        /* Live badge */
        .live-badge {
            display: inline-flex; align-items: center; gap: 7px;
            background: rgba(0,255,65,0.08); border: 1px solid rgba(0,255,65,0.25);
            border-radius: 30px; padding: 7px 14px;
            font-size: 0.65rem; font-weight: 700; letter-spacing: 2.5px;
            text-transform: uppercase; color: var(--neon); white-space: nowrap;
        }
        .live-dot {
            width: 8px; height: 8px; border-radius: 50%; background: var(--neon);
            animation: livePulse 1.4s cubic-bezier(0.4,0,0.6,1) infinite;
        }
        @keyframes livePulse {
            0%   { box-shadow: 0 0 0 0 rgba(0,255,65,0.7); }
            70%  { box-shadow: 0 0 0 8px rgba(0,255,65,0); }
            100% { box-shadow: 0 0 0 0 rgba(0,255,65,0); }
        }

        /* Elapsed pill */
        .elapsed-pill {
            text-align: center; font-size: 0.68rem; color: var(--muted); letter-spacing: 2px;
            background: rgba(255,255,255,0.03); border: 1px solid var(--border);
            border-radius: 30px; padding: 6px 16px;
        }
        .elapsed-pill span { color: rgba(255,255,255,0.35); font-weight: 700; }

        /* Wager banner */
        .wager-banner {
            background: linear-gradient(135deg, rgba(255,215,0,0.08), rgba(255,215,0,0.03));
            border: 1px solid rgba(255,215,0,0.2); border-radius: 14px;
            padding: 14px 20px; display: flex; align-items: center;
            justify-content: space-between; gap: 12px;
        }
        .wager-label { font-size: 0.6rem; letter-spacing: 2.5px; text-transform: uppercase; color: var(--muted); font-weight: 600; }
        .wager-amount {
            font-family: 'Bebas Neue', sans-serif; font-size: 2rem; letter-spacing: 3px;
            color: var(--gold); text-shadow: 0 0 16px var(--gold-glow); line-height: 1;
        }
        .wager-sub { font-size: 0.65rem; color: rgba(255,215,0,0.45); font-weight: 500; margin-top: 2px; }
        .wager-icon { font-size: 2rem; opacity: 0.6; }

        /* Teams */
        .teams-arena {
            display: grid; grid-template-columns: 1fr 36px 1fr;
            align-items: center; gap: 8px;
        }
        .team-card {
            background: var(--card); border: 1px solid var(--border);
            border-radius: 16px; padding: 16px 10px;
            text-align: center; position: relative; overflow: hidden;
        }
        .team-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
        .team-card.home { border-color: rgba(0,255,65,0.2); box-shadow: inset 0 0 30px rgba(0,255,65,0.03); }
        .team-card.home::before { background: linear-gradient(90deg, transparent, var(--neon), transparent); }
        .team-card.away { border-color: rgba(255,100,100,0.15); }
        .team-card.away::before { background: linear-gradient(90deg, transparent, rgba(255,100,100,0.5), transparent); }
        .team-role { font-size: 0.55rem; letter-spacing: 2.5px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 6px; }
        .team-shield { font-size: 2rem; display: block; margin-bottom: 8px; }
        .team-name { font-family: 'Bebas Neue', sans-serif; font-size: 1.05rem; letter-spacing: 1.5px; color: var(--text); line-height: 1.2; word-break: break-word; }
        .team-player { font-size: 0.65rem; color: var(--muted); margin-top: 4px; font-weight: 500; }
        .team-player.you-badge { color: var(--neon); }

        .vs-divider { display: flex; flex-direction: column; align-items: center; gap: 4px; }
        .vs-text { font-family: 'Bebas Neue', sans-serif; font-size: 1.3rem; color: #2a2a2a; letter-spacing: 2px; }
        .vs-line { width: 1px; height: 20px; background: linear-gradient(to bottom, transparent, rgba(255,255,255,0.07), transparent); }

        /* Match code */
        .match-code-strip {
            background: rgba(0,0,0,0.35); border: 1px solid var(--border);
            border-radius: 12px; padding: 12px 16px;
            display: flex; align-items: center; justify-content: space-between; gap: 10px;
        }
        .code-label { font-size: 0.58rem; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-bottom: 2px; }
        .code-value {
            font-family: 'Bebas Neue', sans-serif; font-size: 1.4rem; letter-spacing: 5px;
            color: var(--neon); text-shadow: 0 0 12px rgba(0,255,65,0.3);
        }
        .code-copy-btn {
            background: rgba(0,255,65,0.08); border: 1px solid rgba(0,255,65,0.2);
            color: var(--neon); padding: 7px 14px; border-radius: 8px;
            font-family: 'Outfit', sans-serif; font-size: 0.7rem; font-weight: 700;
            letter-spacing: 1px; cursor: pointer; text-transform: uppercase; white-space: nowrap;
            -webkit-tap-highlight-color: transparent;
        }
        .code-copy-btn:active { background: rgba(0,255,65,0.18); }

        /* Buttons */
        .war-actions { display: flex; flex-direction: column; gap: 10px; }
        .btn-report {
            width: 100%; padding: 16px;
            background: linear-gradient(135deg, var(--neon), var(--neon-dim));
            color: #000; border: none; border-radius: 14px;
            font-family: 'Outfit', sans-serif; font-weight: 800;
            font-size: 0.9rem; letter-spacing: 1.5px; text-transform: uppercase;
            cursor: pointer; box-shadow: 0 4px 20px rgba(0,255,65,0.2);
            -webkit-tap-highlight-color: transparent;
        }
        .btn-report:active { transform: scale(0.98); }
        .btn-back {
            width: 100%; padding: 13px;
            background: none; color: var(--muted);
            border: 1px solid var(--border); border-radius: 14px;
            font-family: 'Outfit', sans-serif; font-weight: 600;
            font-size: 0.82rem; letter-spacing: 1px; text-transform: uppercase;
            cursor: pointer; -webkit-tap-highlight-color: transparent;
        }
        .btn-back:active { border-color: rgba(255,255,255,0.2); color: var(--text); }
    </style>
</head>
<body>

<div class="arena-bg"></div>
<div class="grid-lines"></div>
<div class="scanlines"></div>

<div class="war-room">

    <div class="wr-header">
        <div class="wr-logo-wrap">
            <span class="wr-logo">VUMBUA · EFOOTBALL</span>
            <div class="wr-title">WAR ROOM</div>
        </div>
        <div class="live-badge">
            <span class="live-dot"></span>
            MATCH LIVE
        </div>
    </div>

    <div class="elapsed-pill">Started · <span id="elapsed-display">00:00</span> ago</div>

    <div class="wager-banner">
        <div>
            <div class="wager-label">Prize Pool at Stake</div>
            <div class="wager-amount" id="prize-display">KES —</div>
            <div class="wager-sub" id="wager-sub">Winner takes all</div>
        </div>
        <div class="wager-icon">🏆</div>
    </div>

    <div class="teams-arena">
        <div class="team-card home">
            <div class="team-role">Home</div>
            <span class="team-shield">🏟️</span>
            <div class="team-name" id="home-team">—</div>
            <div class="team-player" id="home-player">—</div>
        </div>
        <div class="vs-divider">
            <div class="vs-line"></div>
            <div class="vs-text">VS</div>
            <div class="vs-line"></div>
        </div>
        <div class="team-card away">
            <div class="team-role">Away</div>
            <span class="team-shield">⚔️</span>
            <div class="team-name" id="away-team">—</div>
            <div class="team-player" id="away-player">—</div>
        </div>
    </div>

    <div class="match-code-strip" id="match-code-strip">
        <div>
            <div class="code-label">Match Code</div>
            <div class="code-value" id="code-display">—</div>
        </div>
        <button class="code-copy-btn" onclick="copyCode()">Copy</button>
    </div>

    <div class="war-actions">
        <button class="btn-report" id="btn-report" onclick="goReport()">
            📸 Report Result &amp; Upload Screenshot
        </button>
        <button class="btn-back" onclick="goBack()">← Back to Dashboard</button>
        <button class="btn-back" onclick="forfeitMatch()" style="border-color:rgba(255,68,68,0.3);color:#ff6666;margin-top:4px">
            🏳️ Forfeit Match
        </button>
    </div>

</div>

<script>
    function escapeHtml(s) {
        if (!s) return '—';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
    }
    function qs(id) { return document.getElementById(id); }

    const authToken = sessionStorage.getItem('supabaseToken');
    if (!authToken) { window.location.href = '/login'; }

    const rawData = sessionStorage.getItem('warRoomData');
    if (!rawData) { window.location.href = '/dashboard'; }

    let matchData = {};
    try { matchData = JSON.parse(rawData); } catch(e) { window.location.href = '/dashboard'; }

    const { matchId, matchCode, creatorTeam, creatorUsername, joinerTeam, joinerUsername,
            wagerAmount, winnerPrize, startedAt, currentUserId, creatorId } = matchData;

    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const API = isLocal ? 'http://localhost:3000' : '/api';

    const isCreator = currentUserId === creatorId;
    qs('home-team').textContent   = escapeHtml(creatorTeam || 'Unknown FC');
    qs('home-player').textContent = escapeHtml(creatorUsername || '—');
    qs('away-team').textContent   = escapeHtml(joinerTeam || 'Unknown FC');
    qs('away-player').textContent = escapeHtml(joinerUsername || '—');

    if (isCreator) {
        qs('home-player').classList.add('you-badge');
        qs('home-player').textContent = '👤 ' + escapeHtml(creatorUsername) + ' (You)';
    } else {
        qs('away-player').classList.add('you-badge');
        qs('away-player').textContent = '👤 ' + escapeHtml(joinerUsername) + ' (You)';
    }

    qs('prize-display').textContent = winnerPrize ? \`KES \${winnerPrize}\` : \`KES \${(wagerAmount||0)*2}\`;
    qs('wager-sub').textContent = wagerAmount ? \`KES \${wagerAmount} staked each · Winner takes all\` : 'Winner takes all';

    qs('code-display').textContent = matchCode || '—';
    if (!matchCode) qs('match-code-strip').style.display = 'none';

    const startTime = startedAt ? new Date(startedAt) : new Date();
    function updateElapsed() {
        const diff = Math.max(0, Math.floor((Date.now() - startTime.getTime()) / 1000));
        const m = Math.floor(diff / 60).toString().padStart(2, '0');
        const s = (diff % 60).toString().padStart(2, '0');
        qs('elapsed-display').textContent = \`\${m}:\${s}\`;
    }
    updateElapsed();
    setInterval(updateElapsed, 1000);

    // ── Live status polling ──────────────────────────────────────────────────
    // Polls /friends/match-status every 10s so the war room reacts to:
    // draw → penalty_shootout, opponent forfeit, dispute, completion
    let lastStatus = 'active';
    async function pollMatchStatus() {
        if (!matchId) return;
        try {
            const res = await fetch(\`\${API}/friends/match-status/\${matchId}\`, {
                headers: { 'Authorization': \`Bearer \${authToken}\` }
            });
            if (res.status === 401) { window.location.href = '/login'; return; }
            if (!res.ok) return;
            const data = await res.json();

            if (data.status === lastStatus) return; // nothing changed
            lastStatus = data.status;

            if (data.status === 'awaiting_confirmation') {
                // Someone declared the score - redirect to dashboard to confirm/dispute
                showStatusBanner('📋 SCORE DECLARED',
                    data.iDeclared
                        ? 'Waiting for your opponent to confirm. Check the dashboard.'
                        : \`Your opponent declared \${data.myDeclaredScore ?? '?'}-\${data.opponentDeclaredScore ?? '?'}. Open the dashboard to confirm or dispute.\`,
                    '#ffb400');
                // Redirect to dashboard after 3 seconds so they can act
                if (!data.iDeclared) {
                    setTimeout(() => { window.location.href = '/dashboard'; }, 3000);
                }

            } else if (data.status === 'penalty_shootout') {
                // Show penalty instructions banner
                showStatusBanner(\`⚽ IT'S A DRAW — PENALTIES!\`,
                    \`Match drew \${data.drawScore || ''}. Go to eFootball → create a new Friends Match room → play a Penalty Shootout → come back and upload the result.\`,
                    '#ffd700');
                const reportBtn = qs('btn-report');
                if (reportBtn) reportBtn.textContent = '📸 Upload Penalty Result';

            } else if (data.status === 'completed') {
                clearInterval(statusPollTimer);
                if (data.youWon) {
                    showStatusBanner('🏆 YOU WON!',
                        \`KES \${data.winnerPrize || winnerPrize} has been credited to your wallet.\`,
                        '#00ff41');
                } else if (data.settlementMethod === 'forfeit') {
                    showStatusBanner('🏳️ MATCH FORFEITED',
                        data.statusMessage || 'Match was forfeited.',
                        '#ff8800');
                } else {
                    showStatusBanner('❌ YOU LOST',
                        'Better luck next time.',
                        '#ff4444');
                }
                setTimeout(() => { window.location.href = '/dashboard'; }, 4000);

            } else if (data.status === 'disputed') {
                clearInterval(statusPollTimer);
                showStatusBanner('⚠️ MATCH DISPUTED',
                    'An admin is reviewing this match. Check back later.',
                    '#ff8800');
            }
        } catch (err) {
            console.warn('Status poll error:', err.message);
        }
    }

    function showStatusBanner(title, message, color) {
        let banner = qs('status-banner');
        if (!banner) {
            banner = document.createElement('div');
            banner.id = 'status-banner';
            banner.style.cssText = \`
                position:fixed; top:0; left:0; right:0; z-index:999;
                padding:16px 20px; text-align:center;
                font-family:'Outfit',sans-serif; font-weight:700;
                border-bottom:2px solid currentColor;
                animation: slideDown 0.4s ease;
            \`;
            document.body.prepend(banner);
        }
        banner.style.background = \`rgba(0,0,0,0.95)\`;
        banner.style.color = color;
        banner.style.borderColor = color;
        banner.innerHTML = \`<div style="font-size:1.1rem;letter-spacing:2px">\${escapeHtml(title)}</div>
                            <div style="font-size:0.8rem;font-weight:400;margin-top:4px;color:#ccc">\${escapeHtml(message)}</div>\`;
    }

    const statusPollTimer = setInterval(pollMatchStatus, 10000);
    pollMatchStatus(); // run immediately on load
    // ────────────────────────────────────────────────────────────────────────

    function copyCode() {
        if (!matchCode) return;
        navigator.clipboard.writeText(matchCode).then(() => {
            const btn = document.querySelector('.code-copy-btn');
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        });
    }

    async function forfeitMatch() {
        if (!confirm('Are you sure you want to forfeit? Your opponent will win the wager.')) return;
        try {
            const res = await fetch(\`\${API}/friends/forfeit\`, {
                method: 'POST',
                headers: { 'Authorization': \`Bearer \${authToken}\`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ matchId })
            });
            const data = await res.json();
            if (res.ok) {
                showStatusBanner('🏳️ FORFEITED', 'You forfeited. Returning to dashboard...', '#ff8800');
                setTimeout(() => { window.location.href = '/dashboard'; }, 2500);
            } else {
                alert(data.error || 'Failed to forfeit');
            }
        } catch (err) {
            alert('Network error. Try again.');
        }
    }

    function goReport() {
        sessionStorage.setItem('openReportMatchId', matchId);
        window.location.href = '/dashboard';
    }

    function goBack() { window.location.href = '/dashboard'; }
</script>
</body>
</html>`;


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

app.get('/', (req, res) => res.type('html').send(HTML_INDEX));
app.get('/login', (req, res) => res.type('html').send(HTML_LOGIN));
app.get('/dashboard', (req, res) => res.type('html').send(HTML_DASHBOARD));
app.get('/admin', (req, res) => res.type('html').send(HTML_ADMIN));
app.get('/war-room', (req, res) => res.type('html').send(HTML_WAR_ROOM));

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