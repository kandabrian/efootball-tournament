// ============================================================
// SHARED HELPER FUNCTIONS
// routes/helpers.js
// ============================================================

'use strict';

const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// ============================================================
// CONSTANTS
// ============================================================
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

// Allowed Supabase storage bucket/path prefix for screenshots
const SCREENSHOT_BUCKET_PATH_PREFIX = 'match-screenshots/';
const PENALTY_BUCKET_PATH_PREFIX    = 'match-challenges/';

// ============================================================
// PHONE NORMALIZATION
// ============================================================
function normalizePhone(phone) {
    if (!phone || typeof phone !== 'string') {
        console.warn('⚠️ Invalid phone type:', typeof phone);
        return null;
    }
    if (phone.length > 30) {
        console.warn('⚠️ Phone number too long');
        return null;
    }
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 0) {
        console.warn('⚠️ Phone number has no digits');
        return null;
    }

    let normalized = null;

    // +254XXXXXXXXX  (12 digits starting with 254)
    if (cleaned.startsWith('254') && cleaned.length === 12) {
        normalized = '+' + cleaned;
    }
    // 0XXXXXXXXX  (10 digits starting with 0)
    else if (cleaned.startsWith('0') && cleaned.length === 10) {
        normalized = '+254' + cleaned.slice(1);
    }
    // XXXXXXXXX  (9 digits)
    else if (cleaned.length === 9) {
        normalized = '+254' + cleaned;
    }
    else {
        console.warn('⚠️ Invalid phone format:', cleaned.slice(0, 4) + '...');
        return null;
    }

    // Validate Safaricom/Airtel prefix (1xx or 7xx)
    const prefix = normalized.substring(4, 5); // digit after +254
    if (!['1', '7'].includes(prefix)) {
        console.warn('⚠️ Invalid Kenya number prefix:', prefix);
        return null;
    }

    return normalized;
}

// ============================================================
// eFOOTBALL CODE VALIDATION
// ============================================================
function validateEFootballCode(code) {
    if (!code || typeof code !== 'string') return false;
    return /^[A-Z0-9]{4,8}$/.test(code.toUpperCase());
}

// ============================================================
// UUID VALIDATION
// ============================================================
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUUID(str) {
    return typeof str === 'string' && UUID_REGEX.test(str);
}

// ============================================================
// EXTRACT TEAM NAMES FROM OCR TEXT
// ============================================================
function extractTeamNames(ocrText) {
    if (!ocrText || typeof ocrText !== 'string') {
        return { home: null, away: null };
    }
    const textUpper = ocrText.toUpperCase();
    const foundTeams = [];

    for (const team of EFOOTBALL_TEAMS) {
        const teamUpper = team.toUpperCase();
        if (textUpper.includes(teamUpper)) {
            foundTeams.push({ name: team, position: textUpper.indexOf(teamUpper) });
        }
    }

    foundTeams.sort((a, b) => a.position - b.position);

    return {
        home:     foundTeams.length > 0 ? foundTeams[0].name : null,
        away:     foundTeams.length > 1 ? foundTeams[1].name : null,
        allFound: foundTeams.map(t => t.name)
    };
}

// ============================================================
// ADMIN CHECK  —  timing-safe comparison (fixes F-10)
// ============================================================
function isAdmin(req) {
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) return false;

    const provided = req.headers['x-admin-key'];
    if (!provided) return false;

    try {
        const a = Buffer.from(provided);
        const b = Buffer.from(adminKey);
        // Lengths must match before timingSafeEqual (different-length always false)
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

// ============================================================
// GENERIC ERROR RESPONSE
// — never exposes internal error details to the client
// ============================================================
function sendGenericError(res, statusCode, message, internalError) {
    // Log internally only — message is safe for client
    if (internalError) {
        console.error('Internal error [' + statusCode + ']:', internalError?.message || String(internalError));
    }
    res.status(statusCode).json({ error: message });
}

// ============================================================
// GET AUTH USER FROM JWT
// ============================================================
async function getAuthUser(supabase, jwt) {
    const { data: { user }, error } = await supabase.auth.getUser(jwt);
    return { user: user || null, error: error || null };
}

// ============================================================
// VALIDATE SCREENSHOT URL  (fixes F-09)
// — Only accepts URLs whose hostname exactly equals or is a
//   subdomain of STORAGE_DOMAIN.  Prevents the endsWith bypass
//   where evil-supabase.co would have matched supabase.co.
// ============================================================
function isValidScreenshotUrl(url) {
    try {
        const parsed = new URL(url);
        const storageDomain = process.env.STORAGE_DOMAIN || 'supabase.co';

        if (parsed.protocol !== 'https:') {
            console.warn('❌ Screenshot URL must use HTTPS:', url);
            return false;
        }

        const host = parsed.hostname.toLowerCase();
        const domain = storageDomain.toLowerCase();

        // Must be exactly the domain OR a proper subdomain (*.domain)
        const hostOk = host === domain || host.endsWith('.' + domain);
        if (!hostOk) {
            console.warn('❌ Screenshot URL from unauthorized domain:', parsed.hostname);
            return false;
        }

        // Path must start with a known storage bucket prefix
        const path = parsed.pathname;
        const validPath =
            path.includes('/' + SCREENSHOT_BUCKET_PATH_PREFIX) ||
            path.includes('/' + PENALTY_BUCKET_PATH_PREFIX)    ||
            path.includes('/storage/v1/object/public/screenshots/');

        if (!validPath) {
            console.warn('❌ Screenshot URL path not in allowed bucket:', path);
            return false;
        }

        return true;
    } catch {
        console.warn('❌ Invalid screenshot URL:', url);
        return false;
    }
}

// ============================================================
// RATE LIMITERS
// ============================================================
function createRateLimiters() {
    const rateLimit = require('express-rate-limit');

    return {
        signupLimiter: rateLimit({
            windowMs: 60 * 60 * 1000,   // 1 hour
            max: 5,
            message: { error: 'Too many accounts created from this IP. Try again later.' },
            standardHeaders: true,
            legacyHeaders: false
        }),
        // Used for login and other sensitive auth actions
        sensitiveLimiter: rateLimit({
            windowMs: 15 * 60 * 1000,   // 15 min
            max: 10,
            message: { error: 'Too many requests. Try again later.' },
            standardHeaders: true,
            legacyHeaders: false
        }),
        depositLimiter: rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 5,
            message: { error: 'Too many deposit attempts. Try again later.' },
            standardHeaders: true,
            legacyHeaders: false
        }),
        screenshotUploadLimiter: rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 15,
            message: { error: 'Too many screenshot uploads. Try again later.' }
        }),
        adminLimiter: rateLimit({
            windowMs: 60 * 1000,
            max: 60,
            message: { error: 'Admin rate limit exceeded. Try again later.' },
            keyGenerator: (req) => req.ip,
            // Skip counting for valid admin requests so legitimate heavy use is unaffected
            skip: (req) => isAdmin(req)
        }),
        // Per-IP match action limiter — protects create/join from abuse
        matchActionLimiter: rateLimit({
            windowMs: 60 * 1000,        // 1 min
            max: 20,
            message: { error: 'Too many match actions. Slow down.' },
            standardHeaders: true,
            legacyHeaders: false
        }),
    };
}

// ============================================================
// CORS CONFIG
// ============================================================
function getCorsOptions() {
    const cors = require('cors');

    const allowedOrigins = [
        process.env.FRONTEND_URL,
        process.env.APP_SERVER_URL,
        process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : null,
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'http://localhost:3000'
    ].filter(Boolean);

    return cors({
        origin: function (origin, callback) {
            if (!origin) return callback(null, true);
            if (
                allowedOrigins.indexOf(origin) !== -1 ||
                process.env.NODE_ENV === 'development' ||
                (process.env.VERCEL_URL && origin.includes('vercel.app'))
            ) {
                callback(null, true);
            } else {
                console.warn('⚠️  CORS blocked origin:', origin);
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
    });
}

// ============================================================
// NOTIFICATION HELPER
// ============================================================
async function sendMatchNotification(supabaseAdmin, matchId, recipientId, type, payload = {}) {
    try {
        await supabaseAdmin.from('match_notifications').insert([{
            match_id:     matchId,
            recipient_id: recipientId,
            type,
            payload:      JSON.stringify(payload),
            read:         false,
            created_at:   new Date().toISOString()
        }]);
    } catch (e) {
        console.error(`sendMatchNotification error [${matchId}/${type}]:`, e.message);
    }
}

// ============================================================
// EXPORTS
// ============================================================
module.exports = {
    EFOOTBALL_TEAMS,
    normalizePhone,
    validateEFootballCode,
    isValidUUID,
    extractTeamNames,
    isAdmin,
    sendGenericError,
    getAuthUser,
    isValidScreenshotUrl,
    getCorsOptions,
    sendMatchNotification,
    createRateLimiters,
};