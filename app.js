// ============================================================
// VUMBUA eFOOTBALL — ENTRY POINT
// app.js
// ============================================================

'use strict';

console.log('========================================');
console.log('🚀 BOOT START:', new Date().toISOString());
console.log('   Node:', process.version);
console.log('   Platform:', process.platform);
console.log('========================================');

process.on('uncaughtException', (err) => {
    console.error('💥 UNCAUGHT EXCEPTION:', err.message, err.stack);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    console.error('💥 UNHANDLED REJECTION:', reason);
});

// ============================================================
// LOAD MODULES
// ============================================================
require('dotenv').config();
const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// ============================================================
// VALIDATE ENV VARS
// ============================================================
const REQUIRED_VARS = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'MPESA_SERVER_URL',
    'MPESA_CALLBACK_SECRET',
    'CRON_SECRET',
    'ADMIN_KEY',
];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error('❌ FATAL: Missing required env vars:', missing.join(', '));
    process.exit(1);
}

// Warn about weak secrets in production
if (process.env.NODE_ENV === 'production') {
    if ((process.env.ADMIN_KEY?.length ?? 0) < 32) {
        console.error('❌ FATAL: ADMIN_KEY must be at least 32 characters in production.');
        process.exit(1);
    }
    if ((process.env.CRON_SECRET?.length ?? 0) < 32) {
        console.error('❌ FATAL: CRON_SECRET must be at least 32 characters in production.');
        process.exit(1);
    }
    if ((process.env.MPESA_CALLBACK_SECRET?.length ?? 0) < 32) {
        console.error('❌ FATAL: MPESA_CALLBACK_SECRET must be at least 32 characters in production.');
        process.exit(1);
    }
}

if (process.env.NODE_ENV === 'production') {
    const mpesaUrl = process.env.MPESA_SERVER_URL || '';
    if (!mpesaUrl.startsWith('https://')) {
        console.error('❌ FATAL: MPESA_SERVER_URL must be an HTTPS URL in production. Got:', mpesaUrl);
        process.exit(1);
    }
}

console.log('✅ Required env vars present.');

// ============================================================
// LOAD SUPABASE
// ============================================================
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession:   false,
        }
    }
);
console.log('✅ Supabase clients created.');

// ============================================================
// BUILD EXPRESS APP
// ============================================================
const app  = express();
const port = process.env.PORT || 3000;

const { createRateLimiters, getCorsOptions, isAdmin } = require('./routes/helpers');
const limiters = createRateLimiters();

// ── Core middleware ──────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', 1);

// ── Static assets ────────────────────────────────────────────
app.use('/js', express.static(path.join(__dirname, 'public', 'js'), {
    maxAge: '1h',
    etag: true,
}));

// ── Attach Supabase clients ──────────────────────────────────
app.use((req, _res, next) => {
    req.supabase      = supabase;
    req.supabaseAdmin = supabaseAdmin;
    next();
});

// ── Strip /api prefix ────────────────────────────────────────
app.use((req, _res, next) => {
    if (req.url.startsWith('/api/')) req.url = req.url.slice(4);
    next();
});

// ── CORS ─────────────────────────────────────────────────────
app.use(getCorsOptions());

// ── Security Headers ─────────────────────────────────────────
app.use((req, res, next) => {
    const koyebUrl    = process.env.APP_SERVER_URL || '';
    const frontendUrl = process.env.FRONTEND_URL   || '';
    const supabaseUrl = process.env.SUPABASE_URL   || '';
    const supabaseWss = supabaseUrl.replace(/^https:/, 'wss:').replace(/^http:/, 'ws:');
    const mpesaUrl    = process.env.MPESA_SERVER_URL || '';
    const connectSrc  = ["'self'", koyebUrl, frontendUrl, supabaseUrl, supabaseWss, mpesaUrl]
        .filter(Boolean).join(' ');

    // Derive storage hostname from SUPABASE_URL for img-src
    // e.g. https://abc.supabase.co  →  https://abc.supabase.co
    const supabaseStorageSrc = supabaseUrl ? supabaseUrl : '';

    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        `script-src 'self' https://cdn.jsdelivr.net`,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        'font-src https://fonts.gstatic.com',
        `img-src 'self' data: blob: ${supabaseStorageSrc}`.trim(),
        `connect-src ${connectSrc}`,
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ].join('; '));

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
    next();
});

// ============================================================
// LOAD HTML PAGES
// ============================================================
function loadHtml(name) {
    const filePath = path.join(__dirname, 'public', name);
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (e) {
        console.warn(`⚠️  Could not load ${name}:`, e.message);
        return `<html><body><h1>${name} not found</h1></body></html>`;
    }
}

const HTML_INDEX     = loadHtml('index.html');
const HTML_LOGIN     = loadHtml('login.html');
const HTML_DASHBOARD = loadHtml('dashboard.html');
const HTML_ADMIN     = loadHtml('admin.html');
const HTML_WAR_ROOM  = loadHtml('war-room.html');
console.log('✅ HTML pages loaded.');

// ============================================================
// IMPORT ROUTES
// ============================================================
const authRoutes         = require('./routes/auth');
const profileRoutes      = require('./routes/profile');
const walletRoutes       = require('./routes/wallet');
const friendsRoutes      = require('./routes/friends');
const tournamentRoutes   = require('./routes/tournaments');
const notificationRoutes = require('./routes/notifications');
const adminRoutes        = require('./routes/admin');
const { router: withdrawalRouter, processMpesaWithdrawal } = require('./routes/withdrawals');

// ============================================================
// HEALTH & DEBUG ROUTES
// ============================================================
app.get('/health', (_req, res) => {
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    res.status(200).json({
        status:         'healthy',
        timestamp:      new Date().toISOString(),
        service:        'vumbua-backend',
        memory_mb:      memMB,
        uptime_seconds: Math.round(process.uptime()),
        mpesa_server:   process.env.MPESA_SERVER_URL,
    });
});

app.get('/debug/config', limiters.adminLimiter, (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    res.json({
        environment: {
            NODE_ENV:       process.env.NODE_ENV    || 'not set',
            PORT:           process.env.PORT         || 'not set',
            SUPABASE_URL:   process.env.SUPABASE_URL            ? '✅ set' : '❌ NOT SET',
            ADMIN_KEY:      process.env.ADMIN_KEY               ? '✅ set' : '❌ NOT SET',
            MPESA_SERVER:   process.env.MPESA_SERVER_URL        || '❌ NOT SET',
            CALLBACK_SECRET:process.env.MPESA_CALLBACK_SECRET   ? '✅ set' : '❌ NOT SET',
            CRON_SECRET:    process.env.CRON_SECRET             ? '✅ set' : '❌ NOT SET',
        }
    });
});

// ============================================================
// PAGE ROUTES
// ============================================================
app.get('/',          (_req, res) => res.type('html').send(HTML_INDEX));
app.get('/login',     (_req, res) => res.type('html').send(HTML_LOGIN));
app.get('/dashboard', (_req, res) => res.type('html').send(HTML_DASHBOARD));
app.get('/admin',     (_req, res) => res.type('html').send(HTML_ADMIN));
app.get('/war-room',  (_req, res) => res.type('html').send(HTML_WAR_ROOM));

// ============================================================
// API ROUTES
// ============================================================
console.log('📝 Loading API routes...');

// ── Routes mounted under /api (production) AND bare path (local dev) ──
const mountRoutes = (prefix) => {
    app.use(`${prefix}/auth/login`,  limiters.sensitiveLimiter);
    app.use(`${prefix}/auth/signup`, limiters.signupLimiter);
    app.use(`${prefix}/auth`,        authRoutes);

    app.use(`${prefix}/profile`, profileRoutes);

    app.use(`${prefix}/wallet/deposit`, limiters.depositLimiter);
    app.use(`${prefix}/wallet`,         walletRoutes);

    app.use(`${prefix}/wallet/withdrawals`, (req, _res, next) => {
        req.processMpesaWithdrawal = (id) => processMpesaWithdrawal(supabaseAdmin, id);
        next();
    }, withdrawalRouter);

    app.use(`${prefix}/tournaments`, tournamentRoutes);

    app.use(`${prefix}/friends/create-match`, limiters.matchActionLimiter);
    app.use(`${prefix}/friends/join-match`,   limiters.matchActionLimiter);
    app.use(`${prefix}/friends/forfeit`,      limiters.matchActionLimiter);
    app.use(`${prefix}/friends/submit-screenshot`, limiters.screenshotUploadLimiter);
    app.use(`${prefix}/friends`, friendsRoutes);

    app.use(`${prefix}/notifications`, notificationRoutes);

    app.use(`${prefix}/admin`, limiters.adminLimiter, adminRoutes);
};

mountRoutes('/api');   // production (Vercel frontend uses /api/...)
mountRoutes('');       // local dev (localhost:3000/auth/...)

console.log('✅ API routes loaded.');

// ============================================================
// M-PESA CALLBACK  —  idempotent, responds immediately
// ============================================================
app.post('/mpesa/callback', async (req, res) => {
    const providedSecret = req.headers['x-mpesa-secret'];
    const expectedSecret = process.env.MPESA_CALLBACK_SECRET;

    // Timing-safe comparison — skip auth if no secret is configured (dev mode)
    if (expectedSecret) {
        if (!providedSecret ||
            providedSecret.length !== expectedSecret.length ||
            !crypto.timingSafeEqual(Buffer.from(providedSecret), Buffer.from(expectedSecret))) {
            console.warn('⚠️  M-Pesa callback with invalid secret from', req.ip);
            return res.status(401).json({ ResultCode: 1, ResultDesc: 'Unauthorized' });
        }
    }

    // Always respond to M-Pesa immediately (they retry if they don't get 200 fast)
    res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });

    try {
        console.log('📲 M-Pesa callback received:', JSON.stringify(req.body));

        const body        = req.body || {};
        const stkCallback = body.Body?.stkCallback || body.stkCallback || body;
        const {
            CheckoutRequestID,
            ResultCode,
            ResultDesc,
            CallbackMetadata,
        } = stkCallback;

        if (!CheckoutRequestID) {
            console.warn('⚠️  M-Pesa callback missing CheckoutRequestID. Body:', JSON.stringify(body));
            return;
        }

        console.log(`📲 M-Pesa callback: CheckoutRequestID=${CheckoutRequestID} ResultCode=${ResultCode} Desc="${ResultDesc}"`);

        if (ResultCode === 0) {
            // ── Successful payment ─────────────────────────────
            const items   = CallbackMetadata?.Item || [];
            const amount  = items.find(i => i.Name === 'Amount')?.Value        || 0;
            const receipt = items.find(i => i.Name === 'MpesaReceiptNumber')?.Value || null;
            const phone   = items.find(i => i.Name === 'PhoneNumber')?.Value   || null;

            console.log(`💰 Payment success: amount=${amount}, receipt=${receipt}, phone=${phone}`);

            if (!receipt) {
                console.error('⚠️  M-Pesa callback missing receipt number for', CheckoutRequestID);
            }

            const { data, error: rpcErr } = await supabaseAdmin.rpc('complete_mpesa_deposit', {
                p_checkout_id: CheckoutRequestID,
                p_amount:      Number(amount),
                p_receipt:     receipt || 'NO_RECEIPT',
            });

            if (rpcErr) {
                console.error(`💥 complete_mpesa_deposit failed [${CheckoutRequestID}]:`, rpcErr.message);
            } else if (data) {
                console.log(`✅ Wallet credited: user=${data.user_id}, KES ${amount}, receipt=${receipt}`);
            } else {
                // NULL return = already processed or checkout ID not in DB (e.g. test callback)
                console.log(`ℹ️  Callback already processed or checkout not found: ${CheckoutRequestID}`);
            }

        } else {
            // ── Failed / cancelled payment ─────────────────────
            const { error: updateErr } = await supabaseAdmin
                .from('transactions')
                .update({
                    status:       'failed',
                    updated_at:   new Date().toISOString(),
                    completed_at: new Date().toISOString(),
                })
                .eq('checkout_request_id', CheckoutRequestID)
                .eq('status', 'pending');

            if (updateErr) {
                console.error(`Failed to mark transaction failed [${CheckoutRequestID}]:`, updateErr.message);
            } else {
                console.log(`❌ M-Pesa payment failed: ${CheckoutRequestID} ResultCode=${ResultCode} "${ResultDesc}"`);
            }
        }
    } catch (err) {
        console.error('💥 M-Pesa callback processing error:', err.message, err.stack);
    }
});

// ── Deposit status (alias at top-level, same as /wallet/deposit/status) ──
app.get('/mpesa/status', async (req, res) => {
    const { checkoutId } = req.query;
    if (!checkoutId || typeof checkoutId !== 'string' || checkoutId.length > 100) {
        return res.status(400).json({ error: 'checkoutId required' });
    }

    const { data } = await supabaseAdmin
        .from('transactions')
        .select('status, mpesa_receipt')
        .eq('checkout_request_id', checkoutId)
        .maybeSingle();

    res.json({ status: data?.status || 'pending', mpesaReceipt: data?.mpesa_receipt || null });
});

// ============================================================
// CRON ENDPOINT (header-only)
// ============================================================
app.get('/cron/resolve-matches', async (req, res) => {
    // Vercel crons call with Authorization: Bearer <CRON_SECRET>
    // Also support x-cron-secret header for manual/local calls
    const authHeader = req.headers['authorization'];
    const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const cronSecret = bearerToken || req.headers['x-cron-secret'];

    if (!cronSecret || cronSecret !== process.env.CRON_SECRET) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const {
            markExpiredMatches,
            purgeExpiredScreenshots
        } = require('./jobs/matchJobs');

        const start = Date.now();
        await markExpiredMatches(supabaseAdmin);
        await purgeExpiredScreenshots(supabaseAdmin);

        res.json({
            ok:       true,
            ran:      ['markExpiredMatches', 'purgeExpiredScreenshots'],
            at:       new Date().toISOString(),
            duration: `${Date.now() - start}ms`,
        });
    } catch (err) {
        console.error('Cron job error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// 404 HANDLER
// ============================================================
app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
    console.error('💥 Unhandled Express error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================================
// BACKGROUND JOBS  (non-Vercel only)
// ============================================================
const IS_VERCEL = !!(process.env.VERCEL || process.env.VERCEL_ENV || process.env.NOW_REGION);

if (!IS_VERCEL) {
    const {
        markExpiredMatches,
        purgeExpiredScreenshots
    } = require('./jobs/matchJobs');

    // Run every 10 minutes
    setInterval(() => markExpiredMatches(supabaseAdmin),  10 * 60 * 1000);
    setTimeout(()  => markExpiredMatches(supabaseAdmin), 15_000);

    // Run every 30 minutes
    setInterval(() => purgeExpiredScreenshots(supabaseAdmin), 30 * 60 * 1000);
    setTimeout(()  => purgeExpiredScreenshots(supabaseAdmin), 20_000);

    const host      = '::';
    const finalPort = process.env.PORT || 3000;

    const server = app.listen(finalPort, host, () => {
        console.log('========================================');
        console.log(`✅ Vumbua running on ${host}:${finalPort}`);
        console.log(`   M-Pesa server: ${process.env.MPESA_SERVER_URL}`);
        console.log('========================================');
    });

    server.timeout          = 90_000;
    server.headersTimeout   = 95_000;
    server.keepAliveTimeout = 65_000;
} else {
    console.log('ℹ️  Running on Vercel — skipping app.listen and background jobs.');
}

module.exports = app;