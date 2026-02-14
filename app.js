const ScreenshotVerifier = require('./screenshot-verifier');
require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Validate env
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('FATAL: Missing Supabase keys in .env file');
    process.exit(1);
}

if (!process.env.MPESA_SERVER_URL) {
    console.error('FATAL: Missing MPESA_SERVER_URL in .env file');
    process.exit(1);
}

// Clients
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Initialize screenshot verifier with admin client
const verifier = new ScreenshotVerifier(supabaseAdmin);

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
    return req.headers['x-admin-key'] === process.env.ADMIN_KEY;
}

// Generate secure match code (VUM-XXXX)
function generateMatchCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = 'VUM-';
    for (let i = 0; i < 4; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// Middleware
app.set('trust proxy', 1); // Trust first proxy (required for rate limiting behind reverse proxy)

// CORS configuration - Allow your Vercel frontend to communicate with Koyeb backend
const allowedOrigins = [
    process.env.FRONTEND_URL, // Your Vercel URL from .env
    'http://localhost:5500', // For local development
    'http://127.0.0.1:5500'
].filter(Boolean); // Remove undefined values

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, Postman, or server-to-server)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));

app.use(express.json());
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://*.supabase.co");
    next();
});
app.use(express.static('public'));

// ============== PAGE ROUTES ==============
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'vumbua-backend'
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ============== AUTH ROUTES ==============
app.post('/auth/signup', async (req, res) => {
    let { phone, password, username } = req.body;
    if (!phone || !password || !username) return res.status(400).json({ error: 'Missing fields.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    phone = normalizePhone(phone);
    if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

    const { data, error } = await supabase.auth.signUp({
        phone, password, options: { data: { username } }
    });

    if (error) return res.status(error.status || 400).json({ error: error.message });

    if (data.user) {
        await supabaseAdmin.from('profiles').upsert([{ id: data.user.id, username }]);
        await supabaseAdmin.from('wallets').upsert([{ user_id: data.user.id, balance: 0 }]);
    }

    res.status(200).json({ message: "Signup successful!", user: data.user });
});

app.post('/auth/login', async (req, res) => {
    let { phone, password } = req.body;
    phone = normalizePhone(phone);
    const { data, error } = await supabase.auth.signInWithPassword({ phone, password });
    if (error) return res.status(400).json({ error: error.message });
    res.status(200).json({ message: "Login successful!", session: data.session });
});

// ============== WALLET ROUTES ==============
app.get('/wallet/balance', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabase.auth.getUser(jwt);
    if (error || !user) return res.status(401).json({ error: 'Invalid session' });

    const { data } = await supabase.from('wallets').select('balance').eq('user_id', user.id).single();
    res.json({ balance: data ? data.balance : 0 });
});

// ============== TOURNAMENT JOIN ==============
app.post('/tournament/join', sensitiveLimiter, async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    const { tournamentId, entryFee, paymentMethod, checkoutId } = req.body;

    try {
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

// ============== PLAY WITH FRIENDS ROUTES ==============

/**
 * CREATE FRIEND MATCH
 */
app.post('/friends/create-match', sensitiveLimiter, async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    const { wagerAmount } = req.body;
    
    if (!wagerAmount || isNaN(wagerAmount) || wagerAmount < 50) {
        return res.status(400).json({ error: 'Minimum wager is KES 50' });
    }

    try {
        // Check user balance
        const { data: wallet } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .single();

        if (!wallet || wallet.balance < wagerAmount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Generate unique match code
        let matchCode;
        let attempts = 0;
        let unique = false;

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
        if (!unique) {
            return res.status(500).json({ error: 'Failed to generate unique code' });
        }

        // Create match with 30-minute expiry
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const platformFee = Math.floor(wagerAmount * 0.10); // 10% platform fee
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

        // Deduct wager from creator's wallet
        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: wagerAmount
        });

        if (deductErr) {
            // Rollback: delete the match
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

/**
 * JOIN FRIEND MATCH
 */
app.post('/friends/join-match', sensitiveLimiter, async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    const { matchCode } = req.body;
    
    if (!matchCode) {
        return res.status(400).json({ error: 'Match code is required' });
    }

    try {
        // Fetch the match
        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('match_code', matchCode.toUpperCase())
            .single();

        if (matchErr || !match) {
            return res.status(404).json({ error: 'Invalid match code' });
        }

        // Validate match status
        if (match.status !== 'pending') {
            return res.status(400).json({ error: 'Match already started or completed' });
        }

        // Check expiry
        if (new Date(match.expires_at) < new Date()) {
            await supabaseAdmin
                .from('friend_matches')
                .update({ status: 'expired' })
                .eq('id', match.id);
            return res.status(400).json({ error: 'Match code has expired' });
        }

        // Prevent self-join
        if (match.creator_id === user.id) {
            return res.status(400).json({ error: 'You cannot join your own match' });
        }

        // Check if already joined
        if (match.joiner_id) {
            return res.status(400).json({ error: 'Match already has two players' });
        }

        // Check joiner's balance
        const { data: wallet } = await supabase
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .single();

        if (!wallet || wallet.balance < match.wager_amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Deduct wager from joiner's wallet
        const { error: deductErr } = await supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: match.wager_amount
        });

        if (deductErr) {
            return res.status(400).json({ error: 'Failed to deduct wager from wallet' });
        }

        // Update match with joiner
        const { data: updatedMatch, error: updateErr } = await supabaseAdmin
            .from('friend_matches')
            .update({
                joiner_id: user.id,
                status: 'active',
                started_at: new Date().toISOString()
            })
            .eq('id', match.id)
            .select()
            .single();

        if (updateErr) {
            // Rollback: refund joiner
            await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: user.id,
                p_amount: match.wager_amount
            });
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

/**
 * SUBMIT MATCH RESULT with screenshot verification
 */
app.post('/friends/submit-result', sensitiveLimiter, async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    const { matchId, winnerId, screenshotUrl } = req.body;
    
    if (!matchId || !winnerId) {
        return res.status(400).json({ error: 'Match ID and winner ID are required' });
    }

    try {
        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) {
            return res.status(404).json({ error: 'Match not found' });
        }

        // Validate user is part of this match
        if (match.creator_id !== user.id && match.joiner_id !== user.id) {
            return res.status(403).json({ error: 'You are not part of this match' });
        }

        // Validate match is active
        if (match.status !== 'active') {
            return res.status(400).json({ error: 'Match is not active' });
        }

        // Validate winner is one of the players
        if (winnerId !== match.creator_id && winnerId !== match.joiner_id) {
            return res.status(400).json({ error: 'Invalid winner ID' });
        }

        // --- Screenshot verification (if URL provided) ---
        let verificationResult = null;
        if (screenshotUrl) {
            try {
                const response = await fetch(screenshotUrl);
                if (!response.ok) throw new Error('Failed to fetch screenshot');
                const buffer = Buffer.from(await response.arrayBuffer());

                verificationResult = await verifier.verifyScreenshot(buffer, {
                    userId: user.id,
                    matchId,
                    startedAt: match.started_at
                });

                // If verification fails with high fraud score, automatically mark as disputed
                if (!verificationResult.isValid || verificationResult.fraudScore >= 50) {
                    await supabaseAdmin
                        .from('friend_matches')
                        .update({
                            status: 'disputed',
                            disputed_at: new Date().toISOString(),
                            dispute_reason: 'Suspicious screenshot',
                            verification_data: verificationResult
                        })
                        .eq('id', matchId);

                    return res.status(409).json({
                        error: 'Screenshot verification failed. Match marked for admin review.',
                        verification: verificationResult
                    });
                }
            } catch (fetchErr) {
                console.error('Screenshot fetch/verify error:', fetchErr);
                // Optionally still allow submission but log warning
            }
        }

        // Check if this is the first or second submission
        if (!match.reported_winner_id) {
            // First submission
            await supabaseAdmin
                .from('friend_matches')
                .update({
                    reported_winner_id: winnerId,
                    reported_by_id: user.id,
                    screenshot_url: screenshotUrl,
                    verification_data: verificationResult,
                    reported_at: new Date().toISOString()
                })
                .eq('id', matchId);

            res.status(200).json({
                message: 'Result submitted. Waiting for opponent confirmation.',
                requiresConfirmation: true,
                verification: verificationResult
            });

        } else {
            // Second submission - check if results match
            if (match.reported_winner_id !== winnerId) {
                // Dispute!
                await supabaseAdmin
                    .from('friend_matches')
                    .update({
                        status: 'disputed',
                        disputed_at: new Date().toISOString(),
                        dispute_reason: 'Reported winners do not match'
                    })
                    .eq('id', matchId);

                return res.status(409).json({
                    error: 'Results do not match. Match marked for admin review.',
                    requiresAdminReview: true
                });
            }

            // Results match! Process payout
            const { error: payoutErr } = await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: winnerId,
                p_amount: match.winner_prize
            });

            if (payoutErr) {
                console.error('Payout error:', payoutErr);
                return res.status(500).json({ error: 'Failed to process payout' });
            }

            // Update match as completed
            await supabaseAdmin
                .from('friend_matches')
                .update({
                    winner_id: winnerId,
                    status: 'completed',
                    completed_at: new Date().toISOString()
                })
                .eq('id', matchId);

            // --- Store perceptual hash and device info for future duplicate checks ---
            if (verificationResult && verificationResult.checks.duplicate?.details?.hash) {
                const hash = verificationResult.checks.duplicate.details.hash;
                await supabaseAdmin
                    .from('screenshot_hashes')
                    .insert([{
                        hash,
                        user_id: winnerId, // or user.id? The user who submitted the screenshot
                        match_id: matchId
                    }])
                    .onConflict('hash') // ignore if already exists (should not happen)
                    .ignore();
            }

            if (verificationResult && verificationResult.checks.device?.details?.device) {
                const device = verificationResult.checks.device.details.device;
                await supabaseAdmin
                    .from('user_screenshot_history')
                    .insert([{
                        user_id: winnerId,
                        device,
                        match_id: matchId
                    }]);
            }

            res.status(200).json({
                message: 'Match completed! Winner has been paid.',
                winnerId,
                prizePaid: match.winner_prize,
                verification: verificationResult
            });
        }

    } catch (err) {
        console.error('Submit result error:', err);
        res.status(500).json({ error: 'Failed to submit result' });
    }
});

/**
 * GET MY FRIEND MATCHES
 */
app.get('/friends/my-matches', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    try {
        const { data: matches, error } = await supabaseAdmin
            .from('friend_matches')
            .select(`
                *,
                creator:profiles!friend_matches_creator_id_fkey(username),
                joiner:profiles!friend_matches_joiner_id_fkey(username)
            `)
            .or(`creator_id.eq.${user.id},joiner_id.eq.${user.id}`)
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) throw error;

        res.json(matches || []);

    } catch (err) {
        console.error('Fetch matches error:', err);
        res.status(500).json({ error: 'Failed to fetch matches' });
    }
});

/**
 * CANCEL MATCH (Only creator can cancel pending matches)
 */
app.post('/friends/cancel-match', sensitiveLimiter, async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    const jwt = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

    const { matchId } = req.body;

    try {
        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) {
            return res.status(404).json({ error: 'Match not found' });
        }

        // Only creator can cancel
        if (match.creator_id !== user.id) {
            return res.status(403).json({ error: 'Only match creator can cancel' });
        }

        // Can only cancel pending matches
        if (match.status !== 'pending') {
            return res.status(400).json({ error: 'Can only cancel pending matches' });
        }

        // Refund creator
        await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: user.id,
            p_amount: match.wager_amount
        });

        // Update match status
        await supabaseAdmin
            .from('friend_matches')
            .update({
                status: 'cancelled',
                cancelled_at: new Date().toISOString()
            })
            .eq('id', matchId);

        res.status(200).json({
            message: 'Match cancelled and wager refunded',
            refundedAmount: match.wager_amount
        });

    } catch (err) {
        console.error('Cancel match error:', err);
        res.status(500).json({ error: 'Failed to cancel match' });
    }
});

// ============== WALLET DEPOSIT/WITHDRAW ALIASES ==============
// Dashboard calls /wallet/deposit and /wallet/deposit/status
// These duplicate the /mpesa/* handlers so both paths work

async function handleDeposit(req, res) {
    let { phone, amount, description } = req.body;
    if (!phone || !amount || isNaN(amount) || amount < 10)
        return res.status(400).json({ error: 'Invalid request. Min deposit KES 10.' });

    phone = normalizePhone(phone);
    if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

    const jwt = req.headers['authorization']?.replace('Bearer ', '');
    const { data: { user } } = await supabase.auth.getUser(jwt);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });

    try {
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
            phone,
            user_id: user.id,
            status: 'pending'
        }]);

        res.status(200).json({ message: 'STK push sent!', checkoutId: checkoutRequestId, checkoutRequestId });
    } catch (err) {
        console.error('Deposit error:', err.message);
        res.status(500).json({ error: err.message || 'Failed to initiate deposit.' });
    }
}

app.post('/wallet/deposit', depositLimiter, handleDeposit);

app.get('/wallet/deposit/status', async (req, res) => {
    const { checkoutId } = req.query;
    if (!checkoutId) return res.status(400).json({ error: 'checkoutId is required' });
    const { data } = await supabaseAdmin
        .from('transactions')
        .select('status, mpesa_receipt')
        .eq('checkout_request_id', checkoutId)
        .single();
    res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt || null });
});

// ============== M-PESA ROUTES ==============
app.post('/mpesa/deposit', depositLimiter, handleDeposit); // uses shared handleDeposit function

app.post('/mpesa/callback', async (req, res) => {
    try {
        const { Body } = req.body;
        const { stkCallback } = Body || {};
        const { CheckoutRequestID, ResultCode, CallbackMetadata } = stkCallback || {};

        if (ResultCode === 0 && CallbackMetadata) {
            const items = CallbackMetadata.Item || [];
            const amountItem = items.find(i => i.Name === 'Amount');
            const receiptItem = items.find(i => i.Name === 'MpesaReceiptNumber');
            const phoneItem = items.find(i => i.Name === 'PhoneNumber');

            const amount = amountItem?.Value || 0;
            const receipt = receiptItem?.Value || 'N/A';
            const phone = normalizePhone(phoneItem?.Value?.toString() || '');

            const { data: txn } = await supabaseAdmin
                .from('transactions')
                .select('user_id')
                .eq('checkout_request_id', CheckoutRequestID)
                .single();

            if (txn && txn.user_id) {
                await supabaseAdmin.rpc('credit_wallet', {
                    p_user_id: txn.user_id,
                    p_amount: amount
                });

                await supabaseAdmin.from('transactions').update({
                    status: 'completed',
                    mpesa_receipt: receipt,
                    completed_at: new Date().toISOString()
                }).eq('checkout_request_id', CheckoutRequestID);
            } else {
                console.error('No user_id found for transaction:', CheckoutRequestID);
            }
        } else {
            await supabaseAdmin.from('transactions').update({
                status: 'failed',
                completed_at: new Date().toISOString()
            }).eq('checkout_request_id', CheckoutRequestID);
        }

        res.status(200).json({ ResultCode: 0, ResultDesc: 'Success' });
    } catch (err) {
        console.error('Callback error:', err);
        res.status(500).json({ error: 'Callback failed' });
    }
});

app.get('/mpesa/status', async (req, res) => {
    const { checkoutId } = req.query;
    const { data } = await supabase.from('transactions').select('status, mpesa_receipt').eq('checkout_request_id', checkoutId).single();
    res.json({ status: data ? data.status : 'pending', mpesaReceipt: data?.mpesa_receipt });
});

// ============== WITHDRAW ROUTES ==============
app.post('/wallet/withdraw', sensitiveLimiter, async (req, res) => {
    const jwt = req.headers['authorization']?.replace('Bearer ', '');
    const { data: { user }, error: authErr } = await supabase.auth.getUser(jwt);
    if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

    let { amount, phone, name } = req.body;
    if (!amount || !phone || !name || isNaN(amount) || amount < 100) return res.status(400).json({ error: 'Invalid details.' });
    phone = normalizePhone(phone);

    try {
        const referenceId = 'WD-' + Date.now().toString(36).toUpperCase();

        const { error: rpcErr } = await supabase.rpc('request_withdrawal', {
            p_user_id: user.id,
            p_amount: Math.floor(Number(amount)),
            p_phone: phone,
            p_name: name,
            p_ref_id: referenceId
        });

        if (rpcErr) return res.status(400).json({ error: rpcErr.message });

        res.status(200).json({ message: 'Request received.', referenceId, amount });
    } catch (err) {
        res.status(500).json({ error: 'System error. Try again.' });
    }
});

// ============== ADMIN SECURED ROUTES ==============
app.get('/admin/withdrawals', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    const { status } = req.query;
    let query = supabaseAdmin.from('withdrawals').select('*').order('created_at', { ascending: true });
    if (status) query = query.eq('status', status);
    
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.patch('/admin/withdrawals/:id/paid', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    const { data, error } = await supabaseAdmin.from('withdrawals')
        .update({ status: 'paid', mpesa_code: req.body.mpesaCode, paid_at: new Date().toISOString() })
        .eq('id', req.params.id).select().single();
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Paid.', withdrawal: data });
});

app.patch('/admin/withdrawals/:id/reject', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { data: wd } = await supabaseAdmin.from('withdrawals').select('*').eq('id', req.params.id).single();
    if (!wd || wd.status !== 'pending') return res.status(400).json({ error: 'Invalid state' });

    const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', {
        p_user_id: wd.user_id,
        p_amount: wd.amount
    });
    if (refundErr) return res.status(500).json({ error: refundErr.message });

    const { data, error } = await supabaseAdmin.from('withdrawals')
        .update({ status: 'rejected', reject_reason: req.body.reason, rejected_at: new Date().toISOString() })
        .eq('id', req.params.id).select().single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Rejected and refunded.', withdrawal: data });
});

// ============== ADMIN TOURNAMENT ROUTES ==============
app.get('/admin/tournaments', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { data, error } = await supabaseAdmin
        .from('tournaments')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.get('/admin/tournaments/:id', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { data, error } = await supabaseAdmin
        .from('tournaments')
        .select('*')
        .eq('id', req.params.id)
        .single();
    
    if (error) return res.status(404).json({ error: 'Tournament not found' });
    res.json(data);
});

app.post('/admin/tournaments', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
    
    if (!name || !entry_fee || !start_time || !max_players) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const { data, error } = await supabaseAdmin
        .from('tournaments')
        .insert([{
            name,
            entry_fee,
            start_time,
            max_players,
            room_code: room_code || null,
            status: status || 'open'
        }])
        .select()
        .single();
    
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data);
});

app.patch('/admin/tournaments/:id', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
    
    const { data, error } = await supabaseAdmin
        .from('tournaments')
        .update({
            name,
            entry_fee,
            start_time,
            max_players,
            room_code,
            status,
            updated_at: new Date().toISOString()
        })
        .eq('id', req.params.id)
        .select()
        .single();
    
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.delete('/admin/tournaments/:id', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { error } = await supabaseAdmin
        .from('tournaments')
        .delete()
        .eq('id', req.params.id);
    
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: 'Tournament deleted' });
});

// ============== ADMIN FRIEND MATCHES ==============
app.get('/admin/friend-matches', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { status } = req.query;
    let query = supabaseAdmin
        .from('friend_matches')
        .select(`
            *,
            creator:profiles!friend_matches_creator_id_fkey(username),
            joiner:profiles!friend_matches_joiner_id_fkey(username),
            winner:profiles!friend_matches_winner_id_fkey(username)
        `)
        .order('created_at', { ascending: false });
    
    if (status && status !== 'all') query = query.eq('status', status);
    
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
});

app.post('/admin/resolve-dispute/:matchId', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    
    const { winnerId } = req.body;
    const { matchId } = req.params;
    
    if (!winnerId) {
        return res.status(400).json({ error: 'Winner ID is required' });
    }
    
    try {
        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', matchId)
            .single();
        
        if (matchErr || !match) {
            return res.status(404).json({ error: 'Match not found' });
        }
        
        if (match.status !== 'disputed') {
            return res.status(400).json({ error: 'Match is not disputed' });
        }
        
        // Pay winner
        await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: winnerId,
            p_amount: match.winner_prize
        });
        
        // Update match
        await supabaseAdmin
            .from('friend_matches')
            .update({
                winner_id: winnerId,
                status: 'completed',
                completed_at: new Date().toISOString(),
                resolved_by_admin: true
            })
            .eq('id', matchId);
        
        res.json({ message: 'Dispute resolved and winner paid' });
        
    } catch (err) {
        console.error('Resolve dispute error:', err);
        res.status(500).json({ error: 'Failed to resolve dispute' });
    }
});

// ============== PUBLIC TOURNAMENT ROUTES ==============
app.get('/tournaments', async (req, res) => {
    try {
        const { data: tournaments, error } = await supabaseAdmin
            .from('tournaments')
            .select(`
                *,
                bookings:bookings(count)
            `)
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

// ============== START SERVER ==============
app.listen(port, () => {
    console.log(`✅ Vumbua Game running on port ${port}`);
});