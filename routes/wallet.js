// ============================================================
// WALLET ROUTES
// routes/wallet.js
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { normalizePhone, sendGenericError, getAuthUser } = require('./helpers');

const MAX_DEPOSIT_AMOUNT = 50_000; // KES
const MIN_DEPOSIT_AMOUNT = 10;     // KES

// ============================================================
// GET BALANCE
// ============================================================
router.get('/balance', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { user, error } = await getAuthUser(req.supabase, jwt);
        if (error || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data, error: dbErr } = await req.supabaseAdmin
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .maybeSingle();

        if (dbErr) throw dbErr;

        res.json({ balance: data ? data.balance : 0 });

    } catch (err) {
        console.error('Balance error:', err.message);
        return sendGenericError(res, 500, 'Failed to fetch balance', err);
    }
});

// ============================================================
// DEPOSIT  —  initiates M-Pesa STK Push
// ============================================================
router.post('/deposit', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        let { phone, amount, description } = req.body;

        // ── Validate amount ──────────────────────────────────────
        const parsedAmount = Number(amount);
        if (!phone || !amount || isNaN(parsedAmount) || parsedAmount < MIN_DEPOSIT_AMOUNT) {
            return res.status(400).json({ error: `Invalid request. Min deposit KES ${MIN_DEPOSIT_AMOUNT}.` });
        }
        if (parsedAmount > MAX_DEPOSIT_AMOUNT) {
            return res.status(400).json({ error: `Max deposit is KES ${MAX_DEPOSIT_AMOUNT.toLocaleString()}.` });
        }

        // ── Validate phone ───────────────────────────────────────
        phone = normalizePhone(phone);
        if (!phone) return res.status(400).json({ error: 'Invalid phone number.' });

        // ── Sanitize description ─────────────────────────────────
        const safeDescription = typeof description === 'string'
            ? description.replace(/[^a-zA-Z0-9 _-]/g, '').slice(0, 100)
            : 'Vumbua Deposit';

        // ── Initiate STK Push via M-Pesa server ──────────────────
        const mpesaBase = process.env.MPESA_SERVER_URL || 'https://mpesa-stk-indol.vercel.app';
        const mpesaUrl = `${mpesaBase}/pay`;
        console.log(`[Wallet] Initiating STK push → ${mpesaUrl} for user=${user.id} amount=${parsedAmount}`);

        let mpesaRes;
        try {
            mpesaRes = await fetch(mpesaUrl, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({
                    phone:       phone.replace('+', ''),
                    amount:      String(Math.floor(parsedAmount)),
                    description: safeDescription,
                }),
                signal: AbortSignal.timeout(30_000),
            });
        } catch (fetchErr) {
            console.error('[Wallet] STK fetch error:', fetchErr.message);
            return res.status(502).json({ error: 'Could not reach M-Pesa server. Please try again.' });
        }

        if (!mpesaRes.ok) {
            const errData = await mpesaRes.json().catch(() => ({}));
            const errMsg  = errData.error || errData.message || `STK request failed (HTTP ${mpesaRes.status})`;
            console.error('[Wallet] STK error response:', errMsg);
            return res.status(502).json({ error: errMsg });
        }

        const mpesaData = await mpesaRes.json();

        // Support various field name conventions from M-Pesa servers
        const checkoutRequestId = mpesaData.CheckoutRequestID
            || mpesaData.checkoutId
            || mpesaData.checkout_request_id
            || mpesaData.data?.CheckoutRequestID;

        const merchantRequestId = mpesaData.MerchantRequestID
            || mpesaData.merchant_request_id
            || mpesaData.data?.MerchantRequestID
            || 'N/A';

        if (!checkoutRequestId) {
            console.error('[Wallet] STK response missing CheckoutRequestID:', JSON.stringify(mpesaData));
            return res.status(502).json({ error: 'M-Pesa did not return a checkout ID. Please try again.' });
        }

        // ── Record pending transaction ───────────────────────────
        const { error: insertErr } = await req.supabaseAdmin.from('transactions').insert([{
            checkout_request_id: checkoutRequestId,
            merchant_request_id: merchantRequestId,
            amount:              Math.floor(parsedAmount),
            phone,
            user_id:             user.id,
            status:              'pending',
        }]);

        if (insertErr) {
            console.error('[Wallet] Failed to record transaction:', insertErr.message);
            // Don't block the user — STK was already sent
        }

        console.log(`[Wallet] STK push sent. checkoutId=${checkoutRequestId} user=${user.id}`);

        res.status(200).json({
            message:           'STK push sent! Please check your phone.',
            checkoutId:        checkoutRequestId,
            checkoutRequestId,
        });

    } catch (err) {
        console.error('Deposit error:', err.message);
        res.status(500).json({ error: 'Failed to initiate deposit. Please try again.' });
    }
});

// ============================================================
// DEPOSIT STATUS CHECK
// ============================================================
router.get('/deposit/status', async (req, res) => {
    try {
        const { checkoutId } = req.query;

        if (!checkoutId || typeof checkoutId !== 'string' || checkoutId.length > 100) {
            return res.status(400).json({ error: 'checkoutId is required' });
        }

        const { data, error } = await req.supabaseAdmin
            .from('transactions')
            .select('status, mpesa_receipt')
            .eq('checkout_request_id', checkoutId)
            .maybeSingle();

        if (error) throw error;

        res.json({
            status:       data ? data.status : 'pending',
            mpesaReceipt: data?.mpesa_receipt || null,
        });

    } catch (err) {
        console.error('Deposit status error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// TRANSACTION HISTORY
// ============================================================
router.get('/transactions', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const limit  = Math.min(parseInt(req.query.limit  || '20', 10), 100);
        const offset = Math.max(parseInt(req.query.offset || '0',  10), 0);

        const { data, error } = await req.supabaseAdmin
            .from('transactions')
            .select('checkout_request_id, amount, status, mpesa_receipt, phone, created_at')
            .eq('user_id', user.id)
            .order('created_at', { ascending: false })
            .range(offset, offset + limit - 1);

        if (error) throw error;

        res.json({ transactions: data || [] });

    } catch (err) {
        console.error('Transaction history error:', err.message);
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

module.exports = router;