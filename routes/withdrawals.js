// ============================================================
// WITHDRAWAL ROUTES — NO AUTO-APPROVE (All go to pending)
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { normalizePhone, isValidUUID } = require('./helpers');

const WITHDRAWAL_CONFIG = {
    MIN_AMOUNT:                    20,
    MAX_AMOUNT:                    50_000,
    DAILY_LIMIT:                   100_000,
    MIN_BALANCE:                   0,
    MIN_ACCOUNT_AGE_HOURS:         24,
    MIN_MATCHES_PLAYED:            1,
};

// ============================================================
// GET withdrawal history
// ============================================================
router.get('/', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { data: withdrawals, error } = await req.supabaseAdmin
            .from('withdrawals')
            .select('id, amount, phone_number, status, requested_at, processed_at, review_notes')
            .eq('user_id', user.id)
            .order('requested_at', { ascending: false })
            .limit(50);

        if (error) throw error;

        res.json({ withdrawals: withdrawals || [] });
    } catch (err) {
        console.error('Get withdrawals error:', err.message);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// ============================================================
// REQUEST WITHDRAWAL — ALWAYS PENDING
// ============================================================
router.post('/request', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { amount, phoneNumber } = req.body;
        const withdrawAmount = parseFloat(amount);

        if (!withdrawAmount || withdrawAmount < WITHDRAWAL_CONFIG.MIN_AMOUNT) {
            return res.status(400).json({ error: `Minimum withdrawal is KES ${WITHDRAWAL_CONFIG.MIN_AMOUNT}` });
        }
        if (withdrawAmount > WITHDRAWAL_CONFIG.MAX_AMOUNT) {
            return res.status(400).json({ error: `Maximum withdrawal is KES ${WITHDRAWAL_CONFIG.MAX_AMOUNT.toLocaleString()}` });
        }

        const cleanPhone = normalizePhone(phoneNumber);
        if (!cleanPhone) {
            return res.status(400).json({ error: 'Invalid phone number' });
        }

        // Call the new manual RPC — always creates 'pending'
        const { data: withdrawal, error: rpcErr } = await req.supabaseAdmin.rpc('create_withdrawal_manual', {
            p_user_id: user.id,
            p_amount:  withdrawAmount,
            p_phone:   cleanPhone,
            p_user_ip: req.ip || req.headers['x-forwarded-for'] || null,
        });

        if (rpcErr) {
            const msg = rpcErr.message?.includes('daily limit') ? 'Daily withdrawal limit exceeded'
                : rpcErr.message?.includes('insufficient') ? 'Insufficient balance'
                : rpcErr.message;
            return res.status(400).json({ error: msg });
        }

        const row = Array.isArray(withdrawal) ? withdrawal[0] : withdrawal;

        res.status(201).json({
            message: 'Withdrawal request submitted for review. Admin will approve shortly.',
            withdrawal: {
                id:          row.id,
                amount:      withdrawAmount,
                status:      'pending',
                phone:       cleanPhone,
                requestedAt: row.requested_at
            }
        });

    } catch (err) {
        console.error('Withdrawal request error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// CANCEL pending withdrawal
// ============================================================
router.post('/:id/cancel', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { data, error: rpcErr } = await req.supabaseAdmin.rpc('cancel_withdrawal', {
            p_withdrawal_id: id,
            p_user_id: user.id
        });

        if (rpcErr) {
            const msg = rpcErr.message?.toLowerCase().includes('not found') ? 'Withdrawal not found'
                : rpcErr.message?.toLowerCase().includes('not pending') ? 'Withdrawal cannot be cancelled (not pending)'
                : 'Failed to cancel withdrawal';
            return res.status(400).json({ error: msg });
        }

        await req.supabaseAdmin
            .from('transactions')
            .insert([{
                user_id:     user.id,
                type:        'refund',
                amount:      data.refunded_amount,
                description: `Withdrawal cancelled: KES ${data.amount}`,
                status:      'completed',
                reference:   `WD-CANCEL-${id.substring(0, 8)}`
            }]);

        res.json({ message: 'Withdrawal cancelled and funds refunded', refundedAmount: data.refunded_amount });

    } catch (err) {
        console.error('Cancel withdrawal error:', err.message);
        res.status(500).json({ error: 'Failed to cancel withdrawal' });
    }
});

module.exports = { router };