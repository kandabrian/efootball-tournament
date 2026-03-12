// ============================================================
// WITHDRAWAL ROUTES
// routes/withdrawals.js
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { normalizePhone, isValidUUID } = require('./helpers');

// ============================================================
// CONFIGURATION
// ============================================================
const WITHDRAWAL_CONFIG = {
    MIN_AMOUNT:                    50,
    MAX_AMOUNT:                    50_000,
    DAILY_LIMIT:                   100_000,
    MIN_BALANCE:                   0,
    PROCESSING_FEE_PERCENT:        0,
    PROCESSING_FEE_FIXED:          0,
    AUTO_APPROVE_THRESHOLD:        5_000,
    REQUIRE_ID_VERIFICATION_ABOVE: 10_000,
    MIN_ACCOUNT_AGE_HOURS:         24,
    MIN_MATCHES_PLAYED:            1,
};

// ============================================================
// HELPER: Check withdrawal eligibility
// ============================================================
async function checkWithdrawalEligibility(supabaseAdmin, userId) {
    const errors = [];

    // 1. Account age
    const { data: profile, error: profileErr } = await supabaseAdmin
        .from('profiles')
        .select('created_at')
        .eq('id', userId)
        .single();

    if (profileErr || !profile) {
        errors.push('Profile not found');
        return { eligible: false, errors };
    }

    const accountAgeHours = (Date.now() - new Date(profile.created_at).getTime()) / (1000 * 60 * 60);
    if (accountAgeHours < WITHDRAWAL_CONFIG.MIN_ACCOUNT_AGE_HOURS) {
        errors.push(`Account must be ${WITHDRAWAL_CONFIG.MIN_ACCOUNT_AGE_HOURS} hours old. Current age: ${Math.floor(accountAgeHours)} hours.`);
    }

    // 2. Completed matches
    const { count: matchCount, error: matchErr } = await supabaseAdmin
        .from('friend_matches')
        .select('id', { count: 'exact', head: true })
        .or(`creator_id.eq.${userId},joiner_id.eq.${userId}`)
        .eq('status', 'completed');

    if (matchErr) {
        console.error('Error checking match count:', matchErr.message);
        errors.push('Could not verify match history. Please try again.');
    } else if ((matchCount ?? 0) < WITHDRAWAL_CONFIG.MIN_MATCHES_PLAYED) {
        errors.push(`Must complete at least ${WITHDRAWAL_CONFIG.MIN_MATCHES_PLAYED} match. Completed: ${matchCount ?? 0}.`);
    }

    // 3. No pending withdrawals
    const { data: pending, error: pendingErr } = await supabaseAdmin
        .from('withdrawals')
        .select('id')
        .eq('user_id', userId)
        .in('status', ['pending', 'approved', 'processing']);

    if (pendingErr) {
        console.error('Error checking pending withdrawals:', pendingErr.message);
        errors.push('Could not verify withdrawal status. Please try again.');
    } else if (pending && pending.length > 0) {
        errors.push('You have a pending withdrawal. Wait for it to complete.');
    }

    return {
        eligible:     errors.length === 0,
        errors,
        accountAgeHours,
        matchCount:   matchCount ?? 0,
    };
}

// ============================================================
// HELPER: Daily withdrawal total (Nairobi time)
// ============================================================
async function getDailyWithdrawalTotal(supabaseAdmin, userId) {
    const now = new Date();
    const nairobiDateStr = now.toLocaleDateString('en-CA', { timeZone: 'Africa/Nairobi' });

    const { data } = await supabaseAdmin
        .from('withdrawals')
        .select('amount, requested_at')
        .eq('user_id', userId)
        .in('status', ['approved', 'processing', 'completed']);

    const total = (data || [])
        .filter(w => {
            const reqDate = new Date(w.requested_at).toLocaleDateString('en-CA', { timeZone: 'Africa/Nairobi' });
            return reqDate === nairobiDateStr;
        })
        .reduce((sum, w) => sum + parseFloat(w.amount), 0);

    return total;
}

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

        res.json({ withdrawals });
    } catch (err) {
        console.error('Get withdrawals error:', err.message);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// ============================================================
// REQUEST withdrawal – with detailed error logging
// ============================================================
router.post('/request', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            console.warn('Withdrawal request missing auth header');
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) {
            console.warn('Withdrawal request invalid session:', authErr?.message);
            return res.status(401).json({ error: 'Invalid session' });
        }

        const { amount, phoneNumber } = req.body;
        console.log(`Withdrawal request: user=${user.id}, amount=${amount}, phone=${phoneNumber}`);

        // --- Validate amount ---
        if (!amount) {
            return res.status(400).json({ error: 'Amount is required' });
        }
        const withdrawAmount = parseFloat(amount);
        if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
            return res.status(400).json({ error: 'Amount must be a positive number' });
        }
        if (withdrawAmount < WITHDRAWAL_CONFIG.MIN_AMOUNT) {
            return res.status(400).json({ error: `Minimum withdrawal is KES ${WITHDRAWAL_CONFIG.MIN_AMOUNT}` });
        }
        if (withdrawAmount > WITHDRAWAL_CONFIG.MAX_AMOUNT) {
            return res.status(400).json({ error: `Maximum withdrawal is KES ${WITHDRAWAL_CONFIG.MAX_AMOUNT.toLocaleString()}` });
        }

        // --- Validate phone ---
        if (!phoneNumber) {
            return res.status(400).json({ error: 'Phone number is required' });
        }
        const cleanPhone = normalizePhone(phoneNumber);
        if (!cleanPhone) {
            console.warn(`Invalid phone format: "${phoneNumber}"`);
            return res.status(400).json({ error: 'Invalid phone number format. Use 07XX XXX XXX or +2547XX XXX XXX' });
        }

        // --- Check eligibility ---
        const eligibility = await checkWithdrawalEligibility(req.supabaseAdmin, user.id);
        if (!eligibility.eligible) {
            console.log(`Withdrawal eligibility failed for user ${user.id}:`, eligibility.errors);
            return res.status(403).json({
                error:   'Not eligible for withdrawal',
                reasons: eligibility.errors
            });
        }

        // --- Daily limit ---
        const todayTotal = await getDailyWithdrawalTotal(req.supabaseAdmin, user.id);
        if (todayTotal + withdrawAmount > WITHDRAWAL_CONFIG.DAILY_LIMIT) {
            return res.status(400).json({
                error: `Daily limit exceeded. Used: KES ${todayTotal.toFixed(2)} of KES ${WITHDRAWAL_CONFIG.DAILY_LIMIT.toLocaleString()}`
            });
        }

        // --- ID verification if required ---
        if (withdrawAmount > WITHDRAWAL_CONFIG.REQUIRE_ID_VERIFICATION_ABOVE) {
            const { data: profileForId } = await req.supabaseAdmin
                .from('profiles')
                .select('id_verified')
                .eq('id', user.id)
                .single();

            if (!profileForId?.id_verified) {
                return res.status(403).json({
                    error: `Withdrawals above KES ${WITHDRAWAL_CONFIG.REQUIRE_ID_VERIFICATION_ABOVE.toLocaleString()} require ID verification. Contact support.`
                });
            }
        }

        const fee = WITHDRAWAL_CONFIG.PROCESSING_FEE_FIXED +
                    (withdrawAmount * WITHDRAWAL_CONFIG.PROCESSING_FEE_PERCENT / 100);
        const totalDeduction = withdrawAmount + fee;
        const autoApprove    = withdrawAmount <= WITHDRAWAL_CONFIG.AUTO_APPROVE_THRESHOLD;

        // --- Call RPC ---
        const rpcParams = {
            p_user_id:       user.id,
            p_amount:        withdrawAmount,
            p_total_deduct:  totalDeduction,
            p_phone:         cleanPhone,
            p_min_balance:   WITHDRAWAL_CONFIG.MIN_BALANCE,
            p_status:        autoApprove ? 'approved' : 'pending',
            p_review_notes:  autoApprove ? 'Auto-approved (amount below threshold)' : null,
            p_user_ip:       req.ip || req.headers['x-forwarded-for'] || null,
            p_user_agent:    req.headers['user-agent'] || null,
        };
        console.log('🔍 RPC params being sent:', JSON.stringify(rpcParams, null, 2));

        const { data: withdrawal, error: rpcErr } = await req.supabaseAdmin.rpc('create_withdrawal', rpcParams);

        if (rpcErr) {
            console.error(`RPC error for user ${user.id}:`, rpcErr.message);
            console.error('RPC full error object:', JSON.stringify(rpcErr, null, 2));
            const msg = rpcErr.message?.toLowerCase().includes('insufficient')
                ? 'Insufficient balance'
                : rpcErr.message?.toLowerCase().includes('min_balance')
                    ? `Must maintain minimum balance of KES ${WITHDRAWAL_CONFIG.MIN_BALANCE}`
                    : 'Failed to process withdrawal request';
            return res.status(400).json({ error: msg, details: rpcErr.message });
        }

        console.log('✅ RPC raw response:', JSON.stringify(withdrawal, null, 2));
        const withdrawalRow = Array.isArray(withdrawal) ? withdrawal[0] : withdrawal;

        // --- Record transaction ---
        await req.supabaseAdmin
            .from('transactions')
            .insert([{
                user_id:     user.id,
                type:        'withdrawal',
                amount:      -totalDeduction,
                description: `Withdrawal: KES ${withdrawAmount.toFixed(2)}${fee > 0 ? ` + KES ${fee.toFixed(2)} fee` : ''}`,
                status:      'completed',
                reference:   `WD-${withdrawalRow.id.substring(0, 8)}`
            }]);

        console.log(`✅ Withdrawal requested: user=${user.id}, amount=${withdrawAmount}, status=${withdrawalRow.status}`);

        res.status(201).json({
            message: autoApprove
                ? 'Withdrawal approved! Processing payment...'
                : 'Withdrawal request submitted for review',
            withdrawal: {
                id:            withdrawalRow.id,
                amount:        withdrawAmount,
                fee,
                total:         totalDeduction,
                status:        withdrawalRow.status,
                phone:         cleanPhone,
                requestedAt:   withdrawalRow.requested_at,
                estimatedTime: autoApprove ? '5–10 minutes' : '1–2 hours'
            }
        });

        if (autoApprove && req.processMpesaWithdrawal) {
            req.processMpesaWithdrawal(withdrawalRow.id).catch(err => {
                console.error(`Failed to auto-process withdrawal ${withdrawalRow.id}:`, err.message);
            });
        }

    } catch (err) {
        console.error('❌ Withdrawal request error:', err.message, err.stack);
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

// ============================================================
// Process M-Pesa B2C withdrawal (called by app.js)
// ============================================================
async function processMpesaWithdrawal(supabaseAdmin, withdrawalId) {
    try {
        console.log(`🔄 Processing M-Pesa withdrawal: ${withdrawalId}`);

        const { data: withdrawal, error: updateErr } = await supabaseAdmin
            .from('withdrawals')
            .update({ status: 'processing' })
            .eq('id', withdrawalId)
            .eq('status', 'approved')
            .select()
            .single();

        if (updateErr || !withdrawal) {
            console.log(`⚠️  Withdrawal ${withdrawalId} not in approved state or already processing.`);
            return;
        }

        const mpesaResponse = await fetch(`${process.env.MPESA_SERVER_URL}/b2c`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                phone:     withdrawal.phone_number,
                amount:    withdrawal.amount,
                reference: `WD-${withdrawalId.substring(0, 8)}`
            })
        });

        const mpesaData = await mpesaResponse.json();

        if (mpesaResponse.ok && mpesaData.success) {
            await supabaseAdmin
                .from('withdrawals')
                .update({
                    status:                 'completed',
                    processed_at:           new Date().toISOString(),
                    mpesa_transaction_id:   mpesaData.transactionId,
                    mpesa_receipt_number:   mpesaData.receiptNumber
                })
                .eq('id', withdrawalId);

            console.log(`✅ Withdrawal completed: ${withdrawalId}`);
        } else {
            throw new Error(mpesaData.error || 'M-Pesa B2C API error');
        }

    } catch (err) {
        console.error(`❌ M-Pesa withdrawal failed: ${withdrawalId}`, err.message);

        const { data: withdrawal } = await supabaseAdmin
            .from('withdrawals')
            .select('user_id, amount, retry_count')
            .eq('id', withdrawalId)
            .single();

        if (!withdrawal) return;

        const retryCount = (withdrawal.retry_count ?? 0) + 1;

        await supabaseAdmin
            .from('withdrawals')
            .update({ status: 'failed', failure_reason: err.message, retry_count: retryCount })
            .eq('id', withdrawalId);

        if (retryCount >= 3) {
            const fee = WITHDRAWAL_CONFIG.PROCESSING_FEE_FIXED +
                        (parseFloat(withdrawal.amount) * WITHDRAWAL_CONFIG.PROCESSING_FEE_PERCENT / 100);
            const totalRefund = parseFloat(withdrawal.amount) + fee;

            await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: withdrawal.user_id,
                p_amount:  totalRefund
            });

            await supabaseAdmin
                .from('transactions')
                .insert([{
                    user_id:     withdrawal.user_id,
                    type:        'refund',
                    amount:      totalRefund,
                    description: `Withdrawal failed after ${retryCount} attempts — refunded: KES ${withdrawal.amount}`,
                    status:      'completed',
                    reference:   `WD-FAIL-${withdrawalId.substring(0, 8)}`
                }]);

            console.log(`💰 Refunded failed withdrawal: ${withdrawalId}`);
        }
    }
}

module.exports = { router, processMpesaWithdrawal, WITHDRAWAL_CONFIG };