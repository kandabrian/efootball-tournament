// ============================================================
// WITHDRAWAL ROUTES MODULE
// routes/withdrawals.js
// ============================================================
const express = require('express');
const router = express.Router();

// Withdrawal configuration
const WITHDRAWAL_CONFIG = {
    MIN_AMOUNT: 100,           // KES 100 minimum
    MAX_AMOUNT: 50000,         // KES 50,000 maximum per transaction
    DAILY_LIMIT: 100000,       // KES 100,000 per day
    MIN_BALANCE: 50,           // Must keep KES 50 in wallet
    PROCESSING_FEE_PERCENT: 0, // 0% fee (or set to 1.5 for 1.5%)
    PROCESSING_FEE_FIXED: 0,   // KES 0 fixed fee
    AUTO_APPROVE_THRESHOLD: 5000, // Auto-approve withdrawals under KES 5,000
    REQUIRE_ID_VERIFICATION_ABOVE: 10000, // Require ID verification for > KES 10,000
    MIN_ACCOUNT_AGE_HOURS: 24, // Account must be 24 hours old
    MIN_MATCHES_PLAYED: 3,     // Must have played at least 3 completed matches
};

// ============================================================
// HELPER: Check if user is eligible for withdrawal
// FIX: Was querying a non-existent `matches` table with wrong
//      column names. Now correctly queries `friend_matches`.
// ============================================================
async function checkWithdrawalEligibility(supabaseAdmin, userId) {
    const errors = [];

    // 1. Check account status
    const { data: profile } = await supabaseAdmin
        .from('profiles')
        .select('account_status, created_at')
        .eq('id', userId)
        .single();

    if (!profile) {
        errors.push('Profile not found');
        return { eligible: false, errors };
    }

    // Only block if explicitly suspended/banned; treat null/missing as 'active'
    if (profile.account_status && profile.account_status !== 'active') {
        errors.push(`Account is ${profile.account_status}. Contact support.`);
    }

    // 2. Check account age
    const accountAge = (Date.now() - new Date(profile.created_at).getTime()) / (1000 * 60 * 60);
    if (accountAge < WITHDRAWAL_CONFIG.MIN_ACCOUNT_AGE_HOURS) {
        errors.push(`Account must be ${WITHDRAWAL_CONFIG.MIN_ACCOUNT_AGE_HOURS} hours old. Current age: ${Math.floor(accountAge)} hours.`);
    }

    // 3. Check matches played
    // FIX: Use friend_matches (creator_id / joiner_id) not the non-existent
    //      `matches` table that had home_id / away_id columns.
    const { count: matchCount, error: matchErr } = await supabaseAdmin
        .from('friend_matches')
        .select('id', { count: 'exact', head: true })
        .or(`creator_id.eq.${userId},joiner_id.eq.${userId}`)
        .eq('status', 'completed');

    if (matchErr) {
        console.error('Error checking match count for withdrawal eligibility:', matchErr.message);
        // Don't block the user if the query itself fails — just note it
        errors.push('Could not verify match history. Please try again.');
    } else if ((matchCount ?? 0) < WITHDRAWAL_CONFIG.MIN_MATCHES_PLAYED) {
        errors.push(`Must play at least ${WITHDRAWAL_CONFIG.MIN_MATCHES_PLAYED} completed matches. Played: ${matchCount ?? 0}.`);
    }

    // 4. Check for pending withdrawals
    const { data: pendingWithdrawals } = await supabaseAdmin
        .from('withdrawals')
        .select('id')
        .eq('user_id', userId)
        .in('status', ['pending', 'approved', 'processing']);

    if (pendingWithdrawals && pendingWithdrawals.length > 0) {
        errors.push('You have a pending withdrawal. Wait for it to complete.');
    }

    return {
        eligible: errors.length === 0,
        errors,
        accountAge,
        matchCount: matchCount ?? 0
    };
}

// ============================================================
// HELPER: Calculate daily withdrawal total
// ============================================================
async function getDailyWithdrawalTotal(supabaseAdmin, userId) {
    const today = new Date().toISOString().split('T')[0];

    const { data: todayWithdrawals } = await supabaseAdmin
        .from('withdrawals')
        .select('amount')
        .eq('user_id', userId)
        .gte('requested_at', `${today}T00:00:00`)
        .in('status', ['approved', 'processing', 'completed']);

    return todayWithdrawals?.reduce((sum, w) => sum + parseFloat(w.amount), 0) || 0;
}

// ============================================================
// ROUTE: GET /withdrawals - Get user's withdrawal history
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
            .select('*')
            .eq('user_id', user.id)
            .order('requested_at', { ascending: false })
            .limit(50);

        if (error) throw error;

        res.json({ withdrawals });
    } catch (err) {
        console.error('Get withdrawals error:', err);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// ============================================================
// ROUTE: POST /withdrawals/request - Create withdrawal request
// ============================================================
router.post('/request', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { amount, phoneNumber } = req.body;

        // ── Validation ──────────────────────────────────────────
        if (!amount || !phoneNumber) {
            return res.status(400).json({ error: 'Amount and phone number required' });
        }

        const withdrawAmount = parseFloat(amount);
        if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        if (withdrawAmount < WITHDRAWAL_CONFIG.MIN_AMOUNT) {
            return res.status(400).json({
                error: `Minimum withdrawal is KES ${WITHDRAWAL_CONFIG.MIN_AMOUNT}`
            });
        }

        if (withdrawAmount > WITHDRAWAL_CONFIG.MAX_AMOUNT) {
            return res.status(400).json({
                error: `Maximum withdrawal is KES ${WITHDRAWAL_CONFIG.MAX_AMOUNT}`
            });
        }

        // Normalize phone
        let cleanPhone = phoneNumber.replace(/\D/g, '');
        if (cleanPhone.startsWith('0')) cleanPhone = '254' + cleanPhone.substring(1);
        else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) cleanPhone = '254' + cleanPhone;
        if (!/^254[17]\d{8}$/.test(cleanPhone)) {
            return res.status(400).json({ error: 'Invalid phone number format' });
        }
        cleanPhone = '+' + cleanPhone;

        // ── Check eligibility ────────────────────────────────────
        const eligibility = await checkWithdrawalEligibility(req.supabaseAdmin, user.id);
        if (!eligibility.eligible) {
            return res.status(403).json({
                error: 'Not eligible for withdrawal',
                reasons: eligibility.errors
            });
        }

        // ── Check wallet balance ────────────────────────────────
        const { data: wallet } = await req.supabaseAdmin
            .from('wallets')
            .select('balance')
            .eq('user_id', user.id)
            .single();

        if (!wallet) {
            return res.status(404).json({ error: 'Wallet not found' });
        }

        const currentBalance = parseFloat(wallet.balance);
        const fee = WITHDRAWAL_CONFIG.PROCESSING_FEE_FIXED +
                    (withdrawAmount * WITHDRAWAL_CONFIG.PROCESSING_FEE_PERCENT / 100);
        const totalDeduction = withdrawAmount + fee;

        if (currentBalance < totalDeduction) {
            return res.status(400).json({
                error: `Insufficient balance. You have KES ${currentBalance.toFixed(2)}. Need KES ${totalDeduction.toFixed(2)} (including fees).`
            });
        }

        if (currentBalance - totalDeduction < WITHDRAWAL_CONFIG.MIN_BALANCE) {
            return res.status(400).json({
                error: `Must maintain minimum balance of KES ${WITHDRAWAL_CONFIG.MIN_BALANCE}`
            });
        }

        // ── Check daily limit ───────────────────────────────────
        const todayTotal = await getDailyWithdrawalTotal(req.supabaseAdmin, user.id);
        if (todayTotal + withdrawAmount > WITHDRAWAL_CONFIG.DAILY_LIMIT) {
            return res.status(400).json({
                error: `Daily limit exceeded. Used: KES ${todayTotal.toFixed(2)} of KES ${WITHDRAWAL_CONFIG.DAILY_LIMIT}`
            });
        }

        // ── Check ID verification requirement ───────────────────
        if (withdrawAmount > WITHDRAWAL_CONFIG.REQUIRE_ID_VERIFICATION_ABOVE) {
            const { data: profileForId } = await req.supabaseAdmin
                .from('profiles')
                .select('id_verified')
                .eq('id', user.id)
                .single();

            if (!profileForId?.id_verified) {
                return res.status(403).json({
                    error: `Withdrawals above KES ${WITHDRAWAL_CONFIG.REQUIRE_ID_VERIFICATION_ABOVE} require ID verification. Please contact support.`
                });
            }
        }

        // ── Create withdrawal request ───────────────────────────
        const autoApprove = withdrawAmount <= WITHDRAWAL_CONFIG.AUTO_APPROVE_THRESHOLD;

        const { data: withdrawal, error: insertError } = await req.supabaseAdmin
            .from('withdrawals')
            .insert([{
                user_id: user.id,
                amount: withdrawAmount,
                phone_number: cleanPhone,
                status: autoApprove ? 'approved' : 'pending',
                user_ip: req.ip || req.headers['x-forwarded-for'],
                user_agent: req.headers['user-agent'],
                reviewed_at: autoApprove ? new Date().toISOString() : null,
                review_notes: autoApprove ? 'Auto-approved (amount below threshold)' : null
            }])
            .select()
            .single();

        if (insertError) throw insertError;

        // ── Atomically deduct from wallet via RPC ───────────────
        const { error: walletError } = await req.supabaseAdmin.rpc('deduct_wallet', {
            p_user_id: user.id,
            p_amount: totalDeduction
        });

        if (walletError) {
            // Rollback withdrawal record if deduction fails
            await req.supabaseAdmin.from('withdrawals').delete().eq('id', withdrawal.id);
            const msg = walletError.message?.toLowerCase().includes('insufficient')
                ? 'Insufficient balance'
                : 'Failed to deduct from wallet';
            return res.status(400).json({ error: msg });
        }

        // ── Record transaction ──────────────────────────────────
        await req.supabaseAdmin
            .from('transactions')
            .insert([{
                user_id: user.id,
                type: 'withdrawal',
                amount: -totalDeduction,
                description: `Withdrawal request: KES ${withdrawAmount.toFixed(2)}${fee > 0 ? ` + KES ${fee.toFixed(2)} fee` : ''}`,
                status: 'completed',
                reference: `WD-${withdrawal.id.substring(0, 8)}`
            }]);

        console.log(`💸 Withdrawal requested: user=${user.id}, amount=${withdrawAmount}, status=${withdrawal.status}`);

        res.status(201).json({
            message: autoApprove
                ? 'Withdrawal approved! Processing payment...'
                : 'Withdrawal request submitted for review',
            withdrawal: {
                id: withdrawal.id,
                amount: withdrawAmount,
                fee,
                total: totalDeduction,
                status: withdrawal.status,
                phone: cleanPhone,
                requestedAt: withdrawal.requested_at,
                estimatedTime: autoApprove ? '5-10 minutes' : '1-2 hours'
            }
        });

        // ── Auto-process if approved ────────────────────────────
        // FIX: req.processMpesaWithdrawal is now properly injected by app.js
        if (autoApprove && req.processMpesaWithdrawal) {
            req.processMpesaWithdrawal(withdrawal.id).catch(err => {
                console.error(`Failed to process auto-approved withdrawal ${withdrawal.id}:`, err);
            });
        } else if (autoApprove && !req.processMpesaWithdrawal) {
            console.warn(`⚠️  Auto-approved withdrawal ${withdrawal.id} but processMpesaWithdrawal not injected — skipping auto-process.`);
        }

    } catch (err) {
        console.error('Withdrawal request error:', err);
        res.status(500).json({ error: 'Failed to process withdrawal request' });
    }
});

// ============================================================
// ROUTE: POST /withdrawals/:id/cancel - Cancel pending withdrawal
// ============================================================
router.post('/:id/cancel', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

        const jwt = authHeader.replace('Bearer ', '');
        const { data: { user }, error: authErr } = await req.supabase.auth.getUser(jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { id } = req.params;

        // Get withdrawal
        const { data: withdrawal } = await req.supabaseAdmin
            .from('withdrawals')
            .select('*')
            .eq('id', id)
            .eq('user_id', user.id)
            .single();

        if (!withdrawal) {
            return res.status(404).json({ error: 'Withdrawal not found' });
        }

        if (withdrawal.status !== 'pending') {
            return res.status(400).json({
                error: `Cannot cancel withdrawal with status: ${withdrawal.status}`
            });
        }

        // Calculate total to refund (amount + any fees)
        const fee = WITHDRAWAL_CONFIG.PROCESSING_FEE_FIXED +
                    (parseFloat(withdrawal.amount) * WITHDRAWAL_CONFIG.PROCESSING_FEE_PERCENT / 100);
        const totalRefund = parseFloat(withdrawal.amount) + fee;

        // Atomically refund to wallet via RPC
        const { error: walletError } = await req.supabaseAdmin.rpc('credit_wallet', {
            p_user_id: user.id,
            p_amount: totalRefund
        });

        if (walletError) throw walletError;

        // Update withdrawal status
        await req.supabaseAdmin
            .from('withdrawals')
            .update({
                status: 'rejected',
                review_notes: 'Cancelled by user',
                reviewed_at: new Date().toISOString()
            })
            .eq('id', id);

        // Record transaction
        await req.supabaseAdmin
            .from('transactions')
            .insert([{
                user_id: user.id,
                type: 'refund',
                amount: totalRefund,
                description: `Withdrawal cancelled: KES ${withdrawal.amount}`,
                status: 'completed',
                reference: `WD-CANCEL-${id.substring(0, 8)}`
            }]);

        res.json({
            message: 'Withdrawal cancelled and funds refunded',
            refundedAmount: totalRefund
        });

    } catch (err) {
        console.error('Cancel withdrawal error:', err);
        res.status(500).json({ error: 'Failed to cancel withdrawal' });
    }
});

// ============================================================
// HELPER: Process M-Pesa withdrawal (async)
// Called by app.js via req.processMpesaWithdrawal(withdrawalId)
// ============================================================
async function processMpesaWithdrawal(supabaseAdmin, withdrawalId) {
    try {
        console.log(`🔄 Processing M-Pesa withdrawal: ${withdrawalId}`);

        const { data: withdrawal } = await supabaseAdmin
            .from('withdrawals')
            .select('*')
            .eq('id', withdrawalId)
            .single();

        if (!withdrawal || withdrawal.status !== 'approved') {
            console.log(`⚠️  Withdrawal ${withdrawalId} not in approved state`);
            return;
        }

        // Update to processing
        await supabaseAdmin
            .from('withdrawals')
            .update({ status: 'processing' })
            .eq('id', withdrawalId);

        // Call M-Pesa B2C API
        const mpesaResponse = await fetch(`${process.env.MPESA_SERVER_URL}/b2c`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: withdrawal.phone_number,
                amount: withdrawal.amount,
                reference: `WD-${withdrawalId.substring(0, 8)}`
            })
        });

        const mpesaData = await mpesaResponse.json();

        if (mpesaResponse.ok && mpesaData.success) {
            await supabaseAdmin
                .from('withdrawals')
                .update({
                    status: 'completed',
                    processed_at: new Date().toISOString(),
                    mpesa_transaction_id: mpesaData.transactionId,
                    mpesa_receipt_number: mpesaData.receiptNumber
                })
                .eq('id', withdrawalId);

            console.log(`✅ Withdrawal completed: ${withdrawalId}`);
        } else {
            throw new Error(mpesaData.error || 'M-Pesa API error');
        }

    } catch (err) {
        console.error(`❌ M-Pesa withdrawal failed: ${withdrawalId}`, err);

        const { data: withdrawal } = await supabaseAdmin
            .from('withdrawals')
            .select('user_id, amount, retry_count')
            .eq('id', withdrawalId)
            .single();

        if (!withdrawal) return;

        const retryCount = (withdrawal.retry_count ?? 0) + 1;

        await supabaseAdmin
            .from('withdrawals')
            .update({
                status: 'failed',
                failure_reason: err.message,
                retry_count: retryCount
            })
            .eq('id', withdrawalId);

        // Refund to wallet if max retries reached
        if (retryCount >= 3) {
            const fee = WITHDRAWAL_CONFIG.PROCESSING_FEE_FIXED +
                        (parseFloat(withdrawal.amount) * WITHDRAWAL_CONFIG.PROCESSING_FEE_PERCENT / 100);
            const totalRefund = parseFloat(withdrawal.amount) + fee;

            await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: withdrawal.user_id,
                p_amount: totalRefund
            });

            await supabaseAdmin
                .from('transactions')
                .insert([{
                    user_id: withdrawal.user_id,
                    type: 'refund',
                    amount: totalRefund,
                    description: `Withdrawal failed after ${retryCount} attempts - refunded: KES ${withdrawal.amount}`,
                    status: 'completed',
                    reference: `WD-FAIL-${withdrawalId.substring(0, 8)}`
                }]);

            console.log(`💰 Refunded failed withdrawal: ${withdrawalId}`);
        }
    }
}

module.exports = {
    router,
    processMpesaWithdrawal,
    WITHDRAWAL_CONFIG
};