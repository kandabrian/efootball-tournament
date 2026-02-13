require('dotenv').config();

const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;
const MPESA_SERVER = process.env.MPESA_SERVER_URL || 'http://localhost:5000';

// Validate env
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('FATAL: Missing Supabase keys in .env file');
    process.exit(1);
}

// Clients
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// Rate limiters
const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 10,
    message: { error: 'Too many requests. Try again later.' }
});
const depositLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many deposit attempts. Try again later.' }
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

// Middleware
app.use(express.json());
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://*.supabase.co");
    next();
});
app.use(express.static('public'));

// ============== PAGE ROUTES ==============
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
            // Use atomic RPC
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
            // M-PESA path: payment already confirmed via callback, now create booking
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

// ============== M-PESA ROUTES ==============
app.post('/mpesa/deposit', depositLimiter, async (req, res) => {
    let { phone, amount, description } = req.body;
    if (!phone || !amount || isNaN(amount) || amount < 10) return res.status(400).json({ error: 'Invalid request.' });
    phone = normalizePhone(phone);

    const jwt = req.headers['authorization']?.replace('Bearer ', '');
    const { data: { user } } = await supabase.auth.getUser(jwt);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });

    try {
        const mpesaRes = await fetch(`${MPESA_SERVER}/pay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: phone.replace('+', ''),
                amount: String(Math.floor(Number(amount))),
                description: description || 'Vumbua Deposit'
            })
        });

        if (!mpesaRes.ok) throw new Error('STK request failed');
        const mpesaData = await mpesaRes.json();
        
        // Insert transaction with user_id
        await supabaseAdmin.from('transactions').insert([{
            checkout_request_id: mpesaData.CheckoutRequestID || mpesaData.checkoutId,
            merchant_request_id: mpesaData.MerchantRequestID || 'N/A',
            amount: Number(amount),
            phone,
            user_id: user.id,
            status: 'pending'
        }]);

        res.status(200).json({ message: 'STK push sent!', checkoutId: mpesaData.CheckoutRequestID || mpesaData.checkoutId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to initiate deposit.' });
    }
});

// SECURE CALLBACK (secret in header, not query)
app.post('/mpesa/callback', async (req, res) => {
    // Check secret in header (e.g., X-Webhook-Secret)
    if (req.headers['x-webhook-secret'] !== process.env.MPESA_WEBHOOK_SECRET) {
        console.warn('⚠️ Unauthorized callback attempt blocked.');
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { Body: { stkCallback: { CheckoutRequestID: checkoutId, ResultCode: resultCode, CallbackMetadata } } } = req.body;
    if (!checkoutId) return res.status(200).json({ ResultCode: 1, ResultDesc: 'Invalid payload' });

    try {
        if (resultCode !== 0) {
            await supabaseAdmin.from('transactions').update({ status: 'failed' }).eq('checkout_request_id', checkoutId);
            return res.status(200).json({ ResultCode: 0, ResultDesc: 'Success' });
        }

        let amount = 0, mpesaReceipt = '', phone = '';
        CallbackMetadata?.Item?.forEach(item => {
            if (item.Name === 'Amount') amount = item.Value;
            if (item.Name === 'MpesaReceiptNumber') mpesaReceipt = item.Value;
            if (item.Name === 'PhoneNumber') phone = normalizePhone(item.Value);
        });

        // Update transaction to success
        const { data: transData, error: transError } = await supabaseAdmin.from('transactions')
            .update({ status: 'success', mpesa_receipt: mpesaReceipt, updated_at: new Date().toISOString() })
            .eq('checkout_request_id', checkoutId)
            .select('user_id, amount')
            .single();

        if (transError || !transData) {
            console.error('Transaction update failed:', transError);
            return res.status(200).json({ ResultCode: 1, ResultDesc: 'Failed to update transaction' });
        }

        // Credit wallet atomically via RPC
        if (transData.user_id) {
            await supabaseAdmin.rpc('credit_wallet', {
                p_user_id: transData.user_id,
                p_amount: transData.amount
            });
            console.log(`✅ Credited +KES ${transData.amount} to user ${transData.user_id}`);
        } else {
            // Fallback: try to find user by phone (legacy)
            const { data: userData } = await supabaseAdmin.rpc('get_user_by_phone', { p_phone: phone });
            if (userData && userData.length > 0) {
                await supabaseAdmin.rpc('credit_wallet', {
                    p_user_id: userData[0].id,
                    p_amount: amount
                });
                // Also update transaction with user_id for future
                await supabaseAdmin.from('transactions').update({ user_id: userData[0].id }).eq('checkout_request_id', checkoutId);
            }
        }

        res.status(200).json({ ResultCode: 0, ResultDesc: 'Success' });
    } catch (err) {
        console.error('Callback error:', err.message);
        res.status(500).json({ ResultCode: 1, ResultDesc: 'Failed' });
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

    // Refund wallet atomically via RPC
    const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', {
        p_user_id: wd.user_id,
        p_amount: wd.amount
    });
    if (refundErr) return res.status(500).json({ error: refundErr.message });

    // Reject record
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

// ============== PUBLIC TOURNAMENT ROUTES ==============
app.get('/tournaments', async (req, res) => {
    try {
        // Fetch tournaments that are open or live, including booking count
        const { data: tournaments, error } = await supabaseAdmin
            .from('tournaments')
            .select(`
                *,
                bookings:bookings(count)
            `)
            .in('status', ['open', 'live'])
            .order('start_time', { ascending: true });

        if (error) throw error;

        // Transform to include current players and compute prize pool (optional)
        const result = tournaments.map(t => ({
            ...t,
            current_players: t.bookings?.[0]?.count || 0,
            prize_pool: t.entry_fee * t.max_players  // display only – not stored
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