// ============================================================
// AUTHENTICATION ROUTES
// routes/auth.js
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { createClient } = require('@supabase/supabase-js');
const { normalizePhone, sendGenericError } = require('./helpers');

// ============================================================
// SIGNUP
// ============================================================
router.post('/signup', async (req, res) => {
    try {
        const supabase      = req.supabase;
        const supabaseAdmin = req.supabaseAdmin;

        console.log('📝 Signup request received:', {
            phone:    req.body.phone?.slice(0, 8) + '***',
            username: req.body.username,
            teamName: req.body.teamName
        });

        let { phone, password, username, teamName } = req.body;

        // ── Validation ───────────────────────────────────────────
        if (!phone || !password || !username || !teamName) {
            return res.status(400).json({
                error: 'Missing fields. Phone, password, username, and team name are required.'
            });
        }
        if (typeof username !== 'string' || username.length < 3 || username.length > 30) {
            return res.status(400).json({ error: 'Username must be 3–30 characters.' });
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username may only contain letters, numbers, and underscores.' });
        }
        if (typeof password !== 'string' || password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }
        if (typeof teamName !== 'string' || teamName.length < 3 || teamName.length > 50) {
            return res.status(400).json({ error: 'Team name must be 3–50 characters.' });
        }

        phone = normalizePhone(phone);
        if (!phone) {
            return res.status(400).json({ error: 'Invalid phone number.' });
        }

        console.log('🔐 Attempting Supabase auth signup...');

        const { data, error } = await supabase.auth.signUp({
            phone,
            password,
            options: { data: { username } }
        });

        if (error) {
            return sendGenericError(res, 400, 'Signup failed. Please try again.', error);
        }

        console.log('✅ User created:', data.user?.id);

        if (data.user) {
            try {
                // Create profile
                const { error: profileError } = await supabaseAdmin
                    .from('profiles')
                    .upsert([{ id: data.user.id, username, team_name: teamName }]);

                if (profileError) throw profileError;

                // Create wallet (idempotent)
                const { data: existingWallet } = await supabaseAdmin
                    .from('wallets')
                    .select('user_id')
                    .eq('user_id', data.user.id)
                    .maybeSingle();

                if (!existingWallet) {
                    const { error: walletError } = await supabaseAdmin
                        .from('wallets')
                        .insert([{ user_id: data.user.id, balance: 0 }]);
                    if (walletError) throw walletError;
                }
            } catch (dbErr) {
                // Log internal details server-side only; never expose to client
                console.error('❌ Failed to create profile/wallet — code:', dbErr.code, 'msg:', dbErr.message);

                // Rollback auth user
                await supabaseAdmin.auth.admin.deleteUser(data.user.id)
                    .catch((delErr) => console.error('❌ Failed to rollback user:', delErr.message));

                return sendGenericError(res, 500, 'Account creation failed. Please try again.', dbErr);
            }
        }

        console.log('🎉 Signup successful for', data.user?.id);
        res.status(200).json({ message: 'Signup successful!', user: data.user });

    } catch (err) {
        console.error('💥 Signup error:', err.message);
        return sendGenericError(res, 500, 'Internal server error', err);
    }
});

// ============================================================
// LOGIN
// ============================================================
router.post('/login', async (req, res) => {
    try {
        let { phone, password } = req.body;

        if (!phone || !password) {
            return res.status(400).json({ error: 'Phone and password are required.' });
        }

        phone = normalizePhone(phone);
        if (!phone) {
            return res.status(400).json({ error: 'Invalid phone number.' });
        }

        // Use a fresh client with no session persistence for login
        const loginClient = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_ANON_KEY,
            { auth: { persistSession: false, autoRefreshToken: false } }
        );

        const { data, error } = await loginClient.auth.signInWithPassword({ phone, password });

        if (error) {
            // Never reveal whether it was the phone or password that was wrong
            return sendGenericError(res, 400, 'Invalid phone number or password.', error);
        }

        res.status(200).json({ message: 'Login successful!', session: data.session });

    } catch (err) {
        console.error('Login error:', err.message);
        return sendGenericError(res, 500, 'Internal server error', err);
    }
});

module.exports = router;