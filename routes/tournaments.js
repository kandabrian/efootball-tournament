// ============================================================
// TOURNAMENT ROUTES
// routes/tournaments.js
// ============================================================
const express = require('express');
const router = express.Router();
const { sendGenericError, getAuthUser, isAdmin } = require('./helpers');

// ============================================================
// PUBLIC: LIST TOURNAMENTS
// ============================================================
router.get('/', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        const { data: tournaments, error } = await supabaseAdmin
            .from('tournaments')
            .select(`*, bookings:bookings(count)`)
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

// ============================================================
// JOIN TOURNAMENT
// ============================================================
router.post('/join', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader = req.headers['authorization'];
        
        if (!authHeader) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        
        if (authErr || !user) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        const { tournamentId, entryFee, paymentMethod, checkoutId } = req.body;
        let roomCode = null;

        if (paymentMethod === 'wallet') {
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin
                .rpc('join_tournament_wallet', {
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
            const { data: rpcRoomCode, error: rpcErr } = await supabaseAdmin
                .rpc('join_tournament_mpesa', {
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

// ============================================================
// ADMIN: LIST ALL TOURNAMENTS
// ============================================================
router.get('/admin/all', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        if (!isAdmin(req)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { data, error } = await supabaseAdmin
            .from('tournaments')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) return res.status(500).json({ error: error.message });

        res.json(data || []);

    } catch (err) {
        console.error('Admin tournaments error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// ADMIN: GET SINGLE TOURNAMENT
// ============================================================
router.get('/admin/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        if (!isAdmin(req)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { data, error } = await supabaseAdmin
            .from('tournaments')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error) return res.status(404).json({ error: 'Tournament not found' });

        res.json(data);

    } catch (err) {
        console.error('Admin tournament detail error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// ADMIN: CREATE TOURNAMENT
// ============================================================
router.post('/admin', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        if (!isAdmin(req)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

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

    } catch (err) {
        console.error('Admin create tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// ADMIN: UPDATE TOURNAMENT
// ============================================================
router.patch('/admin/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        if (!isAdmin(req)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

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

    } catch (err) {
        console.error('Admin update tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// ADMIN: DELETE TOURNAMENT
// ============================================================
router.delete('/admin/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        
        if (!isAdmin(req)) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const { error } = await supabaseAdmin
            .from('tournaments')
            .delete()
            .eq('id', req.params.id);

        if (error) return res.status(500).json({ error: error.message });

        res.json({ message: 'Tournament deleted' });

    } catch (err) {
        console.error('Admin delete tournament error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;