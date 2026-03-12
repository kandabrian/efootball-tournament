// ============================================================
// ADMIN ROUTES
// routes/admin.js
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { isAdmin, isValidUUID } = require('./helpers');
const { deleteMatchScreenshots } = require('../jobs/matchJobs');

router.use((req, res, next) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    next();
});

async function settleMatch(supabaseAdmin, matchId, winnerId, resolution, adminNotes) {
    const { data: match, error: matchErr } = await supabaseAdmin
        .from('friend_matches')
        .select('id, status, creator_id, joiner_id, winner_prize, wager_amount')
        .eq('id', matchId)
        .single();

    if (matchErr || !match) throw new Error('Match not found');

    const SETTLEABLE = [
        'active', 'pending_review', 'disputed',
        'awaiting_confirmation', 'penalty_shootout',
        'no_show_forfeit'
    ];
    if (!SETTLEABLE.includes(match.status)) {
        throw new Error(`Cannot settle match with status: ${match.status}`);
    }

    if (resolution === 'draw') {
        const { error: e1 } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: match.creator_id,
            p_amount:  match.wager_amount,
        });
        if (e1) throw new Error('Failed to refund creator: ' + e1.message);

        const { error: e2 } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: match.joiner_id,
            p_amount:  match.wager_amount,
        });
        if (e2) throw new Error('Failed to refund joiner: ' + e2.message);

        await supabaseAdmin
            .from('friend_matches')
            .update({
                status:            'completed',
                winner_id:         null,
                loser_id:          null,
                creator_result:    'draw',
                joiner_result:     'draw',
                settlement_method: 'admin_draw',
                admin_notes:       adminNotes || null,
                completed_at:      new Date().toISOString(),
            })
            .eq('id', matchId);

        return { winnerId: null, prizePaid: 0, resolution: 'draw' };
    }

    if (!isValidUUID(winnerId)) throw new Error('Invalid winner ID');
    if (winnerId !== match.creator_id && winnerId !== match.joiner_id) {
        throw new Error('Winner must be a participant of this match');
    }

    const loserId       = winnerId === match.creator_id ? match.joiner_id : match.creator_id;
    const creatorResult = winnerId === match.creator_id ? 'won' : 'lost';
    const joinerResult  = winnerId === match.joiner_id  ? 'won' : 'lost';

    const { error: creditErr } = await supabaseAdmin.rpc('credit_wallet', {
        p_user_id: winnerId,
        p_amount:  match.winner_prize,
    });
    if (creditErr) throw new Error('Failed to credit winner: ' + creditErr.message);

    await supabaseAdmin
        .from('friend_matches')
        .update({
            status:            'completed',
            winner_id:         winnerId,
            loser_id:          loserId,
            creator_result:    creatorResult,
            joiner_result:     joinerResult,
            settlement_method: 'admin',
            admin_notes:       adminNotes || null,
            completed_at:      new Date().toISOString(),
        })
        .eq('id', matchId);

    try {
        await supabaseAdmin.from('match_notifications').insert({
            match_id:     matchId,
            recipient_id: winnerId,
            type:         'match_won',
            payload:      JSON.stringify({ prizePaid: match.winner_prize, adminSettled: true }),
            read:         false,
            created_at:   new Date().toISOString(),
        });
    } catch (e) { console.warn('[Admin] winner notify failed:', e.message); }

    try {
        await supabaseAdmin.from('match_notifications').insert({
            match_id:     matchId,
            recipient_id: loserId,
            type:         'match_lost',
            payload:      JSON.stringify({ adminSettled: true }),
            read:         false,
            created_at:   new Date().toISOString(),
        });
    } catch (e) { console.warn('[Admin] loser notify failed:', e.message); }

    return { winnerId, prizePaid: match.winner_prize, resolution: 'winner' };
}

// ============================================================
// FRIEND MATCHES – list
// ============================================================
router.get('/friend-matches', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const status = req.query.status || 'all';

        let query = supabaseAdmin
            .from('friend_matches')
            .select(`
                id, match_code, efootball_room_code, status,
                creator_id, joiner_id,
                creator_team, joiner_team,
                wager_amount, winner_prize, winner_id,
                declared_score_creator, declared_score_joiner,
                declared_score_by, declared_winner_id,
                creator_screenshot_url, joiner_screenshot_url,
                settlement_method, dispute_reason,
                created_at, started_at, completed_at,
                result_post_deadline
            `)
            .order('created_at', { ascending: false })
            .limit(200);

        if (status !== 'all') query = query.eq('status', status);

        const { data: matches, error } = await query;
        if (error) throw error;

        const userIds = new Set();
        (matches || []).forEach(m => {
            if (m.creator_id) userIds.add(m.creator_id);
            if (m.joiner_id)  userIds.add(m.joiner_id);
        });

        let profileMap = {};
        const idArray = Array.from(userIds);
        if (idArray.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles')
                .select('id, username')
                .in('id', idArray);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }

        res.json((matches || []).map(m => ({
            ...m,
            creator_username: profileMap[m.creator_id] || null,
            joiner_username:  profileMap[m.joiner_id]  || null,
        })));
    } catch (err) {
        console.error('Admin friend-matches list error:', err.message);
        res.status(500).json({ error: 'Failed to fetch matches' });
    }
});

// ============================================================
// FRIEND MATCH – single
// ============================================================
router.get('/friend-matches/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        const { data: match, error } = await supabaseAdmin
            .from('friend_matches')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !match) return res.status(404).json({ error: 'Match not found' });

        const ids = [match.creator_id, match.joiner_id].filter(Boolean);
        let profileMap = {};
        if (ids.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles')
                .select('id, username')
                .in('id', ids);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }

        res.json({
            ...match,
            creator_username: profileMap[match.creator_id] || null,
            joiner_username:  profileMap[match.joiner_id]  || null,
        });
    } catch (err) {
        console.error('Admin friend-match detail error:', err.message);
        res.status(500).json({ error: 'Failed to fetch match' });
    }
});

// ============================================================
// DELETE A FRIEND MATCH
// ============================================================
router.delete('/friend-matches/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        await deleteMatchScreenshots(supabaseAdmin, id);

        const { error } = await supabaseAdmin
            .from('friend_matches')
            .delete()
            .eq('id', id);

        if (error) throw error;
        res.json({ message: 'Match deleted successfully' });
    } catch (err) {
        console.error('Admin delete friend match error:', err.message);
        res.status(500).json({ error: 'Failed to delete match' });
    }
});

// ============================================================
// FORCE WINNER
// ============================================================
router.post('/force-winner/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        const { winnerId, resolution, adminNotes } = req.body;
        if (!resolution)           return res.status(400).json({ error: 'resolution is required' });
        if (!adminNotes?.trim())   return res.status(400).json({ error: 'Admin notes are required' });
        if (resolution === 'winner' && !winnerId) return res.status(400).json({ error: 'winnerId is required' });

        const result = await settleMatch(supabaseAdmin, id, winnerId, resolution, adminNotes.trim());
        console.log(`[Admin] force-winner matchId=${id} resolution=${resolution} winner=${winnerId || 'draw'}`);
        res.json({
            message: resolution === 'draw' ? 'Match settled as draw. Both players refunded.' : 'Winner declared. Prize credited.',
            ...result,
        });
    } catch (err) {
        console.error('Admin force-winner error:', err.message);
        res.status(400).json({ error: err.message });
    }
});

// ============================================================
// APPROVE RESULT
// ============================================================
router.post('/approve-result/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        const { winnerId, resolution, adminNotes } = req.body;
        if (!resolution)           return res.status(400).json({ error: 'resolution is required' });
        if (!adminNotes?.trim())   return res.status(400).json({ error: 'Admin notes are required' });
        if (resolution === 'winner' && !winnerId) return res.status(400).json({ error: 'winnerId is required' });

        const result = await settleMatch(supabaseAdmin, id, winnerId, resolution, adminNotes.trim());
        console.log(`[Admin] approve-result matchId=${id} resolution=${resolution} winner=${winnerId || 'draw'}`);
        res.json({
            message: resolution === 'draw' ? 'Result approved — draw.' : 'Result approved. Winner credited.',
            ...result,
        });
    } catch (err) {
        console.error('Admin approve-result error:', err.message);
        res.status(400).json({ error: err.message });
    }
});

// ============================================================
// RESOLVE DISPUTE
// ============================================================
router.post('/resolve-dispute/:id', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        const { winnerId, resolution, adminNotes } = req.body;
        if (!resolution)           return res.status(400).json({ error: 'resolution is required' });
        if (!adminNotes?.trim())   return res.status(400).json({ error: 'Admin notes are required' });
        if (resolution === 'winner' && !winnerId) return res.status(400).json({ error: 'winnerId is required' });

        const result = await settleMatch(supabaseAdmin, id, winnerId, resolution, adminNotes.trim());
        console.log(`[Admin] resolve-dispute matchId=${id} resolution=${resolution} winner=${winnerId || 'draw'}`);
        res.json({
            message: resolution === 'draw' ? 'Dispute resolved — draw. Both refunded.' : 'Dispute resolved. Winner credited.',
            ...result,
        });
    } catch (err) {
        console.error('Admin resolve-dispute error:', err.message);
        res.status(400).json({ error: err.message });
    }
});

// ============================================================
// WITHDRAWALS – list
// GET /admin/withdrawals?status=
// ============================================================
router.get('/withdrawals', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const status = req.query.status || 'all';

        let query = supabaseAdmin
            .from('withdrawals')
            .select('id, user_id, amount, phone, phone_number, name, reference_id, status, requested_at, processed_at, review_notes, mpesa_code, mpesa_transaction_id, reject_reason')
            .order('requested_at', { ascending: false })
            .limit(200);

        if (status !== 'all') query = query.eq('status', status);

        const { data, error } = await query;
        if (error) throw error;

        // Enrich with usernames from profiles
        const userIds = [...new Set((data || []).map(w => w.user_id).filter(Boolean))];
        let profileMap = {};
        if (userIds.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles')
                .select('id, username')
                .in('id', userIds);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }

        res.json((data || []).map(w => ({
            ...w,
            phone:    w.phone || w.phone_number || null,
            username: profileMap[w.user_id] || null,
        })));

    } catch (err) {
        console.error('Admin withdrawals list error:', err.message);
        res.status(500).json({ error: 'Failed to fetch withdrawals' });
    }
});

// ============================================================
// WITHDRAWALS – approve
// POST /admin/withdrawals/:id/approve
// ============================================================
router.post('/withdrawals/:id/approve', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { notes } = req.body;

        const { data, error } = await supabaseAdmin
            .from('withdrawals')
            .update({
                status:       'paid',
                review_notes: notes || 'Approved by admin',
                processed_at: new Date().toISOString(),
                paid_at:      new Date().toISOString(),
            })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        res.json({ message: 'Withdrawal approved', withdrawal: data });
    } catch (err) {
        console.error('Admin approve withdrawal error:', err.message);
        res.status(500).json({ error: 'Failed to approve withdrawal' });
    }
});

// ============================================================
// WITHDRAWALS – reject
// POST /admin/withdrawals/:id/reject
// ============================================================
router.post('/withdrawals/:id/reject', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { notes } = req.body;

        const { data: wd, error: fetchErr } = await supabaseAdmin
            .from('withdrawals')
            .select('id, user_id, amount, status')
            .eq('id', id)
            .single();

        if (fetchErr || !wd) return res.status(404).json({ error: 'Withdrawal not found' });
        if (wd.status === 'rejected' || wd.status === 'paid') {
            return res.status(400).json({ error: `Cannot reject a ${wd.status} withdrawal` });
        }

        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', {
            p_user_id: wd.user_id,
            p_amount:  parseFloat(wd.amount),
        });
        if (refundErr) throw new Error('Failed to refund wallet: ' + refundErr.message);

        await supabaseAdmin
            .from('withdrawals')
            .update({
                status:        'rejected',
                reject_reason: notes || 'Rejected by admin',
                review_notes:  notes || 'Rejected by admin',
                rejected_at:   new Date().toISOString(),
                processed_at:  new Date().toISOString(),
            })
            .eq('id', id);

        res.json({ message: 'Withdrawal rejected and funds refunded' });
    } catch (err) {
        console.error('Admin reject withdrawal error:', err.message);
        res.status(500).json({ error: 'Failed to reject withdrawal' });
    }
});

// ============================================================
// TOURNAMENTS – CRUD
// ============================================================
router.get('/tournaments', async (req, res) => {
    try {
        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .select('*')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Admin tournaments list error:', err.message);
        res.status(500).json({ error: 'Failed to fetch tournaments' });
    }
});

router.post('/tournaments', async (req, res) => {
    try {
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        if (!name || !entry_fee || !start_time || !max_players) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .insert([{ name, entry_fee, start_time, max_players, room_code: room_code || null, status: status || 'open' }])
            .select()
            .single();
        if (error) throw error;
        res.status(201).json(data);
    } catch (err) {
        console.error('Admin create tournament error:', err.message);
        res.status(500).json({ error: 'Failed to create tournament' });
    }
});

router.patch('/tournaments/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid tournament ID' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .update({ name, entry_fee, start_time, max_players, room_code, status, updated_at: new Date().toISOString() })
            .eq('id', id)
            .select()
            .single();
        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('Admin update tournament error:', err.message);
        res.status(500).json({ error: 'Failed to update tournament' });
    }
});

router.delete('/tournaments/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid tournament ID' });
        const { error } = await req.supabaseAdmin.from('tournaments').delete().eq('id', id);
        if (error) throw error;
        res.json({ message: 'Tournament deleted' });
    } catch (err) {
        console.error('Admin delete tournament error:', err.message);
        res.status(500).json({ error: 'Failed to delete tournament' });
    }
});

// ============================================================
// ANALYTICS
// ============================================================
router.get('/analytics', async (req, res) => {
    try {
        const db = req.supabaseAdmin;
        const now = new Date();
        const startOfMonth     = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString();
        const endOfLastMonth   = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59).toISOString();
        const sevenDaysAgo     = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const startOfToday     = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
        const thirtyDaysAgo    = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

        const [
            allMatches, mtdMatches, lastMonthMatches,
            allUsers, newTodayUsers, newMtdUsers, activeUsers,
            allWithdrawals, mtdWithdrawals, pendingWithdrawals,
            allWallets, activeTournaments, dailyData,
        ] = await Promise.all([
            db.from('friend_matches').select('id, wager_amount, winner_prize, status, created_at').eq('status', 'completed'),
            db.from('friend_matches').select('id, wager_amount, winner_prize').eq('status', 'completed').gte('created_at', startOfMonth),
            db.from('friend_matches').select('id, wager_amount, winner_prize').eq('status', 'completed').gte('created_at', startOfLastMonth).lte('created_at', endOfLastMonth),
            db.from('profiles').select('id', { count: 'exact', head: true }),
            db.from('profiles').select('id', { count: 'exact', head: true }).gte('created_at', startOfToday),
            db.from('profiles').select('id', { count: 'exact', head: true }).gte('created_at', startOfMonth),
            db.from('profiles').select('id', { count: 'exact', head: true }).gte('updated_at', sevenDaysAgo),
            db.from('withdrawals').select('amount, status, requested_at, processed_at').in('status', ['completed', 'paid']),
            db.from('withdrawals').select('amount').in('status', ['completed', 'paid']).gte('processed_at', startOfMonth),
            db.from('withdrawals').select('id, amount').in('status', ['pending', 'approved']),
            db.from('wallets').select('balance'),
            db.from('tournaments').select('id, entry_fee, max_players').in('status', ['open', 'live']),
            db.from('friend_matches').select('created_at, wager_amount').eq('status', 'completed').gte('created_at', thirtyDaysAgo),
        ]);

        const allTimeFees   = (allMatches.data || []).reduce((s, m) => s + (m.wager_amount * 2 * 0.10), 0);
        const allTimeVolume = (allMatches.data || []).reduce((s, m) => s + (m.wager_amount * 2), 0);
        const mtdFees       = (mtdMatches.data || []).reduce((s, m) => s + (m.wager_amount * 2 * 0.10), 0);
        const mtdVolume     = (mtdMatches.data || []).reduce((s, m) => s + (m.wager_amount * 2), 0);
        const lastMonthFees = (lastMonthMatches.data || []).reduce((s, m) => s + (m.wager_amount * 2 * 0.10), 0);
        const feesGrowthPct = lastMonthFees > 0 ? Math.round(((mtdFees - lastMonthFees) / lastMonthFees) * 100) : null;

        const totalMatches = (allMatches.data || []).length;
        const { count: totalAllStatuses } = await db.from('friend_matches').select('id', { count: 'exact', head: true });
        const { count: disputedCount }    = await db.from('friend_matches').select('id', { count: 'exact', head: true }).eq('status', 'disputed');
        const disputeRate = totalAllStatuses > 0 ? Math.round(((disputedCount || 0) / totalAllStatuses) * 100) : 0;
        const avgWager    = totalMatches > 0 ? (allMatches.data || []).reduce((s, m) => s + m.wager_amount, 0) / totalMatches : 0;

        const wdAllTime    = (allWithdrawals.data || []).reduce((s, w) => s + parseFloat(w.amount), 0);
        const wdMtd        = (mtdWithdrawals.data || []).reduce((s, w) => s + parseFloat(w.amount), 0);
        const wdPendingVol = (pendingWithdrawals.data || []).reduce((s, w) => s + parseFloat(w.amount), 0);
        const processed    = (allWithdrawals.data || []).filter(w => w.requested_at && w.processed_at);
        const avgProcessHrs = processed.length > 0
            ? Math.round(processed.reduce((s, w) => s + (new Date(w.processed_at) - new Date(w.requested_at)), 0) / processed.length / 3600000)
            : null;

        const totalFloat    = (allWallets.data || []).reduce((s, w) => s + parseFloat(w.balance || 0), 0);
        const livePoolValue = (activeTournaments.data || []).reduce((s, t) => s + (t.entry_fee * t.max_players), 0);

        const chartMap = {};
        (dailyData.data || []).forEach(m => {
            const day = m.created_at.substring(0, 10);
            if (!chartMap[day]) chartMap[day] = { matches: 0, volume: 0 };
            chartMap[day].matches++;
            chartMap[day].volume += m.wager_amount * 2;
        });
        const dailyChart = [];
        for (let i = 29; i >= 0; i--) {
            const d   = new Date(Date.now() - i * 86400000);
            const key = d.toISOString().substring(0, 10);
            dailyChart.push({ date: key, matches: chartMap[key]?.matches || 0, volume: chartMap[key]?.volume || 0 });
        }

        res.json({
            revenue: {
                allTimeFees:   Math.round(allTimeFees * 100) / 100,
                allTimeVolume: Math.round(allTimeVolume * 100) / 100,
                mtdFees:       Math.round(mtdFees * 100) / 100,
                mtdVolume:     Math.round(mtdVolume * 100) / 100,
                lastMonthFees: Math.round(lastMonthFees * 100) / 100,
                feesGrowthPct,
            },
            matches: {
                totalCompleted: totalMatches,
                mtdCompleted:   (mtdMatches.data || []).length,
                avgWager:       Math.round(avgWager * 100) / 100,
                disputeRate,
                disputedCount:  disputedCount || 0,
                totalMatches:   totalAllStatuses || 0,
            },
            users: {
                total:       allUsers.count      || 0,
                newToday:    newTodayUsers.count  || 0,
                newMtd:      newMtdUsers.count    || 0,
                active7Days: activeUsers.count    || 0,
            },
            withdrawals: {
                allTimeVolume:    Math.round(wdAllTime * 100) / 100,
                mtdVolume:        Math.round(wdMtd * 100) / 100,
                pendingCount:     (pendingWithdrawals.data || []).length,
                pendingVolume:    Math.round(wdPendingVol * 100) / 100,
                avgProcessingHrs: avgProcessHrs,
            },
            platform: {
                totalFloat:        Math.round(totalFloat * 100) / 100,
                activeTournaments: (activeTournaments.data || []).length,
                livePoolValue:     Math.round(livePoolValue * 100) / 100,
            },
            dailyChart,
        });
    } catch (err) {
        console.error('Admin analytics error:', err.message);
        res.status(500).json({ error: 'Failed to load analytics' });
    }
});

module.exports = router;