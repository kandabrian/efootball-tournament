// ============================================================
// ADMIN ROUTES
// routes/admin.js
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const { isAdmin, isValidUUID, sendGenericError } = require('./helpers');

// ── Admin auth middleware — applied to every route in this file ──
router.use((req, res, next) => {
    if (!isAdmin(req)) return res.status(403).json({ error: 'Unauthorized' });
    next();
});

// ============================================================
// ANALYTICS
// ============================================================
router.get('/analytics', async (req, res) => {
    try {
        const db = req.supabaseAdmin;
        const now = new Date();
        const mtdStart       = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString();
        const lastMonthEnd   = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
        const todayStr       = now.toISOString().substring(0, 10);
        const sevenDaysAgo   = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const thirtyDaysAgo  = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

        const [
            { data: completedMatches },
            { data: mtdMatches },
            { data: lastMonthMatches },
            { data: allUsers },
            { data: newTodayUsers },
            { data: newMtdUsers },
            { data: pendingWithdrawals },
            { data: paidWithdrawals },
            { data: mtdWithdrawals },
            { data: wallets },
            { data: activeTournaments },
            { data: dailyChart },
            { data: recentMatches },
            { count: disputedCount },
            { count: totalMatches },
        ] = await Promise.all([
            db.from('friend_matches').select('wager_amount, winner_prize').eq('status', 'completed'),
            db.from('friend_matches').select('wager_amount, winner_prize').eq('status', 'completed').gte('completed_at', mtdStart),
            db.from('friend_matches').select('wager_amount').eq('status', 'completed').gte('completed_at', lastMonthStart).lt('completed_at', lastMonthEnd),
            db.from('profiles').select('id, created_at'),
            db.from('profiles').select('id').gte('created_at', todayStr),
            db.from('profiles').select('id').gte('created_at', mtdStart),
            db.from('withdrawals').select('amount').in('status', ['pending', 'approved']),
            db.from('withdrawals').select('amount').in('status', ['paid', 'completed', 'processing']),
            db.from('withdrawals').select('amount').in('status', ['paid', 'completed', 'processing']).gte('requested_at', mtdStart),
            db.from('wallets').select('balance'),
            db.from('tournaments').select('id, entry_fee, max_players').in('status', ['open', 'live']),
            db.from('friend_matches').select('wager_amount, completed_at').eq('status', 'completed').gte('completed_at', thirtyDaysAgo).order('completed_at', { ascending: true }),
            db.from('friend_matches').select('creator_id, joiner_id').gte('created_at', sevenDaysAgo),
            db.from('friend_matches').select('id', { count: 'exact', head: true }).eq('status', 'disputed'),
            db.from('friend_matches').select('id', { count: 'exact', head: true }),
        ]);

        // Fee is 10% of total pot (wager_amount * 2 * 0.10 = wager_amount * 0.2)
        const calcFee = (m) => Number(m.wager_amount || 0) * 0.20;

        const allTimeFees   = (completedMatches || []).reduce((s, m) => s + calcFee(m), 0);
        const mtdFees       = (mtdMatches       || []).reduce((s, m) => s + calcFee(m), 0);
        const lastMonthFees = (lastMonthMatches  || []).reduce((s, m) => s + calcFee(m), 0);
        const allTimeVolume = (completedMatches || []).reduce((s, m) => s + Number(m.wager_amount || 0) * 2, 0);
        const mtdVolume     = (mtdMatches       || []).reduce((s, m) => s + Number(m.wager_amount || 0) * 2, 0);
        const feesGrowthPct = lastMonthFees > 0 ? Math.round(((mtdFees - lastMonthFees) / lastMonthFees) * 100) : null;
        const avgWager      = completedMatches?.length ? (allTimeVolume / 2) / completedMatches.length : 0;
        const disputeRate   = totalMatches > 0 ? Math.round(((disputedCount || 0) / totalMatches) * 100) : 0;
        const totalFloat    = (wallets || []).reduce((s, w) => s + Number(w.balance || 0), 0);
        const livePoolValue = (activeTournaments || []).reduce((s, t) => s + Number(t.entry_fee || 0) * Number(t.max_players || 0), 0);
        const pendingVolume = (pendingWithdrawals || []).reduce((s, w) => s + Number(w.amount || 0), 0);
        const allTimeWdVol  = (paidWithdrawals   || []).reduce((s, w) => s + Number(w.amount || 0), 0);
        const mtdWdVol      = (mtdWithdrawals    || []).reduce((s, w) => s + Number(w.amount || 0), 0);

        const activeUserSet = new Set();
        (recentMatches || []).forEach(m => {
            if (m.creator_id) activeUserSet.add(m.creator_id);
            if (m.joiner_id)  activeUserSet.add(m.joiner_id);
        });

        // Daily chart — last 30 days
        const dayMap = {};
        (dailyChart || []).forEach(m => {
            const day = (m.completed_at || '').substring(0, 10);
            if (!day) return;
            if (!dayMap[day]) dayMap[day] = { volume: 0, matches: 0 };
            dayMap[day].volume  += Number(m.wager_amount || 0) * 2;
            dayMap[day].matches += 1;
        });
        const chartArr = Object.entries(dayMap)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([date, v]) => ({ date, ...v }));

        res.json({
            revenue: { allTimeFees, mtdFees, lastMonthFees, feesGrowthPct, allTimeVolume, mtdVolume },
            matches: {
                totalCompleted: completedMatches?.length || 0,
                mtdCompleted:   mtdMatches?.length       || 0,
                avgWager:       Math.round(avgWager * 100) / 100,
                disputeRate,
                disputedCount:  disputedCount || 0,
                totalMatches:   totalMatches  || 0,
            },
            users: {
                total:       allUsers?.length     || 0,
                newToday:    newTodayUsers?.length || 0,
                newMtd:      newMtdUsers?.length   || 0,
                active7Days: activeUserSet.size,
            },
            withdrawals: {
                pendingCount:    pendingWithdrawals?.length || 0,
                pendingVolume,
                allTimeVolume:   allTimeWdVol,
                mtdVolume:       mtdWdVol,
                avgProcessingHrs: null,
            },
            platform: {
                totalFloat,
                activeTournaments: activeTournaments?.length || 0,
                livePoolValue,
            },
            dailyChart: chartArr,
        });
    } catch (err) {
        console.error('Analytics error:', err.message);
        return sendGenericError(res, 500, 'Failed to load analytics', err);
    }
});

// ============================================================
// WITHDRAWALS — GET list
// Browser calls: GET /admin/withdrawals?status=pending
// ============================================================
router.get('/withdrawals', async (req, res) => {
    try {
        const db     = req.supabaseAdmin;
        const status = req.query.status || 'pending';

        let query = db
            .from('withdrawals')
            .select(`
                id, user_id, amount, phone_number, status,
                requested_at, processed_at, review_notes,
                mpesa_transaction_id, mpesa_receipt_number,
                profiles:user_id ( username )
            `)
            .order('requested_at', { ascending: false })
            .limit(200);

        if (status !== 'all') query = query.eq('status', status);

        const { data, error } = await query;
        if (error) throw error;

        const result = (data || []).map(w => ({
            ...w,
            // Flatten so browser can use w.phone, w.username, w.name
            phone:    w.phone_number,
            username: w.profiles?.username || null,
            name:     w.profiles?.username || null,
            mpesa_code: w.mpesa_receipt_number || w.mpesa_transaction_id || null,
        }));

        res.json(result);
    } catch (err) {
        console.error('Get withdrawals error:', err.message);
        return sendGenericError(res, 500, 'Failed to fetch withdrawals', err);
    }
});

// ============================================================
// WITHDRAWALS — Approve
// Browser calls: POST /admin/withdrawals/:id/approve
// ============================================================
router.post('/withdrawals/:id/approve', async (req, res) => {
    try {
        const db    = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { notes } = req.body;

        const { data, error } = await db
            .from('withdrawals')
            .update({
                status:       'approved',
                review_notes: notes || 'Approved by admin',
                processed_at: new Date().toISOString(),
            })
            .eq('id', id)
            .in('status', ['pending', 'approved'])
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Withdrawal not found or already processed' });

        // Trigger M-Pesa B2C payout in background
        if (req.processMpesaWithdrawal) {
            req.processMpesaWithdrawal(id).catch(e =>
                console.error('Background M-Pesa payout error:', e.message)
            );
        }

        res.json({ message: 'Withdrawal approved', withdrawal: data });
    } catch (err) {
        console.error('Approve withdrawal error:', err.message);
        return sendGenericError(res, 500, 'Failed to approve withdrawal', err);
    }
});

// ============================================================
// WITHDRAWALS — Mark Paid (sets status to 'paid' with M-PESA code)
// Browser calls: POST /admin/withdrawals/:id/paid
// ============================================================
router.post('/withdrawals/:id/paid', async (req, res) => {
    try {
        const db    = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { mpesaCode } = req.body;

        const { data, error } = await db
            .from('withdrawals')
            .update({
                status:                 'paid',
                mpesa_transaction_id:   mpesaCode || null,
                mpesa_receipt_number:   mpesaCode || null,
                review_notes:           mpesaCode ? `Paid. M-PESA: ${mpesaCode}` : 'Marked paid by admin',
                processed_at:           new Date().toISOString(),
            })
            .eq('id', id)
            .in('status', ['pending', 'approved'])
            .select()
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Withdrawal not found or already processed' });

        res.json({ message: 'Withdrawal marked as paid', withdrawal: data });
    } catch (err) {
        console.error('Mark paid error:', err.message);
        return sendGenericError(res, 500, 'Failed to mark as paid', err);
    }
});

// ============================================================
// WITHDRAWALS — Reject + refund
// Browser calls: POST /admin/withdrawals/:id/reject
// ============================================================
router.post('/withdrawals/:id/reject', async (req, res) => {
    try {
        const db    = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid withdrawal ID' });

        const { notes } = req.body;

        const { data: wd, error: fetchErr } = await db
            .from('withdrawals')
            .select('id, user_id, amount, status')
            .eq('id', id)
            .single();

        if (fetchErr || !wd) return res.status(404).json({ error: 'Withdrawal not found' });
        if (!['pending', 'approved'].includes(wd.status))
            return res.status(400).json({ error: 'Withdrawal already processed' });

        // Refund wallet using the same RPC withdrawals.js uses
        const { error: refundErr } = await db.rpc('credit_wallet', {
            p_user_id: wd.user_id,
            p_amount:  Number(wd.amount),
        });
        if (refundErr) throw refundErr;

        const { error: updateErr } = await db
            .from('withdrawals')
            .update({
                status:       'rejected',
                review_notes: notes || 'Rejected by admin',
                processed_at: new Date().toISOString(),
            })
            .eq('id', id);

        if (updateErr) throw updateErr;

        res.json({ message: 'Withdrawal rejected and funds refunded' });
    } catch (err) {
        console.error('Reject withdrawal error:', err.message);
        return sendGenericError(res, 500, 'Failed to reject withdrawal', err);
    }
});

// ============================================================
// TOURNAMENTS
// ============================================================
router.get('/tournaments', async (req, res) => {
    try {
        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .select(`*, bookings:bookings(count)`)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json((data || []).map(t => ({
            ...t,
            current_players: t.bookings?.[0]?.count || 0,
        })));
    } catch (err) {
        console.error('Admin get tournaments error:', err.message);
        return sendGenericError(res, 500, 'Failed to fetch tournaments', err);
    }
});

router.post('/tournaments', async (req, res) => {
    try {
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;
        if (!name || !entry_fee || !start_time || !max_players)
            return res.status(400).json({ error: 'Missing required fields' });

        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .insert([{ name, entry_fee, start_time, max_players, room_code: room_code || null, status: status || 'open' }])
            .select()
            .single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (err) {
        console.error('Create tournament error:', err.message);
        return sendGenericError(res, 500, 'Failed to create tournament', err);
    }
});

router.patch('/tournaments/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid ID' });
        const { name, entry_fee, start_time, max_players, room_code, status } = req.body;

        const { data, error } = await req.supabaseAdmin
            .from('tournaments')
            .update({ name, entry_fee, start_time, max_players, room_code, status })
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('Update tournament error:', err.message);
        return sendGenericError(res, 500, 'Failed to update tournament', err);
    }
});

router.delete('/tournaments/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid ID' });

        const { error } = await req.supabaseAdmin.from('tournaments').delete().eq('id', id);
        if (error) throw error;
        res.json({ message: 'Tournament deleted' });
    } catch (err) {
        console.error('Delete tournament error:', err.message);
        return sendGenericError(res, 500, 'Failed to delete tournament', err);
    }
});

// ============================================================
// FRIEND MATCHES — GET list
// Browser calls: GET /admin/friend-matches?status=pending_review
// ============================================================
router.get('/friend-matches', async (req, res) => {
    try {
        const db     = req.supabaseAdmin;
        const status = req.query.status || 'all';

        let query = db
            .from('friend_matches')
            .select(`
                id, match_code, status, creator_id, joiner_id,
                wager_amount, winner_prize, winner_id,
                creator_team, joiner_team,
                creator_screenshot_url, joiner_screenshot_url,
                declared_score_creator, declared_score_joiner,
                declared_score_by, declared_winner_id,
                settlement_method, dispute_reason,
                created_at, started_at, completed_at,
                result_post_deadline
            `)
            .order('created_at', { ascending: false })
            .limit(300);

        if (status !== 'all') query = query.eq('status', status);

        const { data: matches, error } = await query;
        if (error) throw error;

        // Enrich with usernames in one query
        const userIds = new Set();
        (matches || []).forEach(m => {
            if (m.creator_id) userIds.add(m.creator_id);
            if (m.joiner_id)  userIds.add(m.joiner_id);
        });

        let profileMap = {};
        if (userIds.size > 0) {
            const { data: profiles } = await db
                .from('profiles')
                .select('id, username')
                .in('id', Array.from(userIds));
            (profiles || []).forEach(p => { profileMap[p.id] = p.username; });
        }

        res.json((matches || []).map(m => ({
            ...m,
            creator_username: profileMap[m.creator_id] || null,
            joiner_username:  profileMap[m.joiner_id]  || null,
        })));
    } catch (err) {
        console.error('Admin get friend matches error:', err.message);
        return sendGenericError(res, 500, 'Failed to fetch matches', err);
    }
});

// ============================================================
// FRIEND MATCHES — GET single (used by override + dispute modals)
// Browser calls: GET /admin/friend-matches/:id
// ============================================================
router.get('/friend-matches/:id', async (req, res) => {
    try {
        const db    = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        const { data: match, error } = await db
            .from('friend_matches')
            .select(`
                id, match_code, status, creator_id, joiner_id,
                wager_amount, winner_prize, winner_id,
                creator_team, joiner_team,
                creator_screenshot_url, joiner_screenshot_url,
                declared_score_creator, declared_score_joiner,
                declared_score_by, declared_winner_id,
                settlement_method, dispute_reason,
                created_at, started_at, completed_at,
                result_post_deadline, disputed_at
            `)
            .eq('id', id)
            .single();

        if (error || !match) return res.status(404).json({ error: 'Match not found' });

        const { data: profiles } = await db
            .from('profiles')
            .select('id, username')
            .in('id', [match.creator_id, match.joiner_id].filter(Boolean));

        const profileMap = {};
        (profiles || []).forEach(p => { profileMap[p.id] = p.username; });

        res.json({
            ...match,
            creator_username: profileMap[match.creator_id] || null,
            joiner_username:  profileMap[match.joiner_id]  || null,
        });
    } catch (err) {
        console.error('Admin get match error:', err.message);
        return sendGenericError(res, 500, 'Failed to fetch match', err);
    }
});

// ============================================================
// FRIEND MATCHES — DELETE
// Browser calls: DELETE /admin/friend-matches/:id
// ============================================================
router.delete('/friend-matches/:id', async (req, res) => {
    try {
        const db    = req.supabaseAdmin;
        const { id } = req.params;
        if (!isValidUUID(id)) return res.status(400).json({ error: 'Invalid match ID' });

        // Clean up screenshots from storage
        const { data: match } = await db
            .from('friend_matches')
            .select('creator_screenshot_url, joiner_screenshot_url')
            .eq('id', id)
            .single();

        if (match) {
            const paths = [match.creator_screenshot_url, match.joiner_screenshot_url]
                .filter(Boolean)
                .map(url => {
                    try {
                        const u = new URL(url);
                        const m = u.pathname.match(/\/storage\/v1\/object\/public\/(?:screenshots|match-screenshots)\/(.+)/);
                        return m ? m[1] : null;
                    } catch { return null; }
                })
                .filter(Boolean);

            if (paths.length > 0) {
                await db.storage.from('screenshots').remove(paths)
                    .catch(e => console.warn('Screenshot cleanup warning:', e.message));
            }
        }

        const { error } = await db.from('friend_matches').delete().eq('id', id);
        if (error) throw error;

        res.json({ message: 'Match deleted' });
    } catch (err) {
        console.error('Admin delete match error:', err.message);
        return sendGenericError(res, 500, 'Failed to delete match', err);
    }
});

// ============================================================
// FORCE WINNER  —  uses force_winner RPC (force_winner_48916)
// Browser calls: POST /admin/force-winner/:id
// Body: { winnerId, resolution, adminNotes }
// resolution: 'winner' | 'draw'
// ============================================================
router.post('/force-winner/:id', async (req, res) => {
    try {
        const db      = req.supabaseAdmin;
        const matchId = req.params.id;
        if (!isValidUUID(matchId)) return res.status(400).json({ error: 'Invalid match ID' });

        const { winnerId, resolution, adminNotes } = req.body;

        if (!adminNotes?.trim())
            return res.status(400).json({ error: 'Admin notes are required' });
        if (!resolution || !['winner', 'draw'].includes(resolution))
            return res.status(400).json({ error: 'resolution must be "winner" or "draw"' });
        if (resolution === 'winner' && !isValidUUID(winnerId))
            return res.status(400).json({ error: 'Valid winnerId is required when resolution is "winner"' });

        const isDraw  = resolution === 'draw';
        const adminIp = req.ip || req.headers['x-forwarded-for'] || 'unknown';

        const { error: rpcErr } = await db.rpc('force_winner', {
            p_match_id:    matchId,
            p_winner_id:   isDraw ? null : winnerId,
            p_is_draw:     isDraw,
            p_admin_notes: adminNotes.trim(),
            p_admin_ip:    adminIp,
        });

        if (rpcErr) {
            console.error('force_winner RPC error:', rpcErr.message);
            return res.status(400).json({ error: rpcErr.message || 'Failed to settle match' });
        }

        const { data: settled } = await db
            .from('friend_matches')
            .select('winner_id, winner_prize, status')
            .eq('id', matchId)
            .single();

        console.log(`✅ Admin force-winner: match=${matchId} resolution=${resolution} winner=${winnerId || 'draw'}`);

        res.json({
            message:   isDraw ? 'Match declared a draw. Both players refunded.' : 'Winner declared and prize paid.',
            resolution,
            winnerId:  settled?.winner_id   || null,
            prizePaid: settled?.winner_prize || null,
            status:    settled?.status       || 'completed',
        });
    } catch (err) {
        console.error('Force winner error:', err.message);
        return sendGenericError(res, 500, 'Failed to settle match', err);
    }
});

// ============================================================
// RESOLVE DISPUTE  —  uses resolve_dispute RPC (resolve_dispute_48915)
// Browser calls: POST /admin/resolve-dispute/:id
// Body: { winnerId, resolution, adminNotes }
// ============================================================
router.post('/resolve-dispute/:id', async (req, res) => {
    try {
        const db      = req.supabaseAdmin;
        const matchId = req.params.id;
        if (!isValidUUID(matchId)) return res.status(400).json({ error: 'Invalid match ID' });

        const { winnerId, resolution, adminNotes } = req.body;

        if (!adminNotes?.trim())
            return res.status(400).json({ error: 'Admin notes are required' });
        if (!resolution || !['winner', 'draw'].includes(resolution))
            return res.status(400).json({ error: 'resolution must be "winner" or "draw"' });
        if (resolution === 'winner' && !isValidUUID(winnerId))
            return res.status(400).json({ error: 'Valid winnerId is required when resolution is "winner"' });

        const isDraw  = resolution === 'draw';
        const adminIp = req.ip || req.headers['x-forwarded-for'] || 'unknown';

        const { error: rpcErr } = await db.rpc('resolve_dispute', {
            p_match_id:    matchId,
            p_winner_id:   isDraw ? null : winnerId,
            p_is_draw:     isDraw,
            p_admin_notes: adminNotes.trim(),
            p_admin_ip:    adminIp,
        });

        if (rpcErr) {
            console.error('resolve_dispute RPC error:', rpcErr.message);
            return res.status(400).json({ error: rpcErr.message || 'Failed to resolve dispute' });
        }

        const { data: settled } = await db
            .from('friend_matches')
            .select('winner_id, winner_prize, status')
            .eq('id', matchId)
            .single();

        console.log(`✅ Admin resolve-dispute: match=${matchId} resolution=${resolution} winner=${winnerId || 'draw'}`);

        res.json({
            message:   isDraw ? 'Dispute resolved as draw. Both players refunded.' : 'Dispute resolved. Winner paid.',
            resolution,
            winnerId:  settled?.winner_id   || null,
            prizePaid: settled?.winner_prize || null,
            status:    settled?.status       || 'completed',
        });
    } catch (err) {
        console.error('Resolve dispute error:', err.message);
        return sendGenericError(res, 500, 'Failed to resolve dispute', err);
    }
});

module.exports = router;