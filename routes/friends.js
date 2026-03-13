// ============================================================
// FRIEND MATCHES ROUTES – No OCR, all uploads go to admin review
// ============================================================

'use strict';

const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const {
    validateEFootballCode,
    sendGenericError,
    getAuthUser,
    extractTeamNames,
    sendMatchNotification,
    isValidUUID,
    EFOOTBALL_TEAMS,
} = require('./helpers');

// ============================================================
// MULTER CONFIG
// ============================================================
const upload = multer({
    storage:    multer.memoryStorage(),
    limits:     { fileSize: 10 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/webp'];
        if (allowed.includes(file.mimetype)) cb(null, true);
        else cb(new Error('Only JPEG, PNG, and WebP images are allowed'));
    }
});

function requireValidMatchId(matchId, res) {
    if (!isValidUUID(matchId)) {
        res.status(400).json({ error: 'Invalid match ID format' });
        return false;
    }
    return true;
}

function mimeToExt(mimetype) {
    if (mimetype === 'image/png')  return 'png';
    if (mimetype === 'image/webp') return 'webp';
    return 'jpg';
}

// ============================================================
// CREATE MATCH
// ============================================================
router.post('/create-match', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { wagerAmount, efootballCode } = req.body;
        const parsedWager = Number(wagerAmount);
        if (!wagerAmount || isNaN(parsedWager) || parsedWager < 50)
            return res.status(400).json({ error: 'Minimum wager is KES 50' });
        if (!efootballCode)
            return res.status(400).json({ error: 'eFootball room code is required' });
        if (!validateEFootballCode(efootballCode))
            return res.status(400).json({ error: 'Invalid eFootball code format' });

        const { data: creatorProfile } = await supabaseAdmin
            .from('profiles').select('team_name').eq('id', user.id).single();
        if (!creatorProfile?.team_name)
            return res.status(400).json({ error: 'Please set your team name in profile first' });

        const matchCode = `VUM-${efootballCode.toUpperCase()}`;
        const { data: existing } = await supabaseAdmin
            .from('friend_matches').select('id').eq('match_code', matchCode)
            .eq('status', 'pending').gte('expires_at', new Date().toISOString()).maybeSingle();
        if (existing)
            return res.status(400).json({ error: 'This eFootball code is already in use' });

        const expiresAt   = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const platformFee = Math.floor(parsedWager * 0.10);
        const winnerPrize = (parsedWager * 2) - platformFee;

        const { data: matchResult, error: rpcErr } = await supabaseAdmin.rpc('create_match_and_deduct', {
            p_user_id: user.id,
            p_wager_amount: parsedWager,
            p_platform_fee: platformFee,
            p_winner_prize: winnerPrize,
            p_match_code: matchCode,
            p_efootball_code: efootballCode.toUpperCase(),
            p_creator_team: creatorProfile.team_name,
            p_expires_at: expiresAt,
        });

        if (rpcErr) {
            const msg = rpcErr.message?.toLowerCase().includes('insufficient')
                ? 'Insufficient balance' : 'Failed to create match. Please try again.';
            return res.status(400).json({ error: msg });
        }

        const match = Array.isArray(matchResult) ? matchResult[0] : matchResult;

        res.status(201).json({
            matchId: match.id,
            efootballCode: efootballCode.toUpperCase(),
            wagerAmount: parsedWager,
            winnerPrize,
            platformFee,
            expiresAt,
            message: 'Match created! Share the eFootball room code with your opponent.',
        });
    } catch (err) {
        console.error('Create match error:', err.message);
        res.status(500).json({ error: 'Failed to create match' });
    }
});

// ============================================================
// JOIN MATCH
// ============================================================
router.post('/join-match', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { efootballCode } = req.body;
        if (!efootballCode) return res.status(400).json({ error: 'eFootball room code is required' });
        if (!validateEFootballCode(efootballCode)) return res.status(400).json({ error: 'Invalid eFootball code format' });

        const { data: joinerProfile } = await supabaseAdmin
            .from('profiles').select('team_name').eq('id', user.id).single();
        if (!joinerProfile?.team_name)
            return res.status(400).json({ error: 'Please set your team name in profile first' });

        const resultPostDeadline = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const { data: updatedMatch, error: rpcErr } = await supabaseAdmin.rpc('join_match_and_deduct', {
            p_match_code: `VUM-${efootballCode.toUpperCase()}`,
            p_joiner_id: user.id,
            p_joiner_team: joinerProfile.team_name,
            p_result_post_deadline: resultPostDeadline,
        });

        if (rpcErr) {
            const msg = rpcErr.message?.toLowerCase().includes('not found')     ? 'Invalid eFootball code. No active match found.'
                : rpcErr.message?.toLowerCase().includes('own match')           ? 'You cannot join your own match.'
                : rpcErr.message?.toLowerCase().includes('already joined')      ? 'Match already has two players.'
                : rpcErr.message?.toLowerCase().includes('expired')             ? 'Match code has expired.'
                : rpcErr.message?.toLowerCase().includes('insufficient')        ? 'Insufficient balance.'
                : 'Failed to join match. Please try again.';
            return res.status(400).json({ error: msg });
        }

        await sendMatchNotification(supabaseAdmin, updatedMatch.id, updatedMatch.creator_id, 'match_started', {
            message: 'Your opponent joined! You have 30 minutes to play and submit results.',
            resultPostDeadline,
        });

        // Fetch creator profile so dashboard War Room has correct team/username
        let creatorUsername = null;
        let creatorTeam     = updatedMatch.creator_team || null;
        const { data: creatorProfile } = await supabaseAdmin
            .from('profiles').select('username, team_name').eq('id', updatedMatch.creator_id).maybeSingle();
        if (creatorProfile) {
            creatorUsername = creatorProfile.username;
            if (!creatorTeam) creatorTeam = creatorProfile.team_name;
        }

        res.status(200).json({
            message: 'Successfully joined match!',
            matchId: updatedMatch.id,
            wagerAmount: updatedMatch.wager_amount,
            winnerPrize: updatedMatch.winner_prize,
            opponentId: updatedMatch.creator_id,
            creatorId: updatedMatch.creator_id,
            creatorTeam,
            creatorUsername,
            resultPostDeadline,
        });
    } catch (err) {
        console.error('Join match error:', err.message);
        res.status(500).json({ error: 'Failed to join match' });
    }
});

// ============================================================
// MY MATCHES
// ============================================================
router.get('/my-matches', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Unauthorized' });

        const { data: matches, error } = await supabaseAdmin
            .from('friend_matches')
            .select(`
                id, match_code, status, creator_id, joiner_id,
                wager_amount, winner_prize, winner_id,
                created_at, started_at, completed_at, expires_at,
                result_post_deadline, opponent_upload_deadline,
                declared_score_creator, declared_score_joiner,
                declared_score_by, declared_winner_id,
                score_confirm_deadline, creator_team, joiner_team,
                creator_screenshot_url, joiner_screenshot_url,
                settlement_method, settlement_confidence,
                dispute_reason, disputer_id, challenge_deadline
            `)
            .or(`creator_id.eq.${user.id},joiner_id.eq.${user.id}`)
            .order('created_at', { ascending: false })
            .limit(50);

        if (error) { console.error('Fetch matches error:', error.message); return res.json([]); }

        const userIds = new Set();
        matches?.forEach(m => {
            if (m.creator_id) userIds.add(m.creator_id);
            if (m.joiner_id)  userIds.add(m.joiner_id);
        });
        let profileMap = {};
        const idArray = Array.from(userIds);
        if (idArray.length > 0) {
            const { data: profiles } = await supabaseAdmin
                .from('profiles').select('id, username').in('id', idArray);
            if (profiles) profileMap = Object.fromEntries(profiles.map(p => [p.id, p.username]));
        }
        const enriched = matches?.map(m => ({
            ...m,
            creator: m.creator_id ? { username: profileMap[m.creator_id] || null } : null,
            joiner:  m.joiner_id  ? { username: profileMap[m.joiner_id]  || null } : null,
        })) || [];
        res.json(enriched);
    } catch (err) {
        console.error('Fetch matches error:', err.message);
        res.json([]);
    }
});

// ============================================================
// MATCH STATUS
// ============================================================
router.get('/match-status/:matchId', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });
        const { matchId } = req.params;
        if (!requireValidMatchId(matchId, res)) return;

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select(`
                id, match_code, status, creator_id, joiner_id, wager_amount, winner_prize,
                winner_id, loser_id, expires_at, started_at, completed_at, challenge_deadline,
                penalty_deadline, draw_score, penalty_score, settlement_method, forfeit_by,
                efootball_room_code, declared_score_creator, declared_score_joiner,
                declared_score_by, declared_winner_id, score_confirm_deadline,
                result_post_deadline, creator_result, joiner_result
            `)
            .eq('id', matchId).single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'Not authorized to view this match' });

        let joinerUsername = null;
        if (match.joiner_id) {
            const { data: p } = await supabaseAdmin
                .from('profiles').select('username').eq('id', match.joiner_id).maybeSingle();
            joinerUsername = p?.username || null;
        }

        let statusMessage = null;
        if (match.status === 'no_show_forfeit') {
            statusMessage = 'Neither player submitted results within 30 minutes. Both wagers were forfeited.';
        } else if (match.status === 'penalty_shootout') {
            statusMessage = 'Match ended in a draw! Play a Penalty Shootout in eFootball and upload the result.';
        } else if (match.status === 'disputed') {
            statusMessage = 'Match is under admin review.';
        } else if (match.status === 'pending_review') {
            statusMessage = 'Screenshot uploaded. Admin will review and settle the match.';
        } else if (match.status === 'active' && match.result_post_deadline) {
            const minsLeft = Math.max(0, Math.ceil((new Date(match.result_post_deadline) - Date.now()) / 60000));
            statusMessage = minsLeft > 0
                ? `Submit your result within ${minsLeft} minute${minsLeft !== 1 ? 's' : ''}.`
                : 'Result submission deadline has passed.';
        }

        const isCreator = match.creator_id === user.id;
        res.json({
            matchId: match.id, matchCode: match.match_code, status: match.status, statusMessage,
            joinerUsername, wagerAmount: match.wager_amount, winnerPrize: match.winner_prize,
            winnerId: match.winner_id, loserId: match.loser_id, youWon: match.winner_id === user.id,
            myResult: isCreator ? match.creator_result : match.joiner_result,
            expiresAt: match.expires_at, startedAt: match.started_at,
            resultPostDeadline: match.result_post_deadline || null,
            challengeDeadline: match.challenge_deadline,
            penaltyDeadline: match.penalty_deadline || null,
            drawScore: match.draw_score || null, penaltyScore: match.penalty_score || null,
            settlementMethod: match.settlement_method || null,
            efootballRoomCode: match.efootball_room_code || null,
        });
    } catch (err) {
        console.error('Match status error:', err.message);
        res.status(500).json({ error: 'Failed to get match status' });
    }
});

// ============================================================
// SUBMIT SCREENSHOT – with duplicate upload guard
// ============================================================
router.post('/submit-screenshot', upload.single('screenshot'), async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!requireValidMatchId(matchId, res)) return;
        if (!req.file) return res.status(400).json({ error: 'No screenshot provided' });

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, status, creator_id, joiner_id, creator_screenshot_url, joiner_screenshot_url')
            .eq('id', matchId)
            .single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id)
            return res.status(403).json({ error: 'You are not part of this match' });
        if (match.status !== 'active')
            return res.status(400).json({ error: 'Match is not active' });

        // ── Duplicate screenshot guard ───────────────────────────
        const isCreator      = user.id === match.creator_id;
        const alreadyUploaded = isCreator
            ? !!match.creator_screenshot_url
            : !!match.joiner_screenshot_url;

        if (alreadyUploaded) {
            return res.status(400).json({
                error: 'You have already submitted a screenshot for this match. Please wait for admin review.'
            });
        }

        // Upload to storage
        const ext        = mimeToExt(req.file.mimetype);
        const storageKey = `match-screenshots/${matchId}/${user.id}-${Date.now()}.${ext}`;
        const { error: uploadErr } = await supabaseAdmin.storage
            .from('screenshots')
            .upload(storageKey, req.file.buffer, { contentType: req.file.mimetype });
        if (uploadErr) throw uploadErr;

        const { data: { publicUrl } } = supabaseAdmin.storage.from('screenshots').getPublicUrl(storageKey);

        // Update the correct player's screenshot field
        const updateField = isCreator ? 'creator_screenshot_url' : 'joiner_screenshot_url';
        const updateData = {
            [updateField]: publicUrl,
            status: 'pending_review',
            pending_review_reason: 'screenshot_uploaded'
        };

        const { error: updateErr } = await supabaseAdmin
            .from('friend_matches')
            .update(updateData)
            .eq('id', matchId);

        if (updateErr) throw updateErr;

        res.status(200).json({
            message: 'Screenshot uploaded. An admin will review and settle the match.',
        });

    } catch (err) {
        console.error('Screenshot upload error:', err.message);
        res.status(500).json({ error: 'Failed to upload screenshot' });
    }
});

// ============================================================
// CANCEL MATCH
// ============================================================
router.post('/cancel-match', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!requireValidMatchId(matchId, res)) return;

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('id, status, creator_id, wager_amount').eq('id', matchId).single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id) return res.status(403).json({ error: 'Only match creator can cancel' });
        if (match.status === 'cancelled') return res.status(400).json({ error: 'Match already cancelled' });
        if (match.status === 'active') return res.status(400).json({ error: 'Cannot cancel — someone already joined' });
        if (match.status === 'completed') return res.status(400).json({ error: 'Cannot cancel completed match' });
        if (match.status === 'disputed') return res.status(400).json({ error: 'Cannot cancel disputed match' });
        if (match.status !== 'pending' && match.status !== 'expired') return res.status(400).json({ error: `Cannot cancel ${match.status} match` });

        const { error: refundErr } = await supabaseAdmin.rpc('credit_wallet', { p_user_id: user.id, p_amount: match.wager_amount });
        if (refundErr) return res.status(500).json({ error: 'Failed to refund wager' });

        await supabaseAdmin.from('friend_matches').update({ status: 'cancelled', cancelled_at: new Date().toISOString() }).eq('id', matchId);
        res.status(200).json({ message: 'Match cancelled and wager refunded', refundedAmount: match.wager_amount });

    } catch (err) {
        console.error('Cancel match error:', err.message);
        res.status(500).json({ error: 'Failed to cancel match' });
    }
});

// ============================================================
// FORFEIT
// ============================================================
router.post('/forfeit', async (req, res) => {
    try {
        const supabaseAdmin = req.supabaseAdmin;
        const authHeader    = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
        const jwt = authHeader.replace('Bearer ', '');
        const { user, error: authErr } = await getAuthUser(req.supabase, jwt);
        if (authErr || !user) return res.status(401).json({ error: 'Invalid session' });

        const { matchId } = req.body;
        if (!requireValidMatchId(matchId, res)) return;

        const { data: match, error: matchErr } = await supabaseAdmin
            .from('friend_matches').select('id, status, creator_id, joiner_id, winner_prize').eq('id', matchId).single();

        if (matchErr || !match) return res.status(404).json({ error: 'Match not found' });
        if (match.creator_id !== user.id && match.joiner_id !== user.id) return res.status(403).json({ error: 'Not part of this match' });
        if (match.status !== 'active' && match.status !== 'penalty_shootout') return res.status(400).json({ error: 'Match is not active' });

        const winnerId      = match.creator_id === user.id ? match.joiner_id : match.creator_id;
        const creatorResult = winnerId === match.creator_id ? 'won' : 'lost';
        const joinerResult  = winnerId === match.joiner_id  ? 'won' : 'lost';

        const { error: rpcErr } = await supabaseAdmin.rpc('forfeit_match', {
            p_match_id: matchId,
            p_forfeit_by: user.id,
            p_winner_id: winnerId,
            p_winner_prize: match.winner_prize,
            p_creator_result: creatorResult,
            p_joiner_result: joinerResult
        });

        if (rpcErr) {
            console.error('Forfeit RPC error:', rpcErr.message);
            return res.status(400).json({ error: rpcErr.message || 'Failed to process forfeit' });
        }

        res.status(200).json({ message: 'Match forfeited. Opponent has been paid.', winnerId, prizePaid: match.winner_prize });

    } catch (err) {
        console.error('Forfeit error:', err.message);
        res.status(500).json({ error: 'Failed to process forfeit' });
    }
});

module.exports = router;