// ============================================================
// BACKGROUND JOBS – Only expiry & cleanup, no auto-settlement
// ============================================================

'use strict';

const { sendMatchNotification } = require('../routes/helpers');

// ============================================================
// MARK EXPIRED MATCHES
// ============================================================
async function markExpiredMatches(supabaseAdmin) {
    try {
        const now = new Date().toISOString();

        const { data: expired, error } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, creator_id, joiner_id, wager_amount')
            .eq('status', 'active')
            .is('screenshot_url', null)
            .not('result_post_deadline', 'is', null)
            .lt('result_post_deadline', now);

        if (error) {
            console.error('Error fetching expired matches:', error.message);
            return;
        }

        for (const match of expired || []) {
            await supabaseAdmin
                .from('friend_matches')
                .update({
                    status: 'expired',
                    completed_at: now,
                    settlement_method: 'no_show_forfeit',
                })
                .eq('id', match.id);

            await sendMatchNotification(supabaseAdmin, match.id, match.creator_id, 'match_expired', {
                message: 'Match expired – no screenshot was uploaded within the deadline.',
            });
            await sendMatchNotification(supabaseAdmin, match.id, match.joiner_id, 'match_expired', {
                message: 'Match expired – no screenshot was uploaded within the deadline.',
            });

            console.log(`⏰ Match ${match.match_code} marked as expired (no screenshot).`);
        }

        const { data: oldPending } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code')
            .eq('status', 'pending_review')
            .lt('created_at', new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString());

        for (const match of oldPending || []) {
            await supabaseAdmin
                .from('friend_matches')
                .update({ status: 'expired', completed_at: now })
                .eq('id', match.id);
            console.log(`🧹 Old pending match ${match.match_code} auto-expired.`);
        }

    } catch (err) {
        console.error('markExpiredMatches error:', err.message);
    }
}

// ============================================================
// PURGE OLD SCREENSHOTS
// ============================================================
async function purgeExpiredScreenshots(supabaseAdmin) {
    try {
        const now = new Date().toISOString();

        const { data: expiredMatches, error: matchErr } = await supabaseAdmin
            .from('friend_matches')
            .select('id, match_code, status')
            .lt('screenshot_expires_at', now)
            .is('screenshots_deleted_at', null)
            .not('screenshot_expires_at', 'is', null);

        if (matchErr) {
            console.error('purgeExpiredScreenshots match query error:', matchErr.message);
        } else if (expiredMatches?.length > 0) {
            console.log(`🗑️  Purging screenshots for ${expiredMatches.length} expired match(es)...`);
            for (const match of expiredMatches) {
                await deleteMatchScreenshots(supabaseAdmin, match.id);
                console.log(`🗑️  Screenshots purged for match ${match.match_code}`);
            }
        }

        const { data: expiredQueue, error: qErr } = await supabaseAdmin
            .from('screenshot_review_queue')
            .select('id, match_id, storage_key')
            .lt('expires_at', now);

        if (qErr) {
            console.error('purgeExpiredScreenshots queue query error:', qErr.message);
        } else if (expiredQueue?.length > 0) {
            const keysToDelete = expiredQueue.map(r => r.storage_key).filter(Boolean);
            if (keysToDelete.length > 0) {
                await supabaseAdmin.storage.from('screenshots').remove(keysToDelete);
            }
            const ids = expiredQueue.map(r => r.id);
            await supabaseAdmin.from('screenshot_review_queue').delete().in('id', ids);
            console.log(`🗑️  Purged ${expiredQueue.length} review queue screenshot(s)`);
        }
    } catch (err) {
        console.error('purgeExpiredScreenshots error:', err.message);
    }
}

async function deleteMatchScreenshots(supabaseAdmin, matchId) {
    try {
        const { data: files, error: listErr } = await supabaseAdmin.storage
            .from('screenshots')
            .list(`match-screenshots/${matchId}`);

        if (listErr) {
            console.error(`deleteMatchScreenshots list error:`, listErr.message);
        } else if (files?.length > 0) {
            const paths = files.map(f => `match-screenshots/${matchId}/${f.name}`);
            await supabaseAdmin.storage.from('screenshots').remove(paths);
        }

        await supabaseAdmin.from('friend_matches').update({
            screenshot_url:              null,
            declared_screenshot_url:     null,
            confirmer_screenshot_url:    null,
            draw_screenshot_url:         null,
            penalty_screenshot_url:      null,
            first_upload_screenshot_url: null,
            challenge_screenshot_url:    null,
            disputer_screenshot_url:     null,
            screenshots_deleted_at:      new Date().toISOString(),
        }).eq('id', matchId);

        await supabaseAdmin.from('screenshot_review_queue').delete().eq('match_id', matchId);
    } catch (err) {
        console.error(`deleteMatchScreenshots error:`, err.message);
    }
}

module.exports = {
    markExpiredMatches,
    purgeExpiredScreenshots,
    deleteMatchScreenshots,
};