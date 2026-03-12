// ============================================================
// NOTIFICATION ROUTES
// routes/notifications.js
// ============================================================
const express = require('express');
const router = express.Router();
const { getAuthUser } = require('./helpers');

// ============================================================
// GET NOTIFICATIONS
// ============================================================
router.get('/', async (req, res) => {
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

        const { data: notifs, error: notifErr } = await supabaseAdmin
            .from('match_notifications')
            .select('id, match_id, type, payload, read, created_at')
            .eq('recipient_id', user.id)
            .order('created_at', { ascending: false })
            .limit(50);

        if (notifErr) throw notifErr;

        res.json((notifs || []).map(n => ({
            ...n,
            payload: (() => { 
                try { 
                    return JSON.parse(n.payload); 
                } catch { 
                    return {}; 
                } 
            })()
        })));

    } catch (err) {
        console.error('GET /notifications error:', err);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// ============================================================
// MARK NOTIFICATIONS AS READ
// ============================================================
router.patch('/read', async (req, res) => {
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

        const { ids } = req.body; // optional array of notification IDs
        
        let query = supabaseAdmin
            .from('match_notifications')
            .update({ read: true })
            .eq('recipient_id', user.id);

        if (Array.isArray(ids) && ids.length > 0) {
            query = query.in('id', ids);
        }

        const { error } = await query;
        
        if (error) throw error;

        res.json({ success: true });

    } catch (err) {
        console.error('PATCH /notifications/read error:', err);
        res.status(500).json({ error: 'Failed to update notifications' });
    }
});

module.exports = router;