// ============================================================
// PROFILE ROUTES
// routes/profile.js
// ============================================================
const express = require('express');
const router = express.Router();
const { sendGenericError, getAuthUser } = require('./helpers');

// ============================================================
// GET PROFILE
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

        const { data: profile, error } = await supabaseAdmin
            .from('profiles')
            .select('username, team_name')
            .eq('id', user.id)
            .single();

        if (error) throw error;

        res.json(profile);

    } catch (err) {
        console.error('Profile fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// ============================================================
// UPDATE TEAM NAME
// ============================================================
router.post('/team', async (req, res) => {
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

        const { teamName } = req.body;
        
        if (!teamName || typeof teamName !== 'string' || teamName.length < 3) {
            return res.status(400).json({ 
                error: 'Valid team name required (min 3 characters)' 
            });
        }

        const { error } = await supabaseAdmin
            .from('profiles')
            .update({ team_name: teamName })
            .eq('id', user.id);

        if (error) throw error;

        res.json({ message: 'Team name updated', teamName });

    } catch (err) {
        console.error('Profile team update error:', err);
        res.status(500).json({ error: 'Failed to update team name' });
    }
});

module.exports = router;