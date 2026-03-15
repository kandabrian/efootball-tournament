'use strict';
console.log('[ADMIN] ✅ admin.js loaded and running');

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const API = isLocal ? 'http://localhost:3000' : '';

let adminKey = '';
let currentWithdrawalId = null;
let currentTournamentId = null;
let currentOverrideMatch = null;
let overrideApproveMode = false;
let currentDisputeMatch  = null;

let lbScale = 1, lbOffX = 0, lbOffY = 0, lbDragging = false, lbDragX = 0, lbDragY = 0;
let lbMode = 'single';
let lbCompareUrls = { left: null, right: null };

function escapeHtml(s) {
    if (!s) return '';
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function qs(id) { return document.getElementById(id); }

async function api(path, options = {}) {
    const isFormData = options.body instanceof FormData;
    const headers = {
        'x-admin-key': adminKey,
        ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
        ...options.headers,
    };
    const res = await fetch(`${API}/admin${path}`, { ...options, headers });
    return res;
}

function fmtDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString('en-KE', { dateStyle: 'short', timeStyle: 'short' });
}

function statusBadge(status) {
    const map = {
        pending:              'background:#2a1800;color:#ffb400;border:1px solid #7a5200',
        approved:             'background:#001a00;color:#00cc44;border:1px solid #006600',
        paid:                 'background:#001a00;color:#00ff66;border:1px solid #00aa44',
        completed:            'background:#001a00;color:#00ff66;border:1px solid #00aa44',
        rejected:             'background:#1a0000;color:#ff4444;border:1px solid #660000',
        active:               'background:#001a2a;color:#4aadff;border:1px solid #0066aa',
        disputed:             'background:#1a0a00;color:#ff8800;border:1px solid #884400',
        pending_review:       'background:#1a1a00;color:#ddcc00;border:1px solid #777700',
        cancelled:            'background:#111;color:#555;border:1px solid #333',
        expired:              'background:#111;color:#555;border:1px solid #333',
    };
    const style = map[status] || 'background:#111;color:#888;border:1px solid #333';
    return `<span style="display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.7rem;font-weight:700;letter-spacing:0.5px;${style}">${escapeHtml(status)}</span>`;
}

// ============================================================
// AUTH
// ============================================================
qs('btn-admin-login').addEventListener('click', async () => {
    const key = qs('admin-key').value.trim();
    if (!key) return;
    adminKey = key;
    try {
        const res = await api('/analytics');
        if (res.status === 403) {
            qs('login-error').style.display = 'block';
            adminKey = '';
            return;
        }
        qs('login-section').style.display = 'none';
        qs('dashboard').style.display = 'block';
        loadWithdrawals();
    } catch {
        qs('login-error').style.display = 'block';
        adminKey = '';
    }
});

qs('admin-key').addEventListener('keydown', e => { if (e.key === 'Enter') qs('btn-admin-login').click(); });

qs('btn-admin-logout').addEventListener('click', () => {
    adminKey = '';
    qs('login-section').style.display = 'block';
    qs('dashboard').style.display = 'none';
    qs('admin-key').value = '';
    qs('login-error').style.display = 'none';
});

// ============================================================
// TABS
// ============================================================
document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        qs(`${tab}-tab`).style.display = 'block';
        if (tab === 'withdrawals')    loadWithdrawals();
        if (tab === 'tournaments')    loadTournaments();
        if (tab === 'friend-matches') loadFriendMatches();
        if (tab === 'analytics')      loadAnalytics();
    });
});

// ============================================================
// MODAL HELPERS
// ============================================================
function openModal(id)  {
    const el = qs(id);
    if (el) { el.style.display = 'flex'; el.classList.add('open'); }
}
function closeModal(id) {
    const el = qs(id);
    if (el) { el.classList.remove('open'); el.style.display = 'none'; }
}

document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
});

document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
        if (e.target === overlay) closeModal(overlay.id);
    });
});

// ============================================================
// WITHDRAWALS
// ============================================================
async function loadWithdrawals() {
    const status = qs('wd-status-filter').value;
    try {
        const res  = await api(`/withdrawals?status=${status}`);
        const data = await res.json();
        renderWithdrawals(Array.isArray(data) ? data : []);
    } catch (err) {
        console.error('Withdrawals load error:', err);
    }
}

function renderWithdrawals(items) {
    const container = qs('withdrawal-cards');
    container.innerHTML = '';
    const totalAmt = items.reduce((s, w) => s + parseFloat(w.amount || 0), 0);
    qs('wd-summary').textContent = `${items.length} result${items.length !== 1 ? 's' : ''} · KES ${totalAmt.toLocaleString('en-KE', { minimumFractionDigits: 2 })}`;

    if (!items.length) {
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#444;">No withdrawals found.</div>';
        return;
    }

    items.forEach(w => {
        const phone    = w.phone || w.phone_number || '—';
        const name     = w.name || w.full_name || w.username || '—';
        const refId    = w.reference_id || w.id?.substring(0, 8) || '—';
        const mpesaCode = w.mpesa_code || w.mpesa_transaction_code || null;
        const isPending = w.status === 'pending' || w.status === 'approved';

        const card = document.createElement('div');
        card.style.cssText = `
            background:#0d0d10;
            border:1px solid ${isPending ? 'rgba(255,180,0,0.25)' : '#1e1e26'};
            border-radius:14px;padding:18px 20px;
            position:relative;overflow:hidden;
        `;

        // Top row: amount + status badge
        const topRow = document.createElement('div');
        topRow.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;';
        const amtEl = document.createElement('div');
        amtEl.style.cssText = 'font-weight:800;font-size:1.3rem;color:#fff;';
        amtEl.textContent = `KES ${parseFloat(w.amount).toLocaleString('en-KE', { minimumFractionDigits: 2 })}`;
        const badgeWrap = document.createElement('div');
        badgeWrap.innerHTML = statusBadge(w.status);
        topRow.appendChild(amtEl);
        topRow.appendChild(badgeWrap);
        card.appendChild(topRow);

        // SEND TO box
        const sendBox = document.createElement('div');
        sendBox.style.cssText = `
            background:rgba(0,255,65,0.06);border:1px solid rgba(0,255,65,0.2);
            border-radius:10px;padding:12px 14px;margin-bottom:14px;
        `;
        const sendLabel = document.createElement('div');
        sendLabel.style.cssText = 'font-size:0.62rem;letter-spacing:2px;text-transform:uppercase;color:#00cc44;margin-bottom:6px;font-weight:700;';
        sendLabel.textContent = '📲 SEND MONEY TO';
        sendBox.appendChild(sendLabel);

        const phoneRow = document.createElement('div');
        phoneRow.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;';
        const phoneVal = document.createElement('div');
        phoneVal.style.cssText = 'font-size:1.15rem;font-weight:800;color:#fff;letter-spacing:1px;font-family:monospace;';
        phoneVal.textContent = phone;
        phoneRow.appendChild(phoneVal);

        const copyBtn = document.createElement('button');
        copyBtn.textContent = 'Copy';
        copyBtn.style.cssText = `background:rgba(0,255,65,0.1);border:1px solid rgba(0,255,65,0.3);color:#00cc44;border-radius:6px;padding:4px 10px;font-size:0.72rem;font-weight:700;cursor:pointer;white-space:nowrap;`;
        copyBtn.addEventListener('click', () => {
            if (phone === '—') return;
            navigator.clipboard.writeText(phone).then(() => {
                copyBtn.textContent = '✓ Copied';
                setTimeout(() => copyBtn.textContent = 'Copy', 2000);
            });
        });
        phoneRow.appendChild(copyBtn);
        sendBox.appendChild(phoneRow);

        const nameRow = document.createElement('div');
        nameRow.style.cssText = 'font-size:0.8rem;color:#888;margin-top:4px;';
        nameRow.textContent = `👤 ${name}`;
        sendBox.appendChild(nameRow);
        card.appendChild(sendBox);

        // Meta row
        const metaRow = document.createElement('div');
        metaRow.style.cssText = 'display:flex;justify-content:space-between;font-size:0.72rem;color:#555;margin-bottom:12px;';
        const refEl = document.createElement('span');
        refEl.textContent = `Ref: ${refId}`;
        const dateEl = document.createElement('span');
        dateEl.textContent = fmtDate(w.requested_at || w.created_at);
        metaRow.appendChild(refEl);
        metaRow.appendChild(dateEl);
        card.appendChild(metaRow);

        if (mpesaCode) {
            const mpesaEl = document.createElement('div');
            mpesaEl.style.cssText = 'font-size:0.8rem;color:#00cc44;margin-bottom:10px;font-weight:700;';
            mpesaEl.textContent = `✅ M-PESA: ${mpesaCode}`;
            card.appendChild(mpesaEl);
        }

        if (w.review_notes) {
            const notesEl = document.createElement('div');
            notesEl.style.cssText = 'font-size:0.75rem;color:#888;margin-bottom:10px;font-style:italic;';
            notesEl.textContent = w.review_notes;
            card.appendChild(notesEl);
        }

        // Action buttons
        const actions = document.createElement('div');
        actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';

        if (w.status === 'pending' || w.status === 'approved') {
            const approveBtn = document.createElement('button');
            approveBtn.className = 'btn btn-green';
            approveBtn.textContent = '✓ Approve';
            approveBtn.addEventListener('click', () => approveWithdrawal(w.id));
            actions.appendChild(approveBtn);

            const rejectBtn = document.createElement('button');
            rejectBtn.className = 'btn btn-red';
            rejectBtn.textContent = '✕ Reject';
            rejectBtn.addEventListener('click', () => openRejectModal(w.id));
            actions.appendChild(rejectBtn);
        }

        if (w.status === 'approved' || w.status === 'paid' || w.status === 'completed') {
            const paidBtn = document.createElement('button');
            paidBtn.className = 'btn btn-orange';
            paidBtn.textContent = '💸 Mark Paid';
            paidBtn.addEventListener('click', () => openPaidModal(w.id));
            actions.appendChild(paidBtn);
        }

        card.appendChild(actions);
        container.appendChild(card);
    });
}

qs('btn-refresh-withdrawals').addEventListener('click', loadWithdrawals);
qs('wd-status-filter').addEventListener('change', loadWithdrawals);

async function approveWithdrawal(id) {
    if (!confirm('Approve this withdrawal?')) return;
    try {
        const res = await api(`/withdrawals/${id}/approve`, { method: 'POST', body: JSON.stringify({ notes: 'Approved by admin' }) });
        const data = await res.json();
        if (!res.ok) return alert(data.error || 'Failed');
        alert('✅ Withdrawal approved.');
        loadWithdrawals();
    } catch (err) { alert('Network error: ' + err.message); }
}

function openPaidModal(id) {
    currentWithdrawalId = id;
    qs('mpesa-code').value = '';
    openModal('paid-modal');
}

// FIX: calls /paid endpoint (not /approve) to correctly set status → 'paid'
qs('btn-submit-paid').addEventListener('click', async () => {
    const code = qs('mpesa-code').value.trim();
    if (!code) return alert('Enter M-PESA transaction code');
    try {
        const res = await api(`/withdrawals/${currentWithdrawalId}/paid`, {
            method: 'POST',
            body: JSON.stringify({ mpesaCode: code })
        });
        const data = await res.json();
        if (!res.ok) return alert(data.error || 'Failed');
        closeModal('paid-modal');
        alert('✅ Marked as paid.');
        loadWithdrawals();
    } catch (err) { alert('Network error: ' + err.message); }
});

function openRejectModal(id) {
    currentWithdrawalId = id;
    qs('reject-reason').value = '';
    openModal('reject-modal');
}

qs('btn-submit-reject').addEventListener('click', async () => {
    const notes = qs('reject-reason').value.trim();
    try {
        const res = await api(`/withdrawals/${currentWithdrawalId}/reject`, {
            method: 'POST',
            body: JSON.stringify({ notes })
        });
        const data = await res.json();
        if (!res.ok) return alert(data.error || 'Failed');
        closeModal('reject-modal');
        alert('✅ Withdrawal rejected. Funds refunded.');
        loadWithdrawals();
    } catch (err) { alert('Network error: ' + err.message); }
});

// ============================================================
// TOURNAMENTS
// ============================================================
async function loadTournaments() {
    try {
        const res  = await api('/tournaments');
        const data = await res.json();
        renderTournaments(Array.isArray(data) ? data : []);
    } catch (err) { console.error('Tournaments load error:', err); }
}

function renderTournaments(items) {
    const tbody = qs('tournaments-table').querySelector('tbody');
    tbody.innerHTML = '';
    items.forEach(t => {
        const tr = document.createElement('tr');
        const codeTd = document.createElement('td'); codeTd.textContent = t.name;
        const feeTd = document.createElement('td'); feeTd.textContent = `KES ${t.entry_fee}`;
        const startTd = document.createElement('td'); startTd.textContent = fmtDate(t.start_time);
        const playersTd = document.createElement('td'); playersTd.textContent = `${t.current_players || 0}/${t.max_players}`;
        const roomTd = document.createElement('td'); roomTd.textContent = t.room_code || '—';
        const statusTd = document.createElement('td'); statusTd.innerHTML = statusBadge(t.status);
        const actTd = document.createElement('td');

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-blue'; editBtn.textContent = 'Edit'; editBtn.style.marginRight = '6px';
        editBtn.addEventListener('click', () => openTournamentModal(t));
        actTd.appendChild(editBtn);

        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-red'; delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => openDeleteModal(t.id));
        actTd.appendChild(delBtn);

        [codeTd, feeTd, startTd, playersTd, roomTd, statusTd, actTd].forEach(td => tr.appendChild(td));
        tbody.appendChild(tr);
    });
}

function openTournamentModal(t = null) {
    currentTournamentId = t?.id || null;
    qs('tournament-modal-title').textContent = t ? 'Edit Tournament' : 'Create Tournament';
    qs('tournament-name').value   = t?.name        || '';
    qs('tournament-fee').value    = t?.entry_fee   || '';
    qs('tournament-start').value  = t?.start_time ? t.start_time.substring(0,16) : '';
    qs('tournament-max').value    = t?.max_players || '';
    qs('tournament-room').value   = t?.room_code   || '';
    qs('tournament-status').value = t?.status      || 'open';
    openModal('tournament-modal');
}

qs('btn-open-tournament-modal').addEventListener('click', () => openTournamentModal());

qs('tournament-save').addEventListener('click', async () => {
    const body = {
        name: qs('tournament-name').value.trim(),
        entry_fee: parseInt(qs('tournament-fee').value),
        start_time: qs('tournament-start').value,
        max_players: parseInt(qs('tournament-max').value),
        room_code: qs('tournament-room').value.trim(),
        status: qs('tournament-status').value,
    };
    if (!body.name || !body.entry_fee || !body.start_time || !body.max_players) return alert('Fill in all required fields.');
    try {
        const path   = currentTournamentId ? `/tournaments/${currentTournamentId}` : '/tournaments';
        const method = currentTournamentId ? 'PATCH' : 'POST';
        const res    = await api(path, { method, body: JSON.stringify(body) });
        const data   = await res.json();
        if (!res.ok) return alert(data.error || 'Failed');
        closeModal('tournament-modal');
        loadTournaments();
    } catch (err) { alert('Network error: ' + err.message); }
});

function openDeleteModal(id) { currentTournamentId = id; openModal('delete-modal'); }

qs('btn-confirm-delete').addEventListener('click', async () => {
    try {
        const res  = await api(`/tournaments/${currentTournamentId}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) return alert(data.error || 'Failed');
        closeModal('delete-modal');
        loadTournaments();
    } catch (err) { alert('Network error: ' + err.message); }
});

// ============================================================
// FRIEND MATCHES
// ============================================================
async function loadFriendMatches() {
    const status = qs('fm-status-filter').value;
    qs('fm-loading').style.display = 'block';
    try {
        const res  = await api(`/friend-matches?status=${status}`);
        const data = await res.json();
        renderFriendMatches(Array.isArray(data) ? data : []);
    } catch (err) { console.error('Friend matches load error:', err); }
    finally { qs('fm-loading').style.display = 'none'; }
}

function renderFriendMatches(items) {
    const tbody = qs('friend-matches-table').querySelector('tbody');
    tbody.innerHTML = '';
    items.forEach(m => {
        const code  = m.match_code || m.efootball_code || '—';
        const score = (m.declared_score_creator != null && m.declared_score_joiner != null)
            ? `${m.declared_score_creator}–${m.declared_score_joiner}` : '—';

        const tr = document.createElement('tr');
        const codeTd = document.createElement('td'); codeTd.style.cssText = 'font-family:monospace;color:#00ff41;'; codeTd.textContent = code;
        const creatorTd = document.createElement('td'); creatorTd.textContent = m.creator_username || (m.creator_id?.substring(0,8) || '—');
        const joinerTd = document.createElement('td'); joinerTd.textContent = m.joiner_username || (m.joiner_id?.substring(0,8) || '—');
        const scoreTd = document.createElement('td'); scoreTd.textContent = score;
        const wagerTd = document.createElement('td'); wagerTd.textContent = `KES ${m.wager_amount}`;
        const prizeTd = document.createElement('td'); prizeTd.textContent = `KES ${m.winner_prize}`;
        const statusTd = document.createElement('td'); statusTd.innerHTML = statusBadge(m.status);
        const dateTd = document.createElement('td'); dateTd.style.cssText = 'font-size:0.72rem;color:#555;'; dateTd.textContent = fmtDate(m.created_at);
        const actTd = document.createElement('td'); actTd.style.cssText = 'white-space:nowrap;';

        const hasScreenshot = m.creator_screenshot_url || m.joiner_screenshot_url;
        if (hasScreenshot) {
            const ssBtn = document.createElement('button');
            ssBtn.className = 'btn btn-blue'; ssBtn.textContent = '📸 View'; ssBtn.style.marginRight = '4px';
            ssBtn.addEventListener('click', () => openScreenshotViewer(m));
            actTd.appendChild(ssBtn);
        }

        if (['active','pending_review','disputed','awaiting_confirmation','penalty_shootout'].includes(m.status)) {
            const ovrBtn = document.createElement('button');
            ovrBtn.className = 'btn btn-orange'; ovrBtn.textContent = '⚡ Override'; ovrBtn.style.marginRight = '4px';
            ovrBtn.addEventListener('click', () => openOverrideModal(m));
            actTd.appendChild(ovrBtn);
        }

        if (m.status === 'disputed') {
            const dspBtn = document.createElement('button');
            dspBtn.className = 'btn btn-red'; dspBtn.textContent = '⚖️ Resolve';
            dspBtn.addEventListener('click', () => openDisputeModal(m.id));
            actTd.appendChild(dspBtn);
        }

        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-red'; delBtn.textContent = '🗑️ Delete'; delBtn.style.marginLeft = '4px';
        delBtn.addEventListener('click', async () => {
            if (!confirm(`Delete match ${m.match_code || m.id}?`)) return;
            try {
                const res = await api(`/friend-matches/${m.id}`, { method: 'DELETE' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Delete failed');
                loadFriendMatches();
            } catch (err) { alert('Error: ' + err.message); }
        });
        actTd.appendChild(delBtn);

        if (m.status === 'pending_review') {
            const approveBtn = document.createElement('button');
            approveBtn.className = 'btn btn-green'; approveBtn.textContent = '✅ Approve';
            approveBtn.addEventListener('click', () => approveResult(m.id));
            actTd.appendChild(approveBtn);
        }

        [codeTd, creatorTd, joinerTd, scoreTd, wagerTd, prizeTd, statusTd, dateTd, actTd].forEach(td => tr.appendChild(td));
        tbody.appendChild(tr);
    });
}

qs('btn-refresh-friend-matches').addEventListener('click', loadFriendMatches);
qs('fm-status-filter').addEventListener('change', loadFriendMatches);

function openScreenshotViewer(match) {
    lbCompareUrls = { left: match.creator_screenshot_url || null, right: match.joiner_screenshot_url || null };
    if (lbCompareUrls.left && lbCompareUrls.right) {
        openCompare(lbCompareUrls.left, lbCompareUrls.right, 'Creator', 'Joiner');
    } else {
        const url = lbCompareUrls.left || lbCompareUrls.right;
        openLightbox(url, lbCompareUrls.left ? 'Creator Screenshot' : 'Joiner Screenshot');
    }
}

async function approveResult(matchId) {
    try {
        const res = await api(`/friend-matches/${matchId}`);
        const m   = await res.json();
        if (!res.ok) return alert(m.error || 'Failed to load match');
        openOverrideModal(m, true);
    } catch (err) { alert('Network error: ' + err.message); }
}

// ============================================================
// OVERRIDE (FORCE WINNER) MODAL
// ============================================================
function openOverrideModal(match, approveMode = false) {
    currentOverrideMatch = match;
    overrideApproveMode  = approveMode;

    qs('ovr-code').textContent   = match.match_code || '—';
    qs('ovr-status').textContent = match.status;
    qs('ovr-prize').textContent  = match.winner_prize || '—';
    const score = (match.declared_score_creator != null && match.declared_score_joiner != null)
        ? `${match.declared_score_creator}–${match.declared_score_joiner}` : '—';
    qs('ovr-score').textContent = score;
    qs('ovr-cname').textContent = match.creator_username || '—';
    qs('ovr-cteam').textContent = match.creator_team     || '—';
    qs('ovr-jname').textContent = match.joiner_username  || '—';
    qs('ovr-jteam').textContent = match.joiner_team      || '—';

    const creatorUrl = match.creator_screenshot_url || null;
    const joinerUrl  = match.joiner_screenshot_url  || null;
    setOvrScreenshot('ovr-ss-c-wrap', 'ovr-ss-c-link', 'ovr-ss-c-tag', creatorUrl, 'Creator');
    setOvrScreenshot('ovr-ss-j-wrap', 'ovr-ss-j-link', 'ovr-ss-j-tag', joinerUrl,  'Joiner');
    lbCompareUrls = { left: creatorUrl, right: joinerUrl };

    ovrSelectedWinnerId   = null;
    ovrSelectedResolution = null;
    qs('ovr-btn-creator').classList.remove('selected');
    qs('ovr-btn-joiner').classList.remove('selected');
    qs('ovr-btn-draw').classList.remove('selected');
    qs('ovr-notes').value = '';

    const titleEl = qs('override-modal').querySelector('h3');
    if (titleEl) titleEl.textContent = approveMode ? '📸 APPROVE RESULT' : '⚡ FORCE WINNER';
    const notesEl = qs('ovr-notes');
    if (notesEl) notesEl.placeholder = approveMode
        ? 'e.g. Creator screenshot clearly shows 3–1 final score.'
        : 'e.g. Player A screenshot clearly shows final score 3–1.';

    ovrUpdateBtn();
    openModal('override-modal');
}

function setOvrScreenshot(wrapId, linkId, tagId, url, label) {
    const wrap = qs(wrapId); const link = qs(linkId); const tag  = qs(tagId);
    while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
    if (url) {
        const img = document.createElement('img');
        img.src = url; img.alt = label + ' screenshot'; img.className = 'ovr-ss-img';
        img.addEventListener('click', () => openLightbox(url, label + ' Screenshot'));
        wrap.appendChild(img);
        link.href = url; link.style.display = 'inline';
        if (tag) tag.textContent = '';
    } else {
        const none = document.createElement('div'); none.className = 'ovr-ss-none'; none.textContent = 'No screenshot uploaded';
        wrap.appendChild(none); link.style.display = 'none';
        if (tag) tag.textContent = '';
    }
}

let ovrSelectedWinnerId   = null;
let ovrSelectedResolution = null;

function ovrUpdateBtn() {
    const notes = (qs('ovr-notes')?.value || '').trim();
    const hasSelection = ovrSelectedResolution !== null;
    const btn = qs('ovr-submit-btn');
    if (!btn) return;
    if (hasSelection && notes) {
        btn.disabled = false;
        if (ovrSelectedResolution === 'draw') {
            btn.textContent = '↩ Refund Both Players';
        } else {
            const winnerName = ovrSelectedWinnerId === currentOverrideMatch?.creator_id
                ? (currentOverrideMatch?.creator_username || 'Creator')
                : (currentOverrideMatch?.joiner_username  || 'Joiner');
            btn.textContent = `✅ Declare Winner: ${winnerName}`;
        }
    } else {
        btn.disabled = true;
        btn.textContent = !hasSelection && !notes ? 'Select a winner and add notes'
            : !hasSelection ? 'Select a winner above' : 'Add admin notes below';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    qs('ovr-btn-creator').addEventListener('click', () => {
        ovrSelectedWinnerId   = currentOverrideMatch?.creator_id;
        ovrSelectedResolution = 'winner';
        qs('ovr-btn-creator').classList.add('selected');
        qs('ovr-btn-joiner').classList.remove('selected');
        qs('ovr-btn-draw').classList.remove('selected');
        ovrUpdateBtn();
    });
    qs('ovr-btn-joiner').addEventListener('click', () => {
        ovrSelectedWinnerId   = currentOverrideMatch?.joiner_id;
        ovrSelectedResolution = 'winner';
        qs('ovr-btn-joiner').classList.add('selected');
        qs('ovr-btn-creator').classList.remove('selected');
        qs('ovr-btn-draw').classList.remove('selected');
        ovrUpdateBtn();
    });
    qs('ovr-btn-draw').addEventListener('click', () => {
        ovrSelectedWinnerId   = null;
        ovrSelectedResolution = 'draw';
        qs('ovr-btn-draw').classList.add('selected');
        qs('ovr-btn-creator').classList.remove('selected');
        qs('ovr-btn-joiner').classList.remove('selected');
        ovrUpdateBtn();
    });
    qs('ovr-notes').addEventListener('input', ovrUpdateBtn);

    qs('ovr-submit-btn').addEventListener('click', async () => {
        if (!currentOverrideMatch) { alert('No match selected.'); return; }
        const notes = (qs('ovr-notes')?.value || '').trim();
        if (!notes) { alert('Admin notes are required.'); return; }
        if (!ovrSelectedResolution) { alert('Please select a winner or draw.'); return; }

        const btn = qs('ovr-submit-btn');
        const originalText = btn.textContent;
        btn.disabled = true; btn.textContent = 'Processing...';

        try {
            const res  = await api(`/force-winner/${currentOverrideMatch.id}`, {
                method: 'POST',
                body: JSON.stringify({ winnerId: ovrSelectedWinnerId, resolution: ovrSelectedResolution, adminNotes: notes }),
            });
            const data = await res.json();
            if (!res.ok) { alert('❌ ' + (data.error || 'Failed')); btn.disabled = false; btn.textContent = originalText; return; }
            closeModal('override-modal');
            alert(`✅ Match settled.${data.prizePaid ? ` KES ${data.prizePaid} paid.` : ''}`);
            loadFriendMatches();
        } catch (err) {
            alert('Network error: ' + err.message);
            btn.disabled = false; btn.textContent = originalText;
        }
    });
});

qs('btn-lb-from-override').addEventListener('click', () => {
    openCompare(lbCompareUrls.left, lbCompareUrls.right, 'Creator', 'Joiner');
});

// ============================================================
// DISPUTE MODAL
// ============================================================
async function openDisputeModal(matchId) {
    qs('dsp-loading').style.display = 'block';
    qs('dsp-body').style.display    = 'none';
    openModal('dispute-modal');
    try {
        const res = await api(`/friend-matches/${matchId}`);
        const m   = await res.json();
        if (!res.ok) { alert(m.error || 'Failed to load'); closeModal('dispute-modal'); return; }
        currentDisputeMatch = m;
        populateDisputeModal(m);
    } catch (err) { alert('Network error: ' + err.message); closeModal('dispute-modal'); }
}

function populateDisputeModal(m) {
    qs('dsp-code').textContent   = m.match_code || '—';
    qs('dsp-wager').textContent  = m.wager_amount;
    qs('dsp-prize').textContent  = m.winner_prize;
    qs('dsp-method').textContent = m.settlement_method || 'manual';
    qs('dsp-time').textContent   = fmtDate(m.disputed_at || m.updated_at);
    qs('dsp-reason-text').textContent = m.dispute_reason || '—';
    qs('dsp-cname').textContent = m.creator_username || '—'; qs('dsp-cteam').textContent = m.creator_team || '—';
    qs('dsp-jname').textContent = m.joiner_username  || '—'; qs('dsp-jteam').textContent = m.joiner_team  || '—';
    qs('sc-cname').textContent  = m.creator_username || '—'; qs('sc-cteam').textContent  = m.creator_team || '—';
    qs('sc-jname').textContent  = m.joiner_username  || '—'; qs('sc-jteam').textContent  = m.joiner_team  || '—';

    const cscore = m.declared_score_creator; const jscore = m.declared_score_joiner;
    qs('sc-cscore').textContent = cscore != null ? cscore : '?';
    qs('sc-jscore').textContent = jscore != null ? jscore : '?';
    qs('dsp-cscore').textContent = cscore != null ? cscore : '?';
    qs('dsp-jscore').textContent = jscore != null ? jscore : '?';

    const agree = cscore != null && jscore != null && cscore === jscore;
    qs('sc-verdict').textContent = agree ? '✅ Scores agree' : '❌ Scores conflict';
    qs('sc-verdict').style.color = agree ? '#00ff66' : '#ff4444';
    qs('dsp-btn-c-label').textContent = m.creator_username || 'Creator';
    qs('dsp-btn-j-label').textContent = m.joiner_username  || 'Joiner';

    setDspImg('dsp-cimg', 'dsp-cimg-link', m.creator_screenshot_url || null, 'Creator');
    setDspImg('dsp-jimg', 'dsp-jimg-link', m.joiner_screenshot_url  || null, 'Joiner');

    const timelineRows = qs('dsp-timeline-rows');
    while (timelineRows.firstChild) timelineRows.removeChild(timelineRows.firstChild);
    [{ time: m.created_at, label: 'Match created' }, { time: m.started_at, label: 'Match started' },
     { time: m.declared_at, label: 'Score declared' }, { time: m.disputed_at, label: '⚠️ Disputed' }]
        .filter(e => e.time).forEach(ev => {
            const row = document.createElement('div');
            row.style.cssText = 'display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #1a1a20;font-size:0.78rem;color:#888;';
            const lEl = document.createElement('span'); lEl.textContent = ev.label;
            const tEl = document.createElement('span'); tEl.style.color = '#555'; tEl.textContent = fmtDate(ev.time);
            row.appendChild(lEl); row.appendChild(tEl); timelineRows.appendChild(row);
        });

    qs('dsp-loading').style.display = 'none';
    qs('dsp-body').style.display    = 'block';
}

function setDspImg(wrapId, linkId, url, label) {
    const wrap = qs(wrapId); const link = qs(linkId);
    while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
    if (url) {
        const img = document.createElement('img'); img.src = url; img.alt = label + ' screenshot'; img.className = 'dp-img';
        img.addEventListener('click', () => openLightbox(url, label + ' Screenshot'));
        wrap.appendChild(img); link.href = url; link.style.display = 'inline';
    } else {
        const none = document.createElement('div'); none.className = 'dp-noimg'; none.textContent = 'No screenshot provided';
        wrap.appendChild(none); link.style.display = 'none';
    }
}

async function resolveDispute(winnerId, resolution) {
    if (!currentDisputeMatch) return;
    const notes = qs('dsp-admin-notes').value.trim();
    if (!notes) { alert('Please add admin notes before resolving.'); return; }
    const label = resolution === 'draw' ? 'refund both players'
        : `declare ${winnerId === currentDisputeMatch.creator_id
            ? (currentDisputeMatch.creator_username || 'Creator')
            : (currentDisputeMatch.joiner_username  || 'Joiner')} as winner`;
    if (!confirm(`Confirm: ${label}?`)) return;
    try {
        const res  = await api(`/resolve-dispute/${currentDisputeMatch.id}`, {
            method: 'POST', body: JSON.stringify({ winnerId, resolution, adminNotes: notes })
        });
        const data = await res.json();
        if (!res.ok) { alert(data.error || 'Failed to resolve dispute'); return; }
        closeModal('dispute-modal');
        alert('✅ Dispute resolved.');
        loadFriendMatches();
    } catch (err) { alert('Network error: ' + err.message); }
}

qs('dsp-btn-c').addEventListener('click', () => resolveDispute(currentDisputeMatch?.creator_id, 'winner'));
qs('dsp-btn-j').addEventListener('click', () => resolveDispute(currentDisputeMatch?.joiner_id,  'winner'));
qs('btn-resolve-draw').addEventListener('click', () => resolveDispute(null, 'draw'));

// ============================================================
// ANALYTICS
// ============================================================
async function loadAnalytics() {
    const container = qs('analytics-content');
    container.innerHTML = '<div style="text-align:center;padding:60px 20px;color:#555;"><div style="font-size:2rem;margin-bottom:12px;">📊</div><div>Loading analytics...</div></div>';
    try {
        const res  = await api('/analytics');
        const data = await res.json();
        if (!res.ok) { container.innerHTML = `<div style="color:#ff4444;padding:20px;">${escapeHtml(data.error || 'Failed')}</div>`; return; }
        renderAnalytics(data);
    } catch (err) { container.innerHTML = `<div style="color:#ff4444;padding:20px;">Network error: ${escapeHtml(err.message)}</div>`; }
}

function statCard(label, value, sub) {
    const card = document.createElement('div');
    card.style.cssText = 'background:#0d0d10;border:1px solid #1e1e26;border-radius:14px;padding:20px 22px;';
    const labelEl = document.createElement('div'); labelEl.style.cssText = 'font-size:0.65rem;letter-spacing:2px;text-transform:uppercase;color:#555;margin-bottom:6px;'; labelEl.textContent = label;
    const valEl = document.createElement('div'); valEl.style.cssText = 'font-size:1.8rem;font-weight:800;color:#f0f0f0;line-height:1;'; valEl.textContent = value;
    card.appendChild(labelEl); card.appendChild(valEl);
    if (sub) { const subEl = document.createElement('div'); subEl.style.cssText = 'font-size:0.72rem;color:#555;margin-top:5px;'; subEl.textContent = sub; card.appendChild(subEl); }
    return card;
}

function renderAnalytics(d) {
    const r = d.revenue || {}, m = d.matches || {}, u = d.users || {}, w = d.withdrawals || {}, p = d.platform || {};
    const growthStr = r.feesGrowthPct != null ? ` (${r.feesGrowthPct > 0 ? '+' : ''}${r.feesGrowthPct}% vs last month)` : '';
    const container = qs('analytics-content'); container.innerHTML = '';

    const sections = [
        { title: '💰 Revenue', cards: [
            ['ALL-TIME FEES', `KES ${(r.allTimeFees||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
            ['MTD FEES', `KES ${(r.mtdFees||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`, `vs KES ${(r.lastMonthFees||0).toLocaleString('en-KE')} last month${growthStr}`],
            ['ALL-TIME VOLUME', `KES ${(r.allTimeVolume||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
            ['MTD VOLUME', `KES ${(r.mtdVolume||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
        ]},
        { title: '⚽ Matches', cards: [
            ['TOTAL COMPLETED', m.totalCompleted||0], ['MTD COMPLETED', m.mtdCompleted||0],
            ['AVG WAGER', `KES ${(m.avgWager||0).toFixed(2)}`],
            ['DISPUTE RATE', `${m.disputeRate||0}%`, `${m.disputedCount||0} disputed of ${m.totalMatches||0} total`],
        ]},
        { title: '👥 Users', cards: [
            ['TOTAL USERS', u.total||0], ['NEW TODAY', u.newToday||0], ['NEW MTD', u.newMtd||0], ['ACTIVE 7 DAYS', u.active7Days||0],
        ]},
        { title: '💸 Withdrawals', cards: [
            ['ALL-TIME PAID', `KES ${(w.allTimeVolume||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
            ['MTD PAID', `KES ${(w.mtdVolume||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
            ['PENDING', `${w.pendingCount||0}`, `KES ${(w.pendingVolume||0).toLocaleString('en-KE',{minimumFractionDigits:2})} pending`],
            ['AVG PROCESSING', w.avgProcessingHrs != null ? `${w.avgProcessingHrs}h` : '—'],
        ]},
        { title: '🏟️ Platform', cards: [
            ['TOTAL FLOAT', `KES ${(p.totalFloat||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
            ['ACTIVE TOURNAMENTS', p.activeTournaments||0],
            ['LIVE POOL VALUE', `KES ${(p.livePoolValue||0).toLocaleString('en-KE',{minimumFractionDigits:2})}`],
        ]},
    ];

    sections.forEach(sec => {
        const titleEl = document.createElement('div'); titleEl.style.cssText = 'font-size:1.1rem;font-weight:700;margin:24px 0 12px;color:#888;'; titleEl.textContent = sec.title; container.appendChild(titleEl);
        const grid = document.createElement('div'); grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;';
        sec.cards.forEach(([label, value, sub]) => grid.appendChild(statCard(label, String(value), sub)));
        container.appendChild(grid);
    });

    if (d.dailyChart?.length) {
        const chartTitle = document.createElement('div'); chartTitle.style.cssText = 'font-size:1.1rem;font-weight:700;margin:24px 0 12px;color:#888;'; chartTitle.textContent = '📈 Last 30 Days — Daily Volume'; container.appendChild(chartTitle);
        const maxVol = Math.max(...d.dailyChart.map(r => r.volume), 1);
        const chartEl = document.createElement('div'); chartEl.style.cssText = 'display:flex;align-items:flex-end;gap:3px;height:80px;background:#0d0d10;border:1px solid #1e1e26;border-radius:14px;padding:10px 12px;overflow:hidden;';
        d.dailyChart.forEach(row => {
            const bar = document.createElement('div'); const pct = Math.round((row.volume / maxVol) * 100);
            bar.style.cssText = `flex:1;background:rgba(0,255,65,0.3);border-radius:2px 2px 0 0;height:${Math.max(pct, row.volume > 0 ? 4 : 0)}%;`;
            bar.title = `${row.date}: KES ${row.volume.toLocaleString('en-KE')} (${row.matches} matches)`;
            chartEl.appendChild(bar);
        });
        container.appendChild(chartEl);
    }
}

// ============================================================
// LIGHTBOX
// ============================================================
function openLightbox(url, title) {
    lbScale = 1; lbOffX = 0; lbOffY = 0; lbMode = 'single';
    qs('lightbox-img').src = url;
    qs('lb-single').style.display  = 'flex';
    qs('lb-compare').style.display = 'none';
    qs('lb-btn-single').classList.add('active');
    qs('lb-btn-compare').classList.remove('active');
    applyLbTransform();
    qs('lb-title').textContent = title || 'Screenshot Evidence';
    qs('lightbox').classList.add('open');
}

function openCompare(leftUrl, rightUrl, leftLabel, rightLabel) {
    lbScale = 1; lbOffX = 0; lbOffY = 0; lbMode = 'compare';
    qs('lb-single').style.display  = 'none';
    qs('lb-compare').style.display = 'flex';
    qs('lb-compare').classList.add('active');
    qs('lb-btn-single').classList.remove('active');
    qs('lb-btn-compare').classList.add('active');
    qs('lb-cmp-left-label').textContent  = leftLabel  || 'Left';
    qs('lb-cmp-right-label').textContent = rightLabel || 'Right';
    function setPane(wrapId, url) {
        const wrap = qs(wrapId); while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
        if (url) { const img = document.createElement('img'); img.src = url; img.alt = ''; img.style.cssText = 'max-width:100%;max-height:100%;object-fit:contain;'; wrap.appendChild(img); }
        else { const none = document.createElement('div'); none.className = 'lb-no-img'; none.textContent = 'No screenshot'; wrap.appendChild(none); }
    }
    setPane('lb-cmp-left-wrap', leftUrl); setPane('lb-cmp-right-wrap', rightUrl);
    qs('lb-title').textContent = 'Compare Screenshots';
    qs('lightbox').classList.add('open');
}

function applyLbTransform() {
    qs('lightbox-img').style.transform = `translate(${lbOffX}px,${lbOffY}px) scale(${lbScale})`;
    qs('lb-zoom-label').textContent = Math.round(lbScale * 100) + '%';
}

function closeLightbox() { qs('lightbox').classList.remove('open'); qs('lb-compare').classList.remove('active'); }

qs('btn-lb-close').addEventListener('click', closeLightbox);
qs('btn-lb-zoom-in').addEventListener('click', () => { lbScale = Math.min(lbScale + 0.25, 5); applyLbTransform(); });
qs('btn-lb-zoom-out').addEventListener('click', () => { lbScale = Math.max(lbScale - 0.25, 0.25); applyLbTransform(); });
qs('btn-lb-zoom-reset').addEventListener('click', () => { lbScale = 1; lbOffX = 0; lbOffY = 0; applyLbTransform(); });
qs('lb-btn-single').addEventListener('click', () => {
    lbMode = 'single';
    qs('lb-single').style.display = 'flex'; qs('lb-compare').style.display = 'none'; qs('lb-compare').classList.remove('active');
    qs('lb-btn-single').classList.add('active'); qs('lb-btn-compare').classList.remove('active');
});
qs('lb-btn-compare').addEventListener('click', () => {
    if (lbCompareUrls.left || lbCompareUrls.right) openCompare(lbCompareUrls.left, lbCompareUrls.right, 'Creator', 'Joiner');
});

qs('lightbox').addEventListener('wheel', e => {
    e.preventDefault();
    lbScale = Math.max(0.25, Math.min(5, lbScale + (e.deltaY < 0 ? 0.15 : -0.15)));
    applyLbTransform();
}, { passive: false });

const lbSingle = qs('lb-single');
lbSingle.addEventListener('mousedown', e => {
    if (e.button !== 0) return; lbDragging = true; lbDragX = e.clientX - lbOffX; lbDragY = e.clientY - lbOffY; lbSingle.classList.add('grabbing');
});
window.addEventListener('mousemove', e => { if (!lbDragging) return; lbOffX = e.clientX - lbDragX; lbOffY = e.clientY - lbDragY; applyLbTransform(); });
window.addEventListener('mouseup', () => { lbDragging = false; lbSingle.classList.remove('grabbing'); });
document.addEventListener('keydown', e => {
    if (qs('lightbox').classList.contains('open')) {
        if (e.key === 'Escape') closeLightbox();
        if (e.key === 'c' || e.key === 'C') qs('lb-btn-compare').click();
    }
});