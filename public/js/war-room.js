'use strict';

// ---------- Helpers ----------
function escapeHtml(s) {
    if (!s) return '—';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function qs(id) { return document.getElementById(id); }

// ---------- Session check ----------
// FIX 1: Read token from BOTH sessionStorage (set by updated dashboard.js openWarRoom())
//         AND localStorage (fallback for older sessions / direct navigation).
//         Previously only checked sessionStorage, causing immediate redirect to /login.
const authToken = sessionStorage.getItem('supabaseToken') || localStorage.getItem('supabaseToken');
if (!authToken) {
    window.location.href = '/login';
}

const rawData = sessionStorage.getItem('warRoomData');
if (!rawData) {
    window.location.href = '/dashboard';
}

let matchData = {};
try {
    matchData = JSON.parse(rawData);
} catch (e) {
    window.location.href = '/dashboard';
}

const {
    matchId,
    matchCode,
    creatorTeam,
    creatorUsername,
    joinerTeam,
    joinerUsername,
    wagerAmount,
    winnerPrize,
    startedAt,
    currentUserId,
    creatorId,
    resultPostDeadline
} = matchData;

// FIX 2: Detect environment the same way dashboard.js does.
//         The war-room.html CSP sets connect-src 'self', which blocks
//         http://localhost:3000 in local dev.  To work around this we
//         keep API calls relative ('/api/...') even in dev — the Express
//         server strips the /api prefix via the middleware in app.js, so
//         the same relative path works both locally and in production.
const API = '/api';

const isCreator = currentUserId === creatorId;

// ---------- Fill UI ----------
qs('home-team').textContent   = escapeHtml(creatorTeam || 'Unknown FC');
qs('home-player').textContent = escapeHtml(creatorUsername || '—');
qs('away-team').textContent   = escapeHtml(joinerTeam || 'Unknown FC');
qs('away-player').textContent = escapeHtml(joinerUsername || '—');

if (isCreator) {
    qs('home-player').classList.add('you-badge');
    qs('home-player').textContent = '👤 ' + escapeHtml(creatorUsername) + ' (You)';
} else {
    qs('away-player').classList.add('you-badge');
    qs('away-player').textContent = '👤 ' + escapeHtml(joinerUsername) + ' (You)';
}

qs('prize-display').textContent = winnerPrize ? `KES ${winnerPrize}` : `KES ${(wagerAmount || 0) * 2}`;
qs('wager-sub').textContent = wagerAmount ? `KES ${wagerAmount} staked each · Winner takes all` : 'Winner takes all';

qs('code-display').textContent = matchCode || '—';
if (!matchCode) qs('match-code-strip').style.display = 'none';

// ---------- Elapsed timer ----------
const startTime = startedAt ? new Date(startedAt) : new Date();
function updateElapsed() {
    const diff = Math.max(0, Math.floor((Date.now() - startTime.getTime()) / 1000));
    const m = Math.floor(diff / 60).toString().padStart(2, '0');
    const s = (diff % 60).toString().padStart(2, '0');
    qs('elapsed-display').textContent = `${m}:${s}`;
}
updateElapsed();
const elapsedInterval = setInterval(updateElapsed, 1000);

// ---------- 30-min result submission countdown ----------
const deadlineStrip = qs('deadline-strip');
const deadlineEl    = qs('deadline-display');
let deadlineTime    = resultPostDeadline ? new Date(resultPostDeadline) : null;
let deadlineInterval = null;

// FIX 3: The HTML had both display:none AND display:flex in the same inline
//         style attribute — display:flex always won, showing the strip before
//         any deadline was set.  We now control visibility exclusively via JS.
//         Start hidden; only reveal once we have a valid deadline.
if (deadlineStrip) deadlineStrip.style.display = 'none';

function updateDeadline() {
    if (!deadlineTime || !deadlineEl) return;
    const remaining = Math.max(0, deadlineTime.getTime() - Date.now());
    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    deadlineEl.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    if (remaining < 5 * 60 * 1000 && remaining > 0) {
        deadlineEl.style.color = '#ff4444';
        deadlineStrip.style.borderColor = 'rgba(255,68,68,0.4)';
        deadlineStrip.style.background  = 'rgba(255,68,68,0.06)';
    }
    if (remaining === 0) deadlineEl.textContent = 'EXPIRED';
}

function startDeadlineCountdown() {
    if (!deadlineTime) return;
    if (deadlineStrip) deadlineStrip.style.display = 'flex';
    updateDeadline();
    if (deadlineInterval) clearInterval(deadlineInterval);
    deadlineInterval = setInterval(updateDeadline, 1000);
}

if (deadlineTime) {
    startDeadlineCountdown();
} else if (matchId) {
    // Fetch deadline from API if not in sessionStorage
    fetch(`${API}/friends/match-status/${matchId}`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
    })
        .then(r => r.ok ? r.json() : null)
        .then(d => {
            if (d && d.resultPostDeadline) {
                deadlineTime = new Date(d.resultPostDeadline);
                startDeadlineCountdown();
            }
        })
        .catch(() => {});
}

// ---------- Result badge display ----------
function showResultBadge(youWon, prizeAmount) {
    const badge  = qs('result-badge');
    const title  = qs('result-badge-title');
    const amount = qs('result-badge-amount');

    if (youWon) {
        badge.className = 'result-badge won';
        title.textContent = 'YOU WON! 🏆';
        amount.textContent = `KES ${prizeAmount || winnerPrize} credited to wallet`;
    } else {
        badge.className = 'result-badge lost';
        title.textContent = 'YOU LOST';
        amount.textContent = 'Better luck next time!';
    }

    qs('wager-banner').style.display  = 'none';
    qs('teams-arena').style.display   = 'none';
    qs('war-actions').style.display   = 'none';
    qs('deadline-strip').style.display = 'none';
    qs('live-badge').style.display    = 'none';
}

// ---------- Live status polling ----------
// FIX 4: lastStatus was initialised to 'active' — the most common state a
//         match is in when the user arrives.  The first poll would immediately
//         bail out with "nothing changed", so the deadline countdown, status
//         banners, and completed/disputed states were never applied on load.
//         Initialise to null so the very first poll always processes the response.
let lastStatus = null;
let statusPollTimer = null;

async function pollMatchStatus() {
    if (!matchId) return;
    try {
        const res = await fetch(`${API}/friends/match-status/${matchId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (res.status === 401) {
            window.location.href = '/login';
            return;
        }
        if (!res.ok) return;
        const data = await res.json();

        // On the very first poll, also sync the deadline if we don't have it yet
        if (lastStatus === null && !deadlineTime && data.resultPostDeadline) {
            deadlineTime = new Date(data.resultPostDeadline);
            startDeadlineCountdown();
        }

        if (data.status === lastStatus) return; // nothing changed
        lastStatus = data.status;

        if (data.status === 'awaiting_confirmation') {
            showStatusBanner(
                '📋 SCORE DECLARED',
                data.iDeclared
                    ? 'Waiting for your opponent to confirm. Check the dashboard.'
                    : `Your opponent declared a result. Open the dashboard to confirm or dispute.`,
                '#ffb400'
            );
            if (!data.iDeclared) {
                setTimeout(() => { window.location.href = '/dashboard'; }, 3000);
            }
        } else if (data.status === 'penalty_shootout') {
            showStatusBanner(
                `⚽ IT'S A DRAW — PENALTIES!`,
                `Match drew${data.drawScore ? ' ' + data.drawScore : ''}. Go to eFootball → create a new Friends Match room → play a Penalty Shootout → come back and upload the result.`,
                '#ffd700'
            );
            const reportBtn = qs('btn-report');
            if (reportBtn) reportBtn.textContent = '📸 Upload Penalty Result';
        } else if (data.status === 'no_show_forfeit') {
            clearPolling();
            showStatusBanner(
                '⏰ WAGERS FORFEITED',
                'Neither player submitted results within 30 minutes. Both wagers were forfeited to the platform.',
                '#ff6666'
            );
            setTimeout(() => { window.location.href = '/dashboard'; }, 5000);
        } else if (data.status === 'completed') {
            clearPolling();
            if (data.youWon) {
                showResultBadge(true, data.winnerPrize);
                showStatusBanner('🏆 YOU WON!', `KES ${data.winnerPrize || winnerPrize} has been credited to your wallet.`, '#00ff41');
            } else if (data.settlementMethod === 'forfeit') {
                showResultBadge(false, 0);
                showStatusBanner('🏳️ MATCH FORFEITED', data.statusMessage || 'Match was forfeited.', '#ff8800');
            } else {
                showResultBadge(false, 0);
                showStatusBanner('❌ YOU LOST', 'Better luck next time.', '#ff4444');
            }
            setTimeout(() => { window.location.href = '/dashboard'; }, 2000);
        } else if (data.status === 'disputed') {
            clearPolling();
            showStatusBanner('⚠️ MATCH DISPUTED', 'An admin is reviewing this match. Check back later.', '#ff8800');
        }
    } catch (err) {
        console.warn('Status poll error:', err.message);
    }
}

function showStatusBanner(title, message, color) {
    let banner = qs('status-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'status-banner';
        banner.style.cssText = `
            position:fixed; top:0; left:0; right:0; z-index:999;
            padding:16px 20px; text-align:center;
            font-family:'Outfit',sans-serif; font-weight:700;
            border-bottom:2px solid currentColor;
            animation: slideDown 0.4s ease;
        `;
        document.body.prepend(banner);
    }
    banner.style.background  = 'rgba(0,0,0,0.95)';
    banner.style.color       = color;
    banner.style.borderColor = color;

    while (banner.firstChild) banner.removeChild(banner.firstChild);

    const titleDiv = document.createElement('div');
    titleDiv.style.cssText = 'font-size:1.1rem;letter-spacing:2px';
    titleDiv.textContent = title;
    banner.appendChild(titleDiv);

    const msgDiv = document.createElement('div');
    msgDiv.style.cssText = 'font-size:0.8rem;font-weight:400;margin-top:4px;color:#ccc';
    msgDiv.textContent = message;
    banner.appendChild(msgDiv);
}

function clearPolling() {
    if (statusPollTimer) {
        clearInterval(statusPollTimer);
        statusPollTimer = null;
    }
}

statusPollTimer = setInterval(pollMatchStatus, 10000);
pollMatchStatus(); // run immediately — now works correctly with lastStatus = null

// ---------- Copy code ----------
function copyCode() {
    if (!matchCode) return;
    navigator.clipboard.writeText(matchCode).then(() => {
        const btn = qs('copy-code-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 2000);
    });
}

// ---------- Forfeit ----------
async function forfeitMatch() {
    if (!confirm('Are you sure you want to forfeit? Your opponent will win the wager.')) return;
    try {
        const res = await fetch(`${API}/friends/forfeit`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ matchId })
        });
        const data = await res.json();
        if (res.ok) {
            showStatusBanner('🏳️ FORFEITED', 'You forfeited. Returning to dashboard...', '#ff8800');
            setTimeout(() => { window.location.href = '/dashboard'; }, 2500);
        } else {
            // FIX 5: Replace alert() with a non-blocking status banner
            showStatusBanner('❌ Forfeit Failed', data.error || 'Could not forfeit. Try again.', '#ff4444');
        }
    } catch (err) {
        showStatusBanner('❌ Network Error', 'Check your connection and try again.', '#ff4444');
    }
}

// ---------- Navigation ----------
function goReport() {
    sessionStorage.setItem('openReportMatchId', matchId);
    window.location.href = '/dashboard';
}

function goBack() {
    window.location.href = '/dashboard';
}

// ---------- Attach event listeners after DOM ready ----------
document.addEventListener('DOMContentLoaded', () => {
    qs('copy-code-btn')?.addEventListener('click', copyCode);
    qs('btn-report')?.addEventListener('click', goReport);
    qs('back-btn')?.addEventListener('click', goBack);
    qs('forfeit-btn')?.addEventListener('click', forfeitMatch);
});

// ---------- Cleanup on page unload ----------
window.addEventListener('beforeunload', () => {
    if (elapsedInterval)  clearInterval(elapsedInterval);
    if (deadlineInterval) clearInterval(deadlineInterval);
    if (statusPollTimer)  clearInterval(statusPollTimer);
});