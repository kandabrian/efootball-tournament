// /public/js/dashboard.js – Simplified, no OCR, only admin review

'use strict';

function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function createElementSafe(tag, attributes = {}, textContent = '') {
    const el = document.createElement(tag);
    Object.entries(attributes).forEach(([key, value]) => el.setAttribute(key, value));
    if (textContent) el.textContent = escapeHtml(textContent);
    return el;
}

let authToken = sessionStorage.getItem('supabaseToken');
let currentUser = null;
let currentBalance = 0;
let currentPhone = '';
let currentUsername = '';
let currentTeam = '';
let currentCheckoutId = null;
let pollInterval = null;
let currentFriendMatch = null;
let friendMatchTimer = null;
let currentReportMatch = null;
let currentTournamentId = null, currentTournamentFee = 0, currentTournamentName = '';
let balanceRefreshInterval = null;
let matchStatusPollInterval = null;
let matchesRefreshInterval = null;
let realtimeChannel = null;

function showError(elementId, message) {
    const el = document.getElementById(elementId);
    if (el) { el.textContent = escapeHtml(message); el.style.display = 'block'; }
}
function hideError(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.style.display = 'none';
}

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const API = isLocal ? 'http://localhost:3000' : '/api';

const SUPABASE_URL = 'https://wqnnuqudxsnxldlgxhwr.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Indxbm51cXVkeHNueGxkbGd4aHdyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA5MDQ4NDUsImV4cCI6MjA4NjQ4MDg0NX0.MIoGi_PiwbGPrAxEfaypLLlpNkHUNliDNFoehdf7uPg';

let supabaseRealtime = null;

async function fetchWithAuth(url, options = {}, timeoutMs = 8000) {
    if (!authToken) { window.location.href = '/login'; return; }
    const isMultipart = options.body instanceof FormData;
    const headers = {
        ...(isMultipart ? {} : { 'Content-Type': 'application/json' }),
        'Authorization': `Bearer ${authToken}`,
        ...options.headers
    };
    const fullUrl = url.startsWith('http') ? url : `${API}${url}`;
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
        const res = await fetch(fullUrl, { ...options, headers, signal: controller.signal });
        clearTimeout(timeoutId);
        if (res.status === 401) {
            sessionStorage.removeItem('supabaseToken');
            sessionStorage.removeItem('supabaseUser');
            window.location.href = '/login';
            return;
        }
        return res;
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            throw new Error(`Request timeout after ${timeoutMs}ms`);
        }
        throw err;
    }
}

async function subscribeToBalance(userId) {
    if (!supabaseRealtime) {
        console.warn('⚠️ Supabase realtime not available, falling back to polling');
        startBalanceAutoRefresh();
        return;
    }
    
    console.log('🔔 Setting up realtime subscription for wallet:', userId);
    
    if (realtimeChannel) {
        console.log('🧹 Removing old realtime channel...');
        supabaseRealtime.removeChannel(realtimeChannel);
        realtimeChannel = null;
    }
    
    realtimeChannel = supabaseRealtime
        .channel(`wallet-${userId}`)
        .on(
            'postgres_changes',
            {
                event: 'UPDATE',
                schema: 'public',
                table: 'wallets',
                filter: `user_id=eq.${userId}`
            },
            (payload) => {
                console.log('🔔 Real-time balance update received:', payload);
                if (payload.new.user_id !== currentUser.id) {
                    console.error('❌ SECURITY: Received balance update for different user!');
                    return;
                }
                console.log(`💰 Real-time balance update: ${currentBalance} → ${payload.new.balance}`);
                currentBalance = payload.new.balance;
                updateBalanceDisplay();
            }
        )
        .subscribe((status) => {
            console.log('🔌 Realtime subscription status:', status);
            const indicator = document.getElementById('realtime-indicator');
            if (indicator) {
                indicator.style.opacity = status === 'SUBSCRIBED' ? '1' : '0.5';
            }
            if (status === 'SUBSCRIBED') {
                console.log('✅ Realtime subscription active for user:', userId);
            } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
                console.error('❌ Realtime subscription failed:', status);
                startBalanceAutoRefresh(30000);
            }
        });
    
    console.log('✅ Realtime channel created:', `wallet-${userId}`);
}

async function loadDashboard() {
    try {
        console.log('🚀 Starting loadDashboard...');
        
        if (supabaseRealtime && realtimeChannel) {
            console.log('🧹 Cleaning up old realtime connection...');
            supabaseRealtime.removeChannel(realtimeChannel);
            realtimeChannel = null;
        }
        
        authToken = sessionStorage.getItem('supabaseToken');
        if (!authToken) {
            console.error('❌ No auth token found');
            window.location.href = '/login';
            return;
        }
        
        if (typeof supabase !== 'undefined') {
            console.log('🔌 Creating new Supabase realtime client with fresh token...');
            supabaseRealtime = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
                global: { headers: { Authorization: `Bearer ${authToken}` } },
                realtime: { params: { apikey: SUPABASE_ANON_KEY } }
            });
        } else {
            console.error('❌ Supabase SDK not loaded! Realtime will be unavailable.');
        }
        
        const userStr = sessionStorage.getItem('supabaseUser');
        if (!userStr) { window.location.href = '/login'; return; }
        currentUser = JSON.parse(userStr);
        console.log('👤 Loaded user:', currentUser.id, currentUser.phone);
        
        currentUsername = currentUser.user_metadata?.username || currentUser.phone?.substring(0,8) || 'Player';
        const walletUsernameEl = document.getElementById('wallet-username-display');
        if (walletUsernameEl) walletUsernameEl.textContent = '@' + currentUsername;
        document.getElementById('username-display').innerText = '@' + currentUsername;
        document.getElementById('avatar-letter').innerText = currentUsername.charAt(0).toUpperCase();
        if (currentUser.phone) {
            let phone = currentUser.phone.replace('+254', '0');
            currentPhone = phone;
            const dPhone = document.getElementById('deposit-phone');
            const wPhone = document.getElementById('withdraw-phone');
            if (dPhone) dPhone.value = phone;
            if (wPhone) wPhone.value = phone;
        }

        console.log('🚀 Loading dashboard data...');
        
        let balanceLoaded = false;
        try {
            await refreshBalance(3);
            if (currentBalance >= 0) {
                balanceLoaded = true;
                console.log('✅ Balance loaded successfully:', currentBalance);
            }
        } catch (e) {
            console.error('❌ Balance fetch failed:', e);
        }
        
        if (!balanceLoaded) {
            console.error('❌ CRITICAL: Balance could not be loaded!');
            currentBalance = 0;
            updateBalanceDisplay();
            alert('⚠️ Could not load your balance. Please refresh the page.');
        }
        
        await loadProfile().catch(e => console.warn('Profile fetch failed:', e));

        loadTournaments();
        loadMyFriendMatches();
        
        if (matchesRefreshInterval) clearInterval(matchesRefreshInterval);
        matchesRefreshInterval = setInterval(() => {
            console.log('🔄 Auto-refreshing matches list...');
            loadMyFriendMatches();
        }, 10000);
        
        if (supabaseRealtime) {
            console.log('🔔 Setting up realtime subscription for user:', currentUser.id);
            subscribeToBalance(currentUser.id);
        } else {
            console.warn('⚠️ Realtime unavailable, using polling only');
            startBalanceAutoRefresh(30000);
        }
        
        document.getElementById('loading-screen').style.display = 'none';
        document.getElementById('main-content').style.display = 'block';
        
        startBalanceAutoRefresh(120000);
        
        console.log('✅ Dashboard loaded successfully');
        
    } catch (err) {
        console.error('Failed to load dashboard', err);
        document.getElementById('loading-screen').style.display = 'none';
        document.getElementById('main-content').style.display = 'block';
        alert('⚠️ Error loading dashboard. Some features may not work correctly.');
    }
}

async function refreshBalance(retries = 2) {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            console.log(`📡 Fetching balance (attempt ${attempt}/${retries})...`);
            const res = await fetchWithAuth('/wallet/balance', {}, 5000);
            if (!res) {
                console.error('❌ refreshBalance: No response from server');
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 1000 * attempt));
                    continue;
                }
                return;
            }
            if (!res.ok) {
                console.error('❌ refreshBalance: HTTP', res.status);
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 1000 * attempt));
                    continue;
                }
                return;
            }
            const data = await res.json();
            if (typeof data.balance === 'number') {
                console.log(`✅ Balance updated: ${currentBalance} → ${data.balance}`);
                currentBalance = data.balance;
                updateBalanceDisplay();
                return;
            } else {
                console.error('❌ Invalid balance response:', data);
            }
        } catch (err) {
            console.error(`❌ refreshBalance attempt ${attempt} failed:`, err.message, err);
            if (attempt < retries) {
                await new Promise(r => setTimeout(r, 1000 * attempt));
            }
        }
    }
    console.error('❌ refreshBalance: All attempts failed, balance remains:', currentBalance);
}

function updateBalanceDisplay() {
    const balElement = document.getElementById('balance');
    if (!balElement) {
        console.error('❌ Balance element not found in DOM!');
        return;
    }
    balElement.innerText = currentBalance.toFixed(2);
    balElement.classList.remove('balance-flash');
    void balElement.offsetWidth;
    balElement.classList.add('balance-flash');
}

function startBalanceAutoRefresh(intervalMs = 30000) {
    if (balanceRefreshInterval) {
        clearInterval(balanceRefreshInterval);
    }
    balanceRefreshInterval = setInterval(() => {
        console.log('🔄 Auto-refreshing balance (fallback)...');
        refreshBalance().catch(err => {
            console.error('Failed to auto-refresh balance:', err);
        });
    }, intervalMs);
    console.log(`✅ Balance auto-refresh started (${intervalMs/1000}s interval)`);
}

function stopBalanceAutoRefresh() {
    if (balanceRefreshInterval) {
        clearInterval(balanceRefreshInterval);
        balanceRefreshInterval = null;
        console.log('⏹️  Balance auto-refresh stopped');
    }
    if (realtimeChannel) {
        supabaseRealtime.removeChannel(realtimeChannel);
        realtimeChannel = null;
    }
}

async function loadProfile() {
    try {
        const res = await fetchWithAuth('/profile', {}, 5000);
        if (res && res.ok) {
            const profile = await res.json();
            currentTeam = profile.team_name || '';
            document.getElementById('team-display').innerText = currentTeam || '—';
            const walletUsernameEl2 = document.getElementById('wallet-username-display');
            if (walletUsernameEl2) walletUsernameEl2.textContent = '@' + currentUsername;
            document.getElementById('profile-username').value = escapeHtml(currentUsername);
            document.getElementById('profile-team').value = escapeHtml(currentTeam);
        }
    } catch (e) {
        console.warn('loadProfile failed:', e);
    }
}

async function saveProfile() {
    const teamName = document.getElementById('profile-team').value.trim();
    if (!teamName) { showError('profile-error', 'Team name cannot be empty'); return; }
    if (teamName.length < 3) { showError('profile-error', 'Team name must be at least 3 characters'); return; }
    const btn = document.querySelector('#profile-modal .btn-mpesa');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    try {
        const res = await fetchWithAuth('/profile/team', {
            method: 'POST',
            body: JSON.stringify({ teamName })
        }, 5000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        currentTeam = teamName;
        document.getElementById('team-display').innerText = teamName;
        document.getElementById('profile-team').value = escapeHtml(teamName);
        closeModal('profile-modal');
        alert('Team name updated successfully!');
    } catch (err) {
        showError('profile-error', err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'SAVE CHANGES';
    }
}

async function loadTournaments() {
    try {
        const res = await fetch(`${API}/tournaments`);
        if (!res.ok) throw new Error('Failed to load tournaments');
        const tournaments = await res.json();
        renderTournaments(tournaments);
    } catch (err) {
        console.error('Error loading tournaments:', err);
        const container = document.getElementById('tournament-list');
        container.innerHTML = '';
        const noTourney = document.createElement('div');
        noTourney.className = 'tournament-card';
        noTourney.style.cssText = 'text-align:center;padding:28px;color:#444;font-size:0.82rem;';
        const icon = document.createElement('div'); icon.style.cssText = 'font-size:2rem;margin-bottom:8px;opacity:0.3;'; icon.textContent = '🏆';
        noTourney.appendChild(icon);
        noTourney.appendChild(document.createTextNode('No active tournaments right now.'));
        noTourney.appendChild(document.createElement('br'));
        const sub = document.createElement('span'); sub.style.cssText = 'font-size:0.72rem;color:#333;'; sub.textContent = 'Check back soon!';
        noTourney.appendChild(sub);
        container.appendChild(noTourney);
    }
}

function renderTournaments(tournaments) {
    const container = document.getElementById('tournament-list');
    container.innerHTML = '';
    if (!tournaments || tournaments.length === 0) {
        const noTourney = document.createElement('div');
        noTourney.className = 'tournament-card';
        noTourney.style.cssText = 'text-align:center;padding:28px;color:#444;font-size:0.82rem;';
        const icon2 = document.createElement('div'); icon2.style.cssText = 'font-size:2rem;margin-bottom:8px;opacity:0.3;'; icon2.textContent = '🏆';
        noTourney.appendChild(icon2);
        noTourney.appendChild(document.createTextNode('No active tournaments right now.'));
        noTourney.appendChild(document.createElement('br'));
        const sub2 = document.createElement('span'); sub2.style.cssText = 'font-size:0.72rem;color:#333;'; sub2.textContent = 'Check back soon!';
        noTourney.appendChild(sub2);
        container.appendChild(noTourney);
        return;
    }
    tournaments.forEach(t => {
        const card = createElementSafe('div', { class: `tournament-card ${t.status === 'live' ? 'live' : ''}` });
        card.addEventListener('click', () => openChallengeModal(t.id, t.name, t.entry_fee));

        const headerDiv = createElementSafe('div', { class: 't-header' });
        const titleDiv = createElementSafe('div', {});
        titleDiv.appendChild(createElementSafe('div', { class: 't-name' }, t.name));
        const startTime = new Date(t.start_time).toLocaleDateString('en-KE', { weekday: 'short', hour: '2-digit', minute: '2-digit' });
        titleDiv.appendChild(createElementSafe('div', { class: 't-meta' }, `Starts ${startTime}`));
        headerDiv.appendChild(titleDiv);

        const badgeSpan = document.createElement('span');
        badgeSpan.className = `t-badge ${t.status === 'live' ? 'live-badge' : 'soon-badge'}`;
        if (t.status === 'live') {
            const pip = document.createElement('span');
            pip.className = 'live-pip';
            badgeSpan.appendChild(pip);
            badgeSpan.appendChild(document.createTextNode(' LIVE'));
        } else {
            badgeSpan.textContent = '🗓 SOON';
        }
        headerDiv.appendChild(badgeSpan);
        card.appendChild(headerDiv);

        const footerDiv = createElementSafe('div', { class: 't-footer' });
        const prizeDiv = createElementSafe('div', { class: 't-prize' });
        prizeDiv.appendChild(createElementSafe('small', {}, 'PRIZE POOL'));
        prizeDiv.appendChild(document.createTextNode(`KES ${(t.prize_pool || 0).toLocaleString()}`));
        footerDiv.appendChild(prizeDiv);

        const rightDiv = createElementSafe('div', { style: 'display:flex;flex-direction:column;align-items:flex-end;gap:8px;' });
        rightDiv.appendChild(createElementSafe('div', { class: 't-players' }, `👥 ${t.current_players}/${t.max_players}`));
        const joinBtn = createElementSafe('button', { class: 'btn-join' }, `KES ${t.entry_fee} →`);
        rightDiv.appendChild(joinBtn);
        footerDiv.appendChild(rightDiv);
        card.appendChild(footerDiv);

        const pct = t.max_players > 0 ? Math.round((t.current_players / t.max_players) * 100) : 0;
        const progressDiv = createElementSafe('div', { class: 'progress-bar' });
        progressDiv.appendChild(createElementSafe('div', { class: 'progress-fill', style: `width:${pct}%` }));
        card.appendChild(progressDiv);

        container.appendChild(card);
    });
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('open');
    if (modalId === 'deposit-modal' && pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    if (modalId === 'waiting-friend-modal' && friendMatchTimer) { clearInterval(friendMatchTimer); friendMatchTimer = null; }
    if (modalId === 'waiting-friend-modal') { stopMatchStatusPolling(); }
    if (modalId === 'report-result-modal') { currentReportMatch = null; resetReportModal(); }
}

function openDepositModal() {
    hideError('deposit-error');
    switchStep('deposit-modal', 1);
    document.getElementById('deposit-amount').value = '';
    document.getElementById('deposit-modal').classList.add('open');
}

function selectPreset(btn, amount) {
    document.querySelectorAll('#deposit-modal .preset-btn').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    document.getElementById('deposit-amount').value = amount;
}

async function processDeposit() {
    const amount = parseInt(document.getElementById('deposit-amount').value);
    const phone = document.getElementById('deposit-phone').value.trim();
    if (!amount || amount < 10) { showError('deposit-error', 'Minimum deposit is KES 10'); return; }
    if (!phone) { showError('deposit-error', 'Enter your M-PESA number'); return; }

    let cleanPhone = phone.replace(/[\s\-]/g, '');
    if (cleanPhone.startsWith('+254'))      cleanPhone = cleanPhone;
    else if (cleanPhone.startsWith('254'))  cleanPhone = '+' + cleanPhone;
    else if (cleanPhone.startsWith('0'))    cleanPhone = '+254' + cleanPhone.substring(1);
    else if (/^[71]/.test(cleanPhone))      cleanPhone = '+254' + cleanPhone;
    const digits = cleanPhone.replace('+', '');
    if (!/^254[17]\d{8}$/.test(digits)) {
        showError('deposit-error', 'Invalid M-PESA number. Use format 07XX XXX XXX or +254 7XX XXX XXX');
        return;
    }

    const btn = document.querySelector('#deposit-modal .btn-mpesa');
    btn.disabled = true; btn.textContent = 'Sending request...';
    try {
        const res = await fetchWithAuth('/wallet/deposit', {
            method: 'POST',
            body: JSON.stringify({ amount, phone: cleanPhone })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        currentCheckoutId = data.checkoutRequestId;
        switchStep('deposit-modal', 2);
        pollInterval = setInterval(() => checkDepositStatus(currentCheckoutId), 3000);
    } catch (err) {
        showError('deposit-error', err.message);
    } finally {
        btn.disabled = false; btn.textContent = 'PAY WITH M-PESA 📲';
    }
}

async function checkDepositStatus(checkoutId) {
    try {
        const res = await fetchWithAuth(`/wallet/deposit/status?checkoutId=${checkoutId}`, {}, 5000);
        if (!res) return;
        const data = await res.json();
        if (data.status === 'completed') {
            clearInterval(pollInterval); pollInterval = null;
            closeModal('deposit-modal');
            await refreshBalance();
            alert('✅ Deposit successful! Your balance has been updated.');
        } else if (data.status === 'failed') {
            clearInterval(pollInterval); pollInterval = null;
            switchStep('deposit-modal', 1);
            showError('deposit-error', 'Payment failed or cancelled. Try again.');
        }
    } catch (err) { /* keep polling */ }
}

function openWithdrawModal() {
    hideError('withdraw-error');
    document.getElementById('withdraw-amount').value = '';
    document.getElementById('withdraw-step-1').style.display = 'block';
    document.getElementById('withdraw-step-2').style.display = 'none';
    // Show current balance in modal
    const balEl = document.getElementById('withdraw-balance-display');
    if (balEl) balEl.textContent = 'KES ' + (currentBalance || 0).toLocaleString();
    document.getElementById('withdraw-modal').classList.add('open');

    // Wire preset buttons
    document.querySelectorAll('.withdraw-preset-btn').forEach(btn => {
        btn.classList.remove('active');
        btn.onclick = () => {
            document.querySelectorAll('.withdraw-preset-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('withdraw-amount').value = btn.dataset.amount;
            updateWithdrawFeeNote();
        };
    });

    // Live fee note on amount input
    document.getElementById('withdraw-amount').oninput = () => {
        document.querySelectorAll('.withdraw-preset-btn').forEach(b => b.classList.remove('active'));
        updateWithdrawFeeNote();
    };
}

function updateWithdrawFeeNote() {
    const amt = parseInt(document.getElementById('withdraw-amount').value) || 0;
    const feeNote = document.getElementById('withdraw-fee-note');
    const receiveEl = document.getElementById('withdraw-receive-amount');
    if (amt >= 50) {
        feeNote.style.display = 'block';
        receiveEl.textContent = 'KES ' + amt.toLocaleString();
    } else {
        feeNote.style.display = 'none';
    }
}

async function processWithdraw() {
    const amount = parseInt(document.getElementById('withdraw-amount').value);
    const phone = document.getElementById('withdraw-phone').value.trim();
    if (!amount || amount < 50) { showError('withdraw-error', 'Minimum withdrawal is KES 50'); return; }
    if (amount > currentBalance) { showError('withdraw-error', 'Insufficient balance. Available: KES ' + currentBalance.toLocaleString()); return; }
    if (!phone) { showError('withdraw-error', 'Enter your M-PESA number'); return; }

    let cleanPhone = phone.replace(/[\s\-]/g, '');
    if (cleanPhone.startsWith('+254'))      cleanPhone = cleanPhone;
    else if (cleanPhone.startsWith('254'))  cleanPhone = '+' + cleanPhone;
    else if (cleanPhone.startsWith('0'))    cleanPhone = '+254' + cleanPhone.substring(1);
    else if (/^[71]/.test(cleanPhone))      cleanPhone = '+254' + cleanPhone;
    const _wDigits = cleanPhone.replace('+', '');
    if (!/^254[17]\d{8}$/.test(_wDigits)) {
        showError('withdraw-error', 'Invalid M-PESA number. Use format 07XX XXX XXX');
        return;
    }

    const btn = document.getElementById('btn-process-withdraw');
    btn.disabled = true;
    btn.textContent = 'Processing...';
    btn.style.opacity = '0.7';

    try {
        const res = await fetchWithAuth('/wallet/withdrawals/request', {
            method: 'POST',
            body: JSON.stringify({ amount, phoneNumber: cleanPhone })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || (data.reasons ? data.reasons.join('. ') : 'Withdrawal failed'));

        await refreshBalance();

        // Show success step
        document.getElementById('withdraw-step-1').style.display = 'none';
        document.getElementById('withdraw-step-2').style.display = 'block';
        document.getElementById('withdraw-success-amount').textContent = 'KES ' + amount.toLocaleString();
        document.getElementById('withdraw-success-phone').textContent = '→ ' + cleanPhone;

        // Update balance chip
        const balEl = document.getElementById('withdraw-balance-display');
        if (balEl) balEl.textContent = 'KES ' + (currentBalance || 0).toLocaleString();

    } catch (err) {
        showError('withdraw-error', err.message);
        btn.disabled = false;
        btn.textContent = 'WITHDRAW NOW →';
        btn.style.opacity = '1';
    }
}

function openChallengeModal(tournamentId, name, fee) {
    currentTournamentId = tournamentId;
    currentTournamentFee = fee;
    currentTournamentName = name;
    document.getElementById('challenge-name').textContent = escapeHtml(name);
    document.getElementById('challenge-fee').textContent = `KES ${fee}`;
    hideError('challenge-error');
    switchStep('challenge-modal', 1);
    document.getElementById('challenge-modal').classList.add('open');
}

async function confirmChallenge(method) {
    if (!currentTournamentId) return;

    if (method === 'wallet' && currentBalance < currentTournamentFee) {
        showError('challenge-error', 'Insufficient balance. Please deposit first.');
        return;
    }

    if (method === 'mpesa') {
        switchStep('challenge-modal', 2);
        try {
            const payRes = await fetchWithAuth('/wallet/deposit', {
                method: 'POST',
                body: JSON.stringify({ amount: currentTournamentFee, phone: '+254' + currentPhone.replace(/^0/, '') })
            }, 10000);
            const payData = await payRes.json();
            if (!payRes.ok) { switchStep('challenge-modal', 1); showError('challenge-error', payData.error); return; }
            currentCheckoutId = payData.checkoutRequestId;
            pollInterval = setInterval(async () => {
                try {
                    const sRes = await fetchWithAuth(`/wallet/deposit/status?checkoutId=${currentCheckoutId}`, {}, 5000);
                    if (!sRes) return;
                    const sData = await sRes.json();
                    if (sData.status === 'completed') {
                        clearInterval(pollInterval); pollInterval = null;
                        await doJoinTournament('mpesa', currentCheckoutId);
                    } else if (sData.status === 'failed') {
                        clearInterval(pollInterval); pollInterval = null;
                        switchStep('challenge-modal', 1);
                        showError('challenge-error', 'M-PESA payment failed.');
                    }
                } catch(e) {}
            }, 3000);
        } catch(err) {
            switchStep('challenge-modal', 1);
            showError('challenge-error', err.message);
        }
        return;
    }

    await doJoinTournament('wallet', null);
}

async function doJoinTournament(paymentMethod, checkoutId) {
    try {
        console.log('📝 Joining tournament:', currentTournamentId, 'Payment:', paymentMethod);
        const res = await fetchWithAuth('/tournament/join', {
            method: 'POST',
            body: JSON.stringify({
                tournamentId: currentTournamentId,
                entryFee: currentTournamentFee,
                paymentMethod,
                checkoutId
            })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        
        console.log('✅ Tournament joined successfully');
        
        closeModal('challenge-modal');
        
        await refreshBalance(3);
        console.log('💰 Balance refreshed after tournament join:', currentBalance);
        
        if (data.roomCode) {
            document.getElementById('room-code-display').textContent = data.roomCode;
            document.getElementById('room-modal').classList.add('open');
        } else {
            alert(`✅ ${data.message || 'Umejiunga!'}`);
        }
        await loadTournaments();
    } catch (err) {
        switchStep('challenge-modal', 1);
        showError('challenge-error', err.message);
    }
}

function openCreateMatchModal() {
    if (!currentTeam) {
        alert('Please set your team name in profile before creating a match.');
        openProfileModal();
        return;
    }
    document.getElementById('friend-wager-input').value = 200;
    updateFriendBreakdown();
    hideError('create-friend-error');
    document.getElementById('create-friend-modal').classList.add('open');
}

function openJoinMatchModal() {
    if (!currentTeam) {
        alert('Please set your team name in profile before joining a match.');
        openProfileModal();
        return;
    }
    document.getElementById('join-friend-code').value = '';
    hideError('join-friend-error');
    document.getElementById('join-friend-modal').classList.add('open');
}

function selectFriendPreset(btn, amount) {
    document.querySelectorAll('#create-friend-modal .preset-btn').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    document.getElementById('friend-wager-input').value = amount;
    updateFriendBreakdown();
}

function updateFriendBreakdown() {
    const wager = parseInt(document.getElementById('friend-wager-input').value) || 100;
    const platformFee = Math.floor(wager * 2 * 0.10);
    const winnerPrize = (wager * 2) - platformFee;
    document.getElementById('friend-your-stake').textContent = wager;
    document.getElementById('friend-opp-stake').textContent = wager;
    document.getElementById('friend-total-pot').textContent = wager * 2;
    document.getElementById('friend-platform-fee').textContent = platformFee;
    document.getElementById('friend-winner-prize').textContent = winnerPrize;
    document.getElementById('create-friend-amount').textContent = wager;
}

async function createFriendMatch() {
    const wagerAmount = parseInt(document.getElementById('friend-wager-input').value);
    const efootballCode = document.getElementById('friend-efootball-code').value.trim().toUpperCase();
    const errorEl = document.getElementById('create-friend-error');
    const btn = document.getElementById('create-friend-btn');

    if (!efootballCode) { showError('create-friend-error', 'Please enter your eFootball room code'); return; }
    if (wagerAmount < 50) { showError('create-friend-error', 'Minimum wager is KES 50'); return; }
    if (wagerAmount > currentBalance) { showError('create-friend-error', 'Insufficient balance'); return; }

    btn.disabled = true;
    btn.textContent = 'Creating...';
    try {
        console.log('📝 Creating friend match with eFootball code:', efootballCode, 'wager:', wagerAmount);
        const res = await fetchWithAuth('/friends/create-match', {
            method: 'POST',
            body: JSON.stringify({ wagerAmount, efootballCode })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        console.log('✅ Match created successfully');

        currentFriendMatch = data;

        await refreshBalance(3);
        console.log('💰 Balance refreshed after create:', currentBalance);

        document.getElementById('friend-match-code').textContent = data.efootballCode;
        document.getElementById('waiting-stake-display').textContent = wagerAmount;
        document.getElementById('waiting-prize-display').textContent = data.winnerPrize;
        startFriendTimer(data.expiresAt);
        closeModal('create-friend-modal');
        document.getElementById('waiting-friend-modal').classList.add('open');

        const matchId = data.matchId || data.id;
        if (matchId) {
            startMatchStatusPolling(matchId);
        } else {
            console.warn('⚠️ No matchId returned from server – polling disabled');
        }

        await loadMyFriendMatches();
    } catch (err) {
        console.error('❌ Error creating match:', err);
        showError('create-friend-error', err.message);
        await refreshBalance(3);
    } finally {
        btn.disabled = false;
        btn.textContent = '';
        btn.appendChild(document.createTextNode('CREATE CHALLENGE (Pay KES '));
        const _amtSpan = document.createElement('span');
        _amtSpan.id = 'create-friend-amount';
        _amtSpan.textContent = String(wagerAmount);
        btn.appendChild(_amtSpan);
        btn.appendChild(document.createTextNode(')'));
    }
}

async function joinFriendMatch() {
    const efootballCode = document.getElementById('join-friend-code').value.trim().toUpperCase();
    const errorEl = document.getElementById('join-friend-error');
    if (!efootballCode) { showError('join-friend-error', 'Please enter your opponent\'s eFootball room code'); return; }
    try {
        console.log('📝 Joining friend match with eFootball code:', efootballCode);
        const res = await fetchWithAuth('/friends/join-match', {
            method: 'POST',
            body: JSON.stringify({ efootballCode })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        console.log('✅ Match joined successfully');

        await refreshBalance(3);
        console.log('💰 Balance refreshed after join:', currentBalance);

        currentFriendMatch = data;
        closeModal('join-friend-modal');
        openWarRoom({
            matchId:         data.matchId,
            matchCode:       data.matchCode || null,
            creatorTeam:     data.creatorTeam     || 'Unknown FC',
            creatorUsername: data.creatorUsername || 'Opponent',
            joinerTeam:      currentTeam,
            joinerUsername:  currentUsername,
            wagerAmount:     data.wagerAmount,
            winnerPrize:     data.winnerPrize,
            startedAt:       new Date().toISOString(),
            currentUserId:   currentUser.id,
            creatorId:       data.creatorId || data.opponentId,
            resultPostDeadline: data.resultPostDeadline || null,
        });
    } catch (err) {
        console.error('❌ Error joining match:', err);
        showError('join-friend-error', err.message);
        await refreshBalance(3);
    }
}

async function cancelFriendMatch() {
    if (!confirm('Are you sure you want to cancel? You\'ll get your wager back.')) return;
    stopMatchStatusPolling();
    try {
        console.log('📝 Cancelling friend match');
        const res = await fetchWithAuth('/friends/cancel-match', {
            method: 'POST',
            body: JSON.stringify({ matchId: currentFriendMatch.matchId })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        
        console.log('✅ Match cancelled, refund:', data.refundedAmount);
        
        await refreshBalance(3);
        console.log('💰 Balance refreshed after cancel:', currentBalance);
        
        if (friendMatchTimer) { clearInterval(friendMatchTimer); friendMatchTimer = null; }
        closeModal('waiting-friend-modal');
        showToast('info', 'Match Cancelled', `KES ${data.refundedAmount} refunded to your wallet.`, 5000);
        await loadMyFriendMatches();
    } catch (err) {
        console.error('❌ Error cancelling match:', err);
        showToast('error', 'Cancellation Failed', err.message, 5000);
        await refreshBalance(3);
    }
}

function shareFriendCode() {
    const code = document.getElementById('friend-match-code').textContent;
    const wager = parseInt(document.getElementById('waiting-stake-display').textContent);
    const prize = parseInt(document.getElementById('waiting-prize-display').textContent);
    const text = encodeURIComponent(
        `🎮 Challenge me on Vumbua eFootball!\n\nMatch Code: ${code}\nWager: KES ${wager}\nWinner gets: KES ${prize}\n\nJoin here: https://vumbua.app`
    );
    window.open(`https://wa.me/?text=${text}`, '_blank');
}

function startFriendTimer(expiresAt) {
    if (friendMatchTimer) clearInterval(friendMatchTimer);
    friendMatchTimer = setInterval(() => {
        const now = new Date();
        const expires = new Date(expiresAt);
        const diff = Math.max(0, expires - now);
        const minutes = Math.floor(diff / 60000);
        const seconds = Math.floor((diff % 60000) / 1000);
        document.getElementById('friend-match-timer').textContent = 
            `Expires in ${minutes}:${seconds.toString().padStart(2, '0')}`;
        if (diff === 0) {
            clearInterval(friendMatchTimer);
            closeModal('waiting-friend-modal');
            showToast('info', 'Match Expired', 'No one joined in time. Your wager has been refunded.', 6000);
            refreshBalance();
            loadMyFriendMatches();
        }
    }, 1000);
}

async function loadMyFriendMatches() {
    try {
        const res = await fetchWithAuth('/friends/my-matches', {}, 8000);
        if (!res) return;
        const matches = await res.json();
        renderMyMatches(matches);
    } catch (e) {
        console.warn('loadMyFriendMatches failed:', e);
    }
}

function renderMyMatches(matches) {
    const container = document.getElementById('my-matches-list');
    container.innerHTML = '';

    if (!matches || matches.length === 0) {
        const emptyDiv = createElementSafe('div', { class: 'empty-state' });
        const iconDiv = createElementSafe('div', { class: 'empty-state-icon' }, '⚽');
        const textDiv = document.createElement('div');
        textDiv.className = 'empty-state-text';
        textDiv.textContent = 'No matches yet. Challenge a friend to win KES!';
        const ctaBtn = createElementSafe('button', { class: 'empty-state-cta' }, '⚔️ Create Challenge');
        ctaBtn.addEventListener('click', () => openCreateMatchModal());
        emptyDiv.appendChild(iconDiv);
        emptyDiv.appendChild(textDiv);
        emptyDiv.appendChild(ctaBtn);
        container.appendChild(emptyDiv);
        return;
    }

    const displayMatches = matches.slice(0, 3);
    if (matches.length > 3) {
        const moreEl = createElementSafe('div', { class: 'friend-info', style: 'text-align:center;font-size:0.75rem;margin-bottom:8px;' }, `Showing 3 of ${matches.length} matches`);
        container.appendChild(moreEl);
    }

    displayMatches.forEach(m => {
        const item = createElementSafe('div', { class: 'match-item' });
        const isCreator = m.creator_id === currentUser.id;
        const opponentName = isCreator
            ? (m.joiner?.username || 'Waiting...')
            : (m.creator?.username || 'Unknown');
        const opponentInitial = opponentName.charAt(0).toUpperCase();
        const myTeam   = isCreator ? (m.creator_team || 'My Team') : (m.joiner_team || 'My Team');
        const oppTeam  = isCreator ? (m.joiner_team  || 'Opponent') : (m.creator_team || 'Opponent');

        const headerDiv = createElementSafe('div', { class: 'match-header' });
        const codeDisplay = m.match_code ? m.match_code.replace('VUM-', '') : '—';
        headerDiv.appendChild(createElementSafe('span', { class: 'match-code' }, codeDisplay));

        const statusLabels = {
            pending:        'Waiting',
            active:         'Live',
            pending_review: 'Admin Review',
            disputed:       'Disputed',
            completed:      'Completed',
            cancelled:      'Cancelled',
        };
        const statusCssMap = {
            pending:        'status-pending',
            active:         'status-live',
            pending_review: 'status-pending',
            disputed:       'status-disputed',
            completed:      'status-closed',
            cancelled:      'status-closed',
        };
        const statusSpan = createElementSafe('span', { class: `match-status ${statusCssMap[m.status] || 'status-closed'}` }, statusLabels[m.status] || m.status);
        headerDiv.appendChild(statusSpan);
        item.appendChild(headerDiv);

        item.appendChild(createElementSafe('div', { class: 'match-detail' }, `KES ${m.wager_amount} wager · Prize KES ${m.winner_prize}`));

        if (m.status === 'pending' && isCreator) {
            const actionsDiv = createElementSafe('div', { class: 'match-actions' });
            const cancelBtn = createElementSafe('button', { class: 'btn btn-red' }, 'Cancel & Refund');
            cancelBtn.addEventListener('click', e => { e.stopPropagation(); cancelPendingMatch(m.id); });
            actionsDiv.appendChild(cancelBtn);
            item.appendChild(actionsDiv);
        } else if (m.status === 'active') {
            const userUploaded = isCreator ? !!m.creator_screenshot_url : !!m.joiner_screenshot_url;
            if (!userUploaded) {
                const uploadBtn = createElementSafe('button', { class: 'btn btn-green' }, '📸 Upload Screenshot');
                uploadBtn.addEventListener('click', e => { e.stopPropagation(); openReportResultModal(m.id); });
                item.appendChild(uploadBtn);
            } else {
                const pendingMsg = createElementSafe('div', { style: 'font-size:0.8rem;color:#ffb400;padding:8px 0;' }, '⏳ Screenshot submitted – waiting for admin review');
                item.appendChild(pendingMsg);
            }
        } else if (m.status === 'pending_review') {
            const reviewMsg = createElementSafe('div', { style: 'font-size:0.8rem;color:#ffb400;padding:8px 0;' }, '⏳ Admin is reviewing your screenshot');
            item.appendChild(reviewMsg);
        } else if (m.status === 'disputed') {
            item.appendChild(createElementSafe('div', { style: 'font-size:0.8rem;color:#ff8888;padding:10px 0;' }, '⚖️ Disputed – an admin is reviewing.'));
        } else if (m.status === 'completed') {
            const youWon = m.winner_id === currentUser.id;
            const resultDiv = createElementSafe('div', { style: `font-size:0.9rem;font-weight:700;color:${youWon ? '#00ff41' : '#ff6666'};padding:8px 0;` }, youWon ? '🏆 You won!' : '😔 You lost');
            item.appendChild(resultDiv);
        }

        container.appendChild(item);
    });
}

async function cancelPendingMatch(matchId) {
    if (!confirm('Cancel this pending match? Your wager will be refunded.')) return;
    try {
        const res = await fetchWithAuth('/friends/cancel-match', {
            method: 'POST',
            body: JSON.stringify({ matchId })
        }, 10000);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        await refreshBalance(3);
        await loadMyFriendMatches();
    } catch (err) {
        console.error('❌ Error cancelling pending match:', err);
        alert(err.message);
        await refreshBalance(3);
    }
}

function showToast(type, title, msg, duration = 4000) {
    const toast = document.getElementById('global-toast');
    const iconEl = document.getElementById('toast-icon');
    const titleEl = document.getElementById('toast-title');
    const msgEl = document.getElementById('toast-msg');
    const icons = { success: '✅', error: '❌', info: '⏳' };
    toast.className = `modal-toast ${type}`;
    iconEl.textContent = icons[type] || '💬';
    titleEl.textContent = title;
    msgEl.textContent = msg || '';
    void toast.offsetWidth;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), duration);
}

// --- Simplified upload handler ---
async function handleScreenshotSelected(file) {
    if (!file || !currentReportMatch) return;
    if (!['image/jpeg','image/png','image/webp'].includes(file.type)) {
        showError('declare-error-2', 'Please upload a JPEG, PNG or WebP image.');
        return;
    }
    if (file.size > 10*1024*1024) {
        showError('declare-error-2', 'File too large. Max 10MB.');
        return;
    }

    const thumb = document.getElementById('screenshot-thumb');
    const icon = document.getElementById('upload-icon');
    const label = document.getElementById('upload-label');
    const progress = document.getElementById('upload-progress');
    const progressFill = document.getElementById('upload-progress-fill');

    if (thumb) {
        thumb.src = URL.createObjectURL(file);
        thumb.classList.add('visible');
    }
    if (icon) icon.textContent = '⏳';
    if (label) { label.textContent = ''; const s = document.createElement('strong'); s.textContent = 'Uploading...'; label.appendChild(s); }
    if (progress) progress.classList.add('visible');
    if (progressFill) progressFill.classList.add('indeterminate');

    const formData = new FormData();
    formData.append('screenshot', file);
    formData.append('matchId', currentReportMatch.id);

    try {
        const res = await fetchWithAuth('/friends/submit-screenshot', {
            method: 'POST',
            body: formData
        }, 30000);

        if (progress) progress.classList.remove('visible');
        if (progressFill) progressFill.classList.remove('indeterminate');

        const data = await res.json();

        if (!res.ok) throw new Error(data.error || 'Upload failed');

        if (icon) icon.textContent = '✅';
        if (label) {
            label.textContent = '';
            const s = document.createElement('strong'); s.textContent = 'Screenshot submitted for admin review'; label.appendChild(s);
            label.appendChild(document.createElement('br'));
            const sm = document.createElement('span'); sm.style.cssText = 'font-size:0.75rem;color:#aaa;'; sm.textContent = 'An admin will settle the match shortly.'; label.appendChild(sm);
        }

        setTimeout(() => {
            closeModal('report-result-modal');
            loadMyFriendMatches();
            showToast('info', '📸 Screenshot Received', 'Admin will review and settle the match.', 5000);
        }, 2000);

    } catch (err) {
        if (progress) progress.classList.remove('visible');
        if (progressFill) progressFill.classList.remove('indeterminate');
        if (icon) icon.textContent = '❌';
        if (label) {
            label.textContent = '';
            const s = document.createElement('strong'); s.style.color = '#ff4455'; s.textContent = '❌ Upload failed'; label.appendChild(s);
            label.appendChild(document.createElement('br'));
            const sm = document.createElement('span'); sm.style.cssText = 'font-size:0.75rem;color:#aaa;'; sm.textContent = err.message; label.appendChild(sm);
        }
        showError('declare-error-2', err.message);
    }
}

function openReportResultModal(matchId) {
    fetchWithAuth('/friends/my-matches', {}, 8000).then(async res => {
        const matches = await res.json();
        const match = matches.find(m => m.id === matchId);
        if (!match) { showToast('error', 'Match Not Found', 'Could not load match details.', 4000); return; }
        currentReportMatch = match;

        const thumb = document.getElementById('screenshot-thumb');
        const icon = document.getElementById('upload-icon');
        const label = document.getElementById('upload-label');
        const progress = document.getElementById('upload-progress');
        const error = document.getElementById('declare-error-2');
        if (thumb) { thumb.classList.remove('visible'); thumb.src = ''; }
        if (icon) icon.textContent = '📲';
        if (label) {
            label.textContent = '';
            const s = document.createElement('strong'); s.textContent = 'Tap to upload screenshot'; label.appendChild(s);
            label.appendChild(document.createElement('br'));
            const sm = document.createElement('span'); sm.style.cssText = 'font-size:0.78rem;color:#555;'; sm.textContent = 'Take it directly from eFootball'; label.appendChild(sm);
        }
        if (progress) progress.classList.remove('visible');
        if (error) error.style.display = 'none';

        document.querySelectorAll('#report-match-details-mini').forEach(el => {
            el.textContent = '';
            const rows = [
                ['Wager', `KES ${match.wager_amount}`, ''],
                ['Winner prize', `KES ${match.winner_prize}`, 'neon'],
                ['Your team', match.creator_team || '—', 'color:#ccc;'],
                ['Opponent', match.joiner_team || '—', 'color:#ccc;'],
            ];
            rows.forEach(([label, value, style]) => {
                const row = document.createElement('div'); row.className = 'match-detail-row';
                const lbl = document.createElement('span'); lbl.className = 'match-detail-label'; lbl.textContent = label;
                const val = document.createElement('span'); val.className = `match-detail-value${style === 'neon' ? ' neon' : ''}`; if (style && style !== 'neon') val.style.cssText = style; val.textContent = value;
                row.appendChild(lbl); row.appendChild(val); el.appendChild(row);
            });
        });

        switchStep('report-result-modal', 1);
        document.getElementById('report-result-modal').classList.add('open');
    });
}

function switchStep(modalId, stepNum) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    const steps = modal.querySelectorAll('.step');
    if (steps[stepNum - 1]) steps[stepNum - 1].classList.add('active');
}

function resetReportModal() {
    const thumb = document.getElementById('screenshot-thumb');
    const icon = document.getElementById('upload-icon');
    const label = document.getElementById('upload-label');
    const progress = document.getElementById('upload-progress');
    const error = document.getElementById('declare-error-2');
    if (thumb) { thumb.classList.remove('visible'); thumb.src = ''; }
    if (icon) icon.textContent = '📲';
    if (label) {
        label.textContent = '';
        const s = document.createElement('strong'); s.textContent = 'Tap to upload screenshot'; label.appendChild(s);
        label.appendChild(document.createElement('br'));
        const sm = document.createElement('span'); sm.style.cssText = 'font-size:0.78rem;color:#555;'; sm.textContent = 'Take it directly from eFootball'; label.appendChild(sm);
    }
    if (progress) progress.classList.remove('visible');
    if (error) error.style.display = 'none';
}

function startMatchStatusPolling(matchId) {
    if (matchStatusPollInterval) {
        clearInterval(matchStatusPollInterval);
    }
    matchStatusPollInterval = setInterval(async () => {
        try {
            const res = await fetchWithAuth(`/friends/match-status/${matchId}`, {}, 5000);
            if (!res || !res.ok) return;
            const data = await res.json();
            if (data.status === 'active') {
                stopMatchStatusPolling();
                onMatchBecameActive(data);
            } else if (data.status === 'expired' || data.status === 'cancelled') {
                stopMatchStatusPolling();
                onMatchExpiredOrCancelled(data);
            }
        } catch (err) {
            console.error('Poll error:', err);
        }
    }, 3000);
}

function stopMatchStatusPolling() {
    if (matchStatusPollInterval) {
        clearInterval(matchStatusPollInterval);
        matchStatusPollInterval = null;
    }
}

function onMatchBecameActive(matchData) {
    if (friendMatchTimer) {
        clearInterval(friendMatchTimer);
        friendMatchTimer = null;
    }
    closeModal('waiting-friend-modal');
    openWarRoom({
        matchId:         currentFriendMatch?.matchId || matchData.matchId,
        matchCode:       currentFriendMatch?.matchCode || matchData.matchCode,
        creatorTeam:     currentTeam,
        creatorUsername: currentUsername,
        joinerTeam:      matchData.joinerTeam    || matchData.joinerUsername || 'Opponent FC',
        joinerUsername:  matchData.joinerUsername || 'Opponent',
        wagerAmount:     matchData.wagerAmount    || currentFriendMatch?.wagerAmount,
        winnerPrize:     matchData.winnerPrize,
        startedAt:       new Date().toISOString(),
        currentUserId:   currentUser.id,
        creatorId:       currentUser.id
    });
}

function onMatchExpiredOrCancelled(matchData) {
    if (friendMatchTimer) {
        clearInterval(friendMatchTimer);
        friendMatchTimer = null;
    }
    closeModal('waiting-friend-modal');
    if (matchData.status === 'expired') {
        showToast('info', '⏰ Match Expired', 'No one joined in time. Your wager has been refunded.', 6000);
    } else {
        showToast('info', '❌ Match Cancelled', 'Your wager has been refunded.', 5000);
    }
    refreshBalance();
    loadMyFriendMatches();
}

function shareRoomCode() {
    const code = document.getElementById('room-code-display').innerText;
    const text = encodeURIComponent(`Join my match on Vumbua eFootball! Room code: ${code}. Play here: https://vumbua.app`);
    window.open(`https://wa.me/?text=${text}`, '_blank');
}

function openProfileModal() {
    document.getElementById('profile-username').value = escapeHtml(currentUsername);
    document.getElementById('profile-team').value = escapeHtml(currentTeam);
    document.getElementById('profile-error').style.display = 'none';
    document.getElementById('profile-modal').classList.add('open');
}

document.getElementById('logoutBtn').addEventListener('click', () => {
    stopBalanceAutoRefresh();
    stopMatchStatusPolling();
    if (supabaseRealtime && realtimeChannel) {
        supabaseRealtime.removeChannel(realtimeChannel);
        realtimeChannel = null;
    }
    if (matchesRefreshInterval) {
        clearInterval(matchesRefreshInterval);
        matchesRefreshInterval = null;
    }
    currentBalance = 0;
    currentUser = null;
    currentUsername = '';
    currentPhone = '';
    currentTeam = '';
    authToken = null;
    currentCheckoutId = null;
    currentFriendMatch = null;
    currentTournamentId = null;
    currentTournamentFee = 0;
    currentTournamentName = '';
    supabaseRealtime = null;
    sessionStorage.removeItem('supabaseToken');
    sessionStorage.removeItem('supabaseUser');
    window.location.href = '/login';
});

function openWarRoom(data) {
    sessionStorage.setItem('warRoomData', JSON.stringify(data));
    window.location.href = '/war-room';
}

window.onload = () => {
    if (!authToken) { window.location.href = '/login'; return; }
    loadDashboard().then(() => {
        const reportId = sessionStorage.getItem('openReportMatchId');
        if (reportId) {
            sessionStorage.removeItem('openReportMatchId');
            sessionStorage.removeItem('warRoomData');
            setTimeout(() => openReportResultModal(reportId), 600);
        }
    });
};

window.addEventListener('beforeunload', () => {
    if (pollInterval)            { clearInterval(pollInterval);            pollInterval = null; }
    if (friendMatchTimer)        { clearInterval(friendMatchTimer);        friendMatchTimer = null; }
    if (matchStatusPollInterval) { clearInterval(matchStatusPollInterval); matchStatusPollInterval = null; }
    if (balanceRefreshInterval)  { clearInterval(balanceRefreshInterval);  balanceRefreshInterval = null; }
    if (matchesRefreshInterval)  { clearInterval(matchesRefreshInterval);  matchesRefreshInterval = null; }
    if (supabaseRealtime && realtimeChannel) {
        supabaseRealtime.removeChannel(realtimeChannel);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const wire = (id, fn) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', fn);
    };

    wire('nav-user-btn',               () => openProfileModal());
    wire('btn-open-deposit',           () => openDepositModal());
    wire('btn-open-withdraw',          () => openWithdrawModal());
    wire('btn-load-tournaments',       () => loadTournaments());
    wire('btn-open-create-match',      () => openCreateMatchModal());
    wire('btn-open-join-match',        () => openJoinMatchModal());
    wire('btn-refresh-friend-matches', () => loadMyFriendMatches());
    wire('btn-save-profile',           () => saveProfile());
    wire('btn-close-profile',          () => closeModal('profile-modal'));
    wire('btn-process-deposit',        () => processDeposit());
    wire('btn-process-withdraw',       () => processWithdraw());
    wire('btn-challenge-wallet',       () => confirmChallenge('wallet'));
    wire('btn-challenge-mpesa',        () => confirmChallenge('mpesa'));
    wire('btn-share-room',             () => shareRoomCode());
    wire('btn-share-friend-code',      () => shareFriendCode());
    wire('btn-cancel-friend-match',    () => cancelFriendMatch());
    wire('btn-back-from-waiting',      () => closeModal('waiting-friend-modal'));
    wire('create-friend-btn',          () => createFriendMatch());
    wire('btn-join-friend-match',      () => joinFriendMatch());
    wire('btn-back-to-dashboard',      () => closeModal('report-result-modal'));

    const quickCard = document.getElementById('quick-card-friend');
    if (quickCard) quickCard.addEventListener('click', () =>
        document.querySelector('.friend-section')?.scrollIntoView({ behavior: 'smooth' }));

    ['profile-modal','deposit-modal','withdraw-modal','challenge-modal',
     'room-modal','create-friend-modal','join-friend-modal','report-result-modal',
     'waiting-friend-modal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', e => { if (e.target === el) closeModal(id); });
    });

    document.querySelectorAll('[data-close-modal]').forEach(btn =>
        btn.addEventListener('click', () => closeModal(btn.dataset.closeModal)));

    document.querySelectorAll('#deposit-modal .preset-btn').forEach(btn => {
        const amt = parseInt(btn.textContent.trim(), 10);
        if (!isNaN(amt)) btn.addEventListener('click', () => selectPreset(btn, amt));
    });

    document.querySelectorAll('#create-friend-modal .preset-btn').forEach(btn => {
        const amt = parseInt(btn.textContent.trim(), 10);
        if (!isNaN(amt)) btn.addEventListener('click', () => selectFriendPreset(btn, amt));
    });

    const wagerInput = document.getElementById('friend-wager-input');
    if (wagerInput) wagerInput.addEventListener('input', () => updateFriendBreakdown());

    const screenshotInput = document.getElementById('screenshot-file-input');
    if (screenshotInput) screenshotInput.addEventListener('change', e => handleScreenshotSelected(e.target.files[0]));
});