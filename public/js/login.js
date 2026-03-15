'use strict';

function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Auto-detect environment
const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const API = isLocal ? 'http://localhost:3000' : '/api';

console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
console.log('🔍 API URL:', API);

// Redirect if already logged in
if (localStorage.getItem('supabaseToken')) {
    window.location.href = '/dashboard';
}

const errorEl = document.getElementById('error-msg');
const btn     = document.getElementById('submit-btn');

function showError(msg) {
    errorEl.textContent = escapeHtml(msg);
    errorEl.style.display = 'block';
    errorEl.classList.remove('shake');
    void errorEl.offsetWidth; // force reflow to restart animation
    errorEl.classList.add('shake');
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.style.display = 'none';

    const phone    = document.getElementById('login-phone').value.trim();
    const password = document.getElementById('login-password').value;

    // Normalise phone to +254XXXXXXXXX
    let cleanPhone = phone.replace(/\s+/g, '');
    if (cleanPhone.startsWith('+')) cleanPhone = cleanPhone.substring(1);
    if (cleanPhone.startsWith('0')) {
        cleanPhone = '254' + cleanPhone.substring(1);
    } else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) {
        cleanPhone = '254' + cleanPhone;
    }
    if (!/^254[17]\d{8}$/.test(cleanPhone)) {
        return showError('Namba ya simu si sahihi.');
    }
    cleanPhone = '+' + cleanPhone;

    btn.disabled    = true;
    btn.textContent = 'Inaload...';

    try {
        const res = await fetch(`${API}/auth/login`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ phone: cleanPhone, password }),
        });

        const result = await res.json();

        if (res.ok) {
            localStorage.setItem('supabaseToken', result.session.access_token);
            localStorage.setItem('supabaseUser',  JSON.stringify(result.session.user));
            window.location.href = '/dashboard';
        } else {
            showError(result.error || 'Namba ya simu au password si sahihi.');
        }
    } catch {
        showError('Network error. Check connection yako.');
    } finally {
        btn.disabled    = false;
        btn.textContent = 'Enter Uwanja →';
    }
});