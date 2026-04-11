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

// Auto-detect: Use localhost for local dev, Koyeb URL for production
const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const API = isLocal ? 'http://localhost:3000' : '/api';

console.log('🔍 Environment:', isLocal ? 'LOCAL' : 'PRODUCTION');
console.log('🔍 API URL:', API);

// Redirect if already logged in
if (localStorage.getItem('supabaseToken')) {
    window.location.href = '/dashboard';
}

const form = document.getElementById('signup-form');
const errorEl = document.getElementById('error-msg');
const btn = document.getElementById('submit-btn');

function showError(msg) { 
    errorEl.textContent = escapeHtml(msg); 
    errorEl.style.display = 'block'; 
    errorEl.classList.remove('shake');
    void errorEl.offsetWidth; // trigger reflow
    errorEl.classList.add('shake');
}

function hideError() { 
    errorEl.style.display = 'none'; 
    errorEl.classList.remove('shake');
}

form.addEventListener('submit', async (e) => {
    e.preventDefault(); 
    hideError();

    const rawPhone = document.getElementById('phone').value;
    const username = document.getElementById('username').value.trim();
    const teamName = document.getElementById('team').value.trim();
    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm-password').value;

    if (password !== confirm) return showError("Passwords do not match. Please try again.");
    if (password.length < 6) return showError("Password must be at least 6 characters.");
    if (!teamName) return showError("DLS Club name is required.");
    if (teamName.length < 3) return showError("DLS Club name must be at least 3 characters.");

    // Phone formatting
    let cleanPhone = rawPhone.replace(/\s+/g, '');
    if (cleanPhone.startsWith('+')) cleanPhone = cleanPhone.substring(1);
    if (cleanPhone.startsWith('0')) {
        cleanPhone = '254' + cleanPhone.substring(1);
    } else if (cleanPhone.startsWith('7') || cleanPhone.startsWith('1')) {
        cleanPhone = '254' + cleanPhone;
    }
    if (!/^254[17]\d{8}$/.test(cleanPhone)) {
        return showError("Invalid phone number. Use format: 0712 345 678");
    }
    cleanPhone = '+' + cleanPhone;

    btn.disabled = true; 
    btn.textContent = 'Loading...';

    try {
        const res = await fetch(`${API}/auth/signup`, {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                phone: cleanPhone, 
                password, 
                username,
                teamName
            })
        });

        const result = await res.json();

        if (res.ok) {
            if (result.session) {
                localStorage.setItem('supabaseToken', result.session.access_token);
                localStorage.setItem('supabaseUser', JSON.stringify(result.session.user));
                window.location.href = '/dashboard';
            } else {
                window.location.href = '/login';
            }
        } else { 
            showError(result.error || 'Something went wrong. Please try again.'); 
        }
    } catch (err) { 
        showError('Network error. Please check your internet connection.'); 
    } finally { 
        btn.disabled = false; 
        btn.textContent = 'Create DLS Account →'; 
    }
});