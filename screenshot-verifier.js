/**
 * SCREENSHOT VERIFIER v7 — Gemini Vision
 * ─────────────────────────────────────────────────────────────────────────────
 * Score extraction is now a single Gemini Vision API call.
 * No Tesseract, no color segmentation, no preprocessing variants.
 *
 * Gemini receives the raw screenshot and returns structured JSON:
 *   { score1, score2, homeTeam, awayTeam, hasFullTime, confidence }
 *
 * All fraud checks (duplicate hash, EXIF, manipulation, etc.) are unchanged.
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const sharp = require('sharp');

const DEBUG = process.env.DEBUG_OCR === 'true';
function log(...a) { if (DEBUG) console.log('[OCR-v7]', ...a); }

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL   = 'gemini-2.5-flash';
const GEMINI_URL     = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

// ── Gemini rate-limit queue ───────────────────────────────────────────────────
// Free tier: 15 req/min. We serialize all Gemini calls through this queue and
// enforce a minimum 5s gap between requests (= max 12/min, safely under limit).
// If multiple uploads arrive simultaneously they wait their turn rather than
// all firing at once and burning through the per-minute quota.
const GEMINI_MIN_GAP_MS = 13000; // 13s between calls → max ~4.6/min, safely under 5 RPM free limit
let _geminiLastCall = 0;
let _geminiQueue = Promise.resolve();

function queuedGeminiFetch(body) {
    _geminiQueue = _geminiQueue.then(async () => {
        const now = Date.now();
        const wait = GEMINI_MIN_GAP_MS - (now - _geminiLastCall);
        if (wait > 0) {
            console.log(`⏱️  [OCR-v7] Rate-limit gap: waiting ${wait}ms before Gemini call`);
            await new Promise(r => setTimeout(r, wait));
        }
        _geminiLastCall = Date.now();
        return fetch(GEMINI_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(25000),
        });
    });
    return _geminiQueue;
}

const USER_MESSAGES = {
    fileIntegrity:    'The file appears corrupt or is not a valid image. Please take a fresh screenshot and try again.',
    duplicate:        'This screenshot has already been used in a previous match. Please upload the actual result from this match.',
    exifTimestamp:    'Screenshot metadata shows it was taken BEFORE this match started. Please upload the correct end-of-match result screen.',
    tooEarly:         'The match just started — it cannot have finished yet. Upload the result screenshot after you finish playing.',
    manipulation:     'Our system detected possible image editing or tampering. If genuine, contact admin with the original file.',
    ocrSanity:        'Could not read the score from the screenshot. Please upload the final "Full Time" result screen from eFootball.',
    scoreSanity:      'The score detected looks unusual. Please upload the correct end-of-match result screen.',
    statsConsistency: "Match statistics don't match the score. This screenshot may be from a different match.",
    teamNameMatch:    "Team names in the screenshot don't match the teams registered for this match.",
    fullTimeWord:     'Screenshot is missing the "Full Time" text. Please upload the actual end-of-match summary screen.',
    aspectRatio:      'Image dimensions are unusual for a game screenshot. Please screenshot the eFootball result screen directly.',
    matchContext:     "Neither player's username was found in the screenshot. Make sure you upload the result from THIS match.",
    usernameMatch:    "Player usernames in the screenshot don't match this match's players. Please upload the correct result screen.",
    scorePlausibility:'The score looks unusually extreme. This match has been flagged for admin confirmation.',
};

// ─── Gemini Vision score extraction ──────────────────────────────────────────

const GEMINI_PROMPT = `You are analyzing an eFootball (Konami) mobile/console match result screenshot.

The final score appears at the TOP of the screen in a banner:
- Left side: home team name + their score in a YELLOW BOX (e.g. "1")
- Center: the eFootball ⊖ logo (this is NOT a digit, ignore it)
- Right side: away score in a YELLOW BOX (e.g. "6") + away team name

Below the score banner there is usually "Full Time" text.
Below that may be player usernames/gamertags (NOT team names — these are the PSN/Xbox/mobile account names of the two players).
Below that is a stats table with rows like Shots, Passes, Fouls, etc. — IGNORE all numbers in the stats table.

Extract ONLY the two numbers in the yellow score boxes, the team names, and any visible player usernames.

Respond with ONLY valid JSON — no markdown fences, no extra text:
{
  "score1": <home score as integer, e.g. 1>,
  "score2": <away score as integer, e.g. 6>,
  "homeTeam": "<home team name exactly as shown>",
  "awayTeam": "<away team name exactly as shown>",
  "homeUsername": "<home player's username/gamertag if visible, else null>",
  "awayUsername": "<away player's username/gamertag if visible, else null>",
  "hasFullTime": <true or false>,
  "confidence": <integer 50-100 — always provide a number, never null>
}

Rules:
- score1 and score2 MUST be integers between 0 and 20
- confidence must always be an integer — use 50 if unsure, never null or omit it
- If you truly cannot find any score at all, set score1 and score2 to null
- NEVER read from the stats rows — only the top score banner
- The ⊖ symbol is the game logo, NOT a minus sign or digit
- homeUsername and awayUsername are the player account names, NOT team names`;

async function extractScoreWithGemini(imageBuffer) {
    if (!GEMINI_API_KEY) {
        console.error('❌ [OCR-v7] GEMINI_API_KEY not set in environment');
        return null;
    }

    // Resize to max 1280px wide to stay well under Gemini's size limits
    const resized = await sharp(imageBuffer)
        .resize(1280, null, { fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 90 })
        .toBuffer();

    const base64 = resized.toString('base64');

    const body = {
        contents: [{
            parts: [
                { text: GEMINI_PROMPT },
                { inline_data: { mime_type: 'image/jpeg', data: base64 } },
            ]
        }],
        generationConfig: {
            temperature: 0,       // deterministic
            maxOutputTokens: 512,  // enough for the JSON response
        }
    };

    // Use the serialized queue — enforces 5s minimum gap between calls
    // so concurrent uploads don't collide and burn the per-minute quota.
    let res = await queuedGeminiFetch(body);

    // Single retry if still 429 (e.g. burst from previous session)
    if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('Retry-After') || '0', 10);
        const waitMs = retryAfter > 0 ? retryAfter * 1000 : 65000;
        console.warn(`⏳ [OCR-v7] Gemini 429 — waiting ${waitMs / 1000}s then retrying once...`);
        await new Promise(r => setTimeout(r, waitMs));
        _geminiLastCall = 0; // reset gap tracker after long wait
        res = await queuedGeminiFetch(body);
        if (res.status === 429) {
            console.warn('⏳ [OCR-v7] Gemini still 429 — quota exhausted. Failing gracefully.');
            return null;
        }
    }

    if (!res.ok) {
        const errText = await res.text().catch(() => '');
        console.error(`❌ [OCR-v7] Gemini API error ${res.status}:`, errText.slice(0, 300));
        return null;
    }

    const data = await res.json();
    const raw  = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    log('Gemini raw response:', raw);

    // Strip any accidental markdown fences
    const clean = raw.replace(/```json|```/gi, '').trim();

    try {
        const parsed = JSON.parse(clean);
        const s1 = parsed.score1, s2 = parsed.score2;

        if (s1 === null || s1 === undefined || s2 === null || s2 === undefined) {
            log('Gemini returned null scores');
            return null;
        }

        const score1 = parseInt(s1, 10), score2 = parseInt(s2, 10);
        if (isNaN(score1) || isNaN(score2) || score1 < 0 || score1 > 20 || score2 < 0 || score2 > 20) {
            log('Gemini returned out-of-range scores:', s1, s2);
            return null;
        }

        return {
            score1,
            score2,
            homeTeam:     parsed.homeTeam     || null,
            awayTeam:     parsed.awayTeam     || null,
            homeUsername: parsed.homeUsername || null,
            awayUsername: parsed.awayUsername || null,
            hasFullTime:  parsed.hasFullTime   === true,
            confidence:   Math.min(100, Math.max(0, parseInt(parsed.confidence, 10) || 0)),
        };
    } catch (e) {
        console.error('❌ [OCR-v7] Failed to parse Gemini JSON:', e.message, '| raw:', raw.slice(0, 300));
        return null;
    }
}

// ─── Fraud detection helpers ──────────────────────────────────────────────────

async function pHash(buf) {
    try {
        const px  = await sharp(buf).resize(8, 8, { fit: 'fill' }).grayscale().raw().toBuffer();
        const avg = px.reduce((s, v) => s + v, 0) / px.length;
        return Array.from(px).map(v => v >= avg ? '1' : '0').join('');
    } catch { return null; }
}

function hammingDistance(a, b) {
    if (!a || !b || a.length !== b.length) return Infinity;
    let d = 0;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) d++;
    return d;
}

async function detectManipulation(buf) {
    try {
        const { data: raw, info } = await sharp(buf)
            .resize(400, 225, { fit: 'inside' }).grayscale().raw()
            .toBuffer({ resolveWithObject: true });
        const BS = 8, ents = [];
        for (let y = 0; y < info.height - BS; y += BS)
            for (let x = 0; x < info.width - BS; x += BS) {
                const hist = new Array(256).fill(0);
                for (let dy = 0; dy < BS; dy++)
                    for (let dx = 0; dx < BS; dx++)
                        hist[raw[(y + dy) * info.width + (x + dx)]]++;
                let e = 0;
                for (const c of hist) if (c > 0) { const p = c / (BS * BS); e -= p * Math.log2(p); }
                ents.push(e);
            }
        if (!ents.length) return { suspicious: false };
        const mean = ents.reduce((s, v) => s + v, 0) / ents.length;
        const std  = Math.sqrt(ents.reduce((s, v) => s + (v - mean) ** 2, 0) / ents.length);
        return { suspicious: std > 2.8, stdDev: +std.toFixed(3), mean: +mean.toFixed(3) };
    } catch (e) { return { suspicious: false, error: e.message }; }
}

function fuzzyTeamMatch(a, b) {
    if (!a || !b) return false;
    // Normalize: lowercase, remove common suffixes, strip non-alphanumeric
    const norm = s => s.toLowerCase()
        .replace(/\b(fc|cf|sc|ac|af|bc|united|city|town|club|football)\b/g, '')
        .replace(/[^a-z0-9\s]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    const strip = s => s.toLowerCase().replace(/[^a-z0-9]/g, '');

    const na = norm(a), nb = norm(b);
    const sa = strip(a), sb = strip(b);

    // Exact match after normalization
    if (na === nb) return true;
    // Stripped exact match (handles "Arsenal FC" vs "Arsenal")
    if (sa === sb) return true;
    // One contains the other (handles "Arsenal FC" matching "Arsenal")
    if (sa.includes(sb) || sb.includes(sa)) return true;
    // First 5 chars of stripped match
    if (sa.length >= 5 && sb.length >= 5 && (sa.startsWith(sb.slice(0, 5)) || sb.startsWith(sa.slice(0, 5)))) return true;
    // Word overlap — for multi-word custom names like "this team vere level"
    // At least 60% of words from the shorter name appear in the longer name
    const wordsA = na.split(' ').filter(w => w.length > 2);
    const wordsB = nb.split(' ').filter(w => w.length > 2);
    if (wordsA.length > 0 && wordsB.length > 0) {
        const [sh, lo] = wordsA.length <= wordsB.length ? [wordsA, wordsB] : [wordsB, wordsA];
        const loStr = lo.join(' ');
        const overlap = sh.filter(w => loStr.includes(w)).length;
        if (overlap / sh.length >= 0.6) return true;
    }
    // Character overlap fallback — only for short names (abbreviations)
    const shS = sa.length < sb.length ? sa : sb;
    const loS = sa.length < sb.length ? sb : sa;
    if (shS.length <= 8 && loS.length <= 12) {
        return (Array.from(shS).filter(ch => loS.includes(ch)).length / Math.max(shS.length, 1)) >= 0.65;
    }
    return false;
}

function determineWinner(sd, md) {
    if (sd.score1 == null || sd.score2 == null) return { winner: null, reason: 'no_score' };
    const ct = (md.creatorTeam || '').toLowerCase(), jt = (md.joinerTeam || '').toLowerCase();
    const h  = (sd.homeTeam   || '').toLowerCase(), aw = (sd.awayTeam  || '').toLowerCase();
    let cih = null; // is creator playing as home?

    // Primary: match by team name
    if (ct) { if (fuzzyTeamMatch(h, ct)) cih = true;  else if (fuzzyTeamMatch(aw, ct)) cih = false; }
    if (cih === null && jt) { if (fuzzyTeamMatch(h, jt)) cih = false; else if (fuzzyTeamMatch(aw, jt)) cih = true; }

    // Secondary fallback: match by username (if Gemini read them from the screenshot)
    if (cih === null && (sd.homeUsername || sd.awayUsername)) {
        const cu = (md.uploaderUsername || md.creatorUsername || '').toLowerCase();
        const ju = (md.opponentUsername  || md.joinerUsername  || '').toLowerCase();
        const hu = (sd.homeUsername || '').toLowerCase();
        const au = (sd.awayUsername || '').toLowerCase();
        const usernameHit = (name, extracted) => name.length >= 4 && extracted.length >= 4 &&
            (extracted.includes(name.slice(0, 5)) || name.includes(extracted.slice(0, 5)));
        if (cu && usernameHit(cu, hu)) cih = true;
        else if (cu && usernameHit(cu, au)) cih = false;
        else if (ju && usernameHit(ju, hu)) cih = false;
        else if (ju && usernameHit(ju, au)) cih = true;
    }

    if (cih === null) return { winner: null, score1: sd.score1, score2: sd.score2, reason: 'team_side_unknown' };
    const cs = cih ? sd.score1 : sd.score2, js = cih ? sd.score2 : sd.score1;
    if (cs > js) return { winner: 'creator', creatorScore: cs, joinerScore: js, score1: sd.score1, score2: sd.score2 };
    if (js > cs) return { winner: 'joiner',  creatorScore: cs, joinerScore: js, score1: sd.score1, score2: sd.score2 };
    return { winner: 'draw', creatorScore: cs, joinerScore: js, score1: sd.score1, score2: sd.score2 };
}

function parseExifDate(b) {
    try {
        const m = b.toString('binary').match(/(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
        return m ? new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`) : null;
    } catch { return null; }
}

// ─── Main verifier class ──────────────────────────────────────────────────────

class ScreenshotVerifier {
    constructor(supabase, teamConfig = {}) {
        this.supabase = supabase;
        this.teams = teamConfig.teams || [];
        this.extractTeamNames = teamConfig.extractTeamNames || (() => ({ home: null, away: null }));
    }

    async verifyScreenshot(imageBuffer, matchData = {}) {
        const t0 = Date.now(), warnings = [], checks = {};
        let fraudScore = 0;

        const fail = (name, pts, det = {}) => {
            checks[name] = { passed: false, details: det, warning: USER_MESSAGES[name] || 'Suspicious.' };
            warnings.push(USER_MESSAGES[name] || name);
            fraudScore += pts;
            log(`❌ ${name} +${pts} → ${fraudScore}`);
        };
        const pass = (name, det = {}) => {
            checks[name] = { passed: true, details: det };
            log(`✅ ${name}`);
        };

        // 1. File integrity
        let imgMeta;
        try {
            imgMeta = await sharp(imageBuffer).metadata();
            if (!imgMeta.width || !imgMeta.height) throw new Error('No dimensions');
            pass('fileIntegrity', { width: imgMeta.width, height: imgMeta.height, format: imgMeta.format });
        } catch (e) {
            fail('fileIntegrity', 100, { error: e.message });
            return this._build({ checks, warnings, fraudScore: 100, geminiResult: null, elapsed: Date.now() - t0 });
        }

        // 2. Aspect ratio
        const ratio = imgMeta.width / imgMeta.height;
        ratio < 1.3
            ? fail('aspectRatio', 20, { ratio: +ratio.toFixed(2) })
            : pass('aspectRatio', { ratio: +ratio.toFixed(2) });

        // 3. Duplicate hash
        const hash = await pHash(imageBuffer);
        if (hash && this.supabase) {
            try {
                const { data: rows } = await this.supabase.from('screenshot_hashes').select('match_id,hash').limit(2000);
                const dup = (rows || []).find(r => r.hash && hammingDistance(hash, r.hash) <= 8 && r.match_id !== matchData.matchId);
                dup ? fail('duplicate', 80, { originalMatch: dup.match_id, hash }) : pass('duplicate', { hash });
            } catch { pass('duplicate', { hash, dbError: true }); }
        } else { pass('duplicate', { hash }); }

        // 4. EXIF timestamp
        const exifDate    = imgMeta.exif ? parseExifDate(imgMeta.exif) : null;
        const matchStarted = matchData.startedAt ? new Date(matchData.startedAt) : null;
        if (exifDate && matchStarted) {
            const diff = (exifDate - matchStarted) / 60000;
            diff < -5
                ? fail('exifTimestamp', 70, { diff: +diff.toFixed(1) })
                : pass('exifTimestamp', { diff: +diff.toFixed(1) });
        } else { pass('exifTimestamp', { note: 'skipped' }); }

        // 5. Too early
        if (matchStarted) {
            const age = (Date.now() - matchStarted.getTime()) / 1000;
            age < 60
                ? fail('tooEarly', 60, { ageSeconds: Math.round(age) })
                : pass('tooEarly', { ageSeconds: Math.round(age) });
        } else { pass('tooEarly', { note: 'skipped' }); }

        // 6. Manipulation detection
        const manip = await detectManipulation(imageBuffer);
        manip.suspicious ? fail('manipulation', 40, manip) : pass('manipulation', manip);

        // 7. Gemini Vision — extract score, teams, Full Time
        let geminiResult = null;
        try {
            geminiResult = await extractScoreWithGemini(imageBuffer);
            log('Gemini result:', JSON.stringify(geminiResult));
        } catch (e) {
            console.error('❌ [OCR-v7] Gemini call failed:', e.message);
        }

        const scoreFound  = geminiResult && geminiResult.score1 != null && geminiResult.score2 != null;
        const hasFullTime = geminiResult?.hasFullTime === true;
        const gemConf     = geminiResult?.confidence ?? 0;

        scoreFound
            ? pass('ocrSanity', { score1: geminiResult.score1, score2: geminiResult.score2, confidence: gemConf })
            : fail('ocrSanity', 30, { error: 'Gemini could not read the score' });

        hasFullTime
            ? pass('fullTimeWord')
            : fail('fullTimeWord', 15, { note: 'Full Time text not detected' });

        // 8. Score sanity — 0-0 with many shots is suspicious
        if (scoreFound) {
            const s1 = geminiResult.score1, s2 = geminiResult.score2;
            const zeroZeroSuspicious = s1 === 0 && s2 === 0 && gemConf < 70;
            zeroZeroSuspicious
                ? fail('scoreSanity', 20, { score1: s1, score2: s2 })
                : pass('scoreSanity', { score1: s1, score2: s2 });
        } else { pass('scoreSanity', { note: 'no score' }); }

        // 9. Team name match — compare Gemini's read against THIS match's registered teams only
        // (not a static club list — players use custom clubs like "this team vere level")
        if (scoreFound && matchData.creatorTeam && matchData.joinerTeam) {
            const home = geminiResult.homeTeam, away = geminiResult.awayTeam;
            const cOk = fuzzyTeamMatch(home, matchData.creatorTeam) || fuzzyTeamMatch(away, matchData.creatorTeam);
            const jOk = fuzzyTeamMatch(home, matchData.joinerTeam)  || fuzzyTeamMatch(away, matchData.joinerTeam);
            if (home && away && !cOk && !jOk) {
                // Neither team matches — genuinely suspicious (wrong match screenshot)
                fail('teamNameMatch', 25, { geminiHome: home, geminiAway: away, creatorTeam: matchData.creatorTeam, joinerTeam: matchData.joinerTeam });
            } else if (home && (!cOk || !jOk)) {
                // One team matched, one didn't — soft flag only (custom club names are common)
                fail('teamNameMatch', 10, { geminiHome: home, geminiAway: away, creatorTeam: matchData.creatorTeam, joinerTeam: matchData.joinerTeam, note: 'partial_match' });
            } else {
                pass('teamNameMatch', { home, away });
            }
        } else { pass('teamNameMatch', { note: 'skipped — match teams not registered' }); }

        // 10. Username presence — soft check only; many eFootball result screens don't show usernames
        // Only fail hard if BOTH Gemini found usernames AND neither matches
        if (scoreFound && (matchData.uploaderUsername || matchData.opponentUsername)) {
            const hu = (geminiResult.homeUsername || '').toLowerCase();
            const au = (geminiResult.awayUsername || '').toLowerCase();
            const uploaderName = (matchData.uploaderUsername || '').toLowerCase();
            const opponentName = (matchData.opponentUsername || '').toLowerCase();

            // If Gemini couldn't read any usernames, skip — screen may not show them
            if (!hu && !au) {
                pass('usernameMatch', { note: 'no usernames visible in screenshot — skipped' });
            } else {
                const usernameHit = (name, extracted) => !name || !extracted ||
                    extracted.includes(name.slice(0, 5)) || name.includes(extracted.slice(0, 5));
                const uploaderFound = usernameHit(uploaderName, hu) || usernameHit(uploaderName, au);
                const opponentFound = usernameHit(opponentName, hu) || usernameHit(opponentName, au);
                if (!uploaderFound && !opponentFound) {
                    // Usernames ARE visible but match neither player — moderately suspicious
                    fail('usernameMatch', 20, { geminiHome: hu, geminiAway: au, uploaderUsername: matchData.uploaderUsername, opponentUsername: matchData.opponentUsername });
                } else {
                    pass('usernameMatch', { homeUsername: geminiResult.homeUsername, awayUsername: geminiResult.awayUsername });
                }
            }
        } else { pass('usernameMatch', { note: 'skipped — no usernames provided' }); }

        // 11. Score plausibility — extreme scorelines are rare in eFootball
        if (scoreFound) {
            const s1 = geminiResult.score1, s2 = geminiResult.score2;
            const gap = Math.abs(s1 - s2);
            const total = s1 + s2;
            if (gap > 8 || total > 15) {
                // Very lopsided or extremely high-scoring — flag for admin confirmation, don't auto-settle
                fail('scorePlausibility', 20, { score1: s1, score2: s2, gap, total, note: 'Extreme scoreline — unlikely in normal eFootball match' });
            } else {
                pass('scorePlausibility', { score1: s1, score2: s2, gap, total });
            }
        } else { pass('scorePlausibility', { note: 'no score' }); }

        fraudScore = Math.min(100, fraudScore);

        let rec;
        if      (fraudScore >= 80)             rec = 'reject';
        else if (fraudScore >= 60)             rec = 'admin_review';
        else if (!scoreFound)                  rec = 'manual_declare';
        else if (gemConf >= 80 && fraudScore < 30) rec = 'auto_settle';
        else if (gemConf >= 60)                rec = 'challenge_window';
        else                                   rec = 'manual_confirm';

        const scoreData = scoreFound
            ? { score1: geminiResult.score1, score2: geminiResult.score2, homeTeam: geminiResult.homeTeam, awayTeam: geminiResult.awayTeam, homeUsername: geminiResult.homeUsername, awayUsername: geminiResult.awayUsername }
            : { score1: null, score2: null, homeTeam: null, awayTeam: null, homeUsername: null, awayUsername: null };

        const winner = scoreFound ? determineWinner(scoreData, matchData) : { winner: null, reason: 'no_score' };
        const elapsed = Date.now() - t0;

        console.log(`📊 [OCR-v7] ${elapsed}ms — score=${scoreData.score1 ?? '?'}-${scoreData.score2 ?? '?'} gemConf=${gemConf}% fraud=${fraudScore} winner=${winner.winner ?? 'unknown'} rec=${rec}`);

        return this._build({ checks, warnings, fraudScore, geminiResult, scoreData, elapsed, gemConf, winner, hash, rec });
    }

    _build({ checks, warnings, fraudScore, geminiResult, scoreData = {}, elapsed, gemConf = 0, winner, hash, rec }) {
        const sf = scoreData.score1 != null;
        const scoreStr = sf ? `${scoreData.score1}–${scoreData.score2}` : null;
        return {
            isValid:          sf && fraudScore < 80 && gemConf >= 50,
            ocrText:          '',   // not applicable with Gemini
            ocrConfidence:    gemConf,
            extractedScores:  { score1: scoreData.score1 ?? null, score2: scoreData.score2 ?? null },
            teamMatch:        { home: scoreData.homeTeam ?? null, away: scoreData.awayTeam ?? null },
            extractedStats:   {},
            winner:           winner || { winner: null, reason: 'no_score' },
            recommendation:   rec || 'manual_declare',
            fraudScore,
            confidence:       gemConf,
            warnings,
            userMessage:      this._msg(fraudScore, checks, sf, rec, scoreStr),
            checks,
            timings:          { total: elapsed },
            hash,
            geminiResult,
        };
    }

    _msg(fs, checks, sf, rec, scoreStr) {
        if (fs >= 80) {
            const W = { duplicate: 5, fileIntegrity: 5, exifTimestamp: 4, manipulation: 3, tooEarly: 3 };
            const top = Object.entries(checks)
                .filter(([, v]) => !v.passed)
                .sort(([a], [b]) => (W[b] || 1) - (W[a] || 1))[0];
            return top ? top[1].warning : 'Screenshot rejected. Contact admin if this is an error.';
        }
        if (fs >= 60) return `Flagged for admin review: ${Object.entries(checks).filter(([, v]) => !v.passed).map(([, v]) => v.warning).filter(Boolean).join(' | ')}`;
        if (!sf) return 'Could not read the score. Upload the "Full Time" result screen showing both team names and the final score.';
        const w = Object.entries(checks).filter(([, v]) => !v.passed).map(([, v]) => v.warning).filter(Boolean);
        if (w.length) return `Screenshot accepted with caution. Note: ${w.join(' | ')}`;
        return `Screenshot verified! Score: ${scoreStr ?? '?'}. Confidence: ${rec === 'auto_settle' ? 90 : 70}%.`;
    }
}

// ─── Gemini Arbitration — resolves cases without admin ────────────────────────
//
// Handles three situations:
//   'team_side'    — score known, can't tell which player is home/away
//   'low_score'    — score unclear, retry with a focused prompt on just the scoreline
//   'mismatch'     — two screenshots show different scores, Gemini picks the credible one
//
// Returns:
//   { resolved: true,  winner: 'creator'|'joiner'|'draw', score1, score2, confidence, reason }
//   { resolved: false, reason: string }   ← escalate to admin
// ─────────────────────────────────────────────────────────────────────────────
async function geminiArbitrate(type, payload) {
    if (!GEMINI_API_KEY) return { resolved: false, reason: 'no_api_key' };

    try {
        if (type === 'team_side') {
            // We know the score but not which player is home/away.
            // Give Gemini the screenshot + both registered team names and ask it to decide.
            const { imageBuffer, score1, score2, creatorTeam, joinerTeam } = payload;

            const resized = await sharp(imageBuffer)
                .resize(1280, null, { fit: 'inside', withoutEnlargement: true })
                .jpeg({ quality: 90 }).toBuffer();

            const prompt = `This is an eFootball match result screenshot. The final score is ${score1}–${score2}.

Two players are registered for this match:
- Creator played as: "${creatorTeam}"
- Joiner played as: "${joinerTeam}"

Look at the team names shown in the score banner at the top of the screen.
Determine which side (home=left, away=right) each registered team is on.

Respond with ONLY valid JSON, no markdown:
{
  "creatorIsHome": <true if creator's team is on the LEFT/home side, false if RIGHT/away>,
  "creatorScore": <creator's final score as integer>,
  "joinerScore": <joiner's final score as integer>,
  "winner": <"creator", "joiner", or "draw">,
  "confidence": <integer 50-100>,
  "reasoning": "<one sentence explaining how you identified which team is which>"
}`;

            const body = {
                contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: 'image/jpeg', data: resized.toString('base64') } }] }],
                generationConfig: { temperature: 0, maxOutputTokens: 256 }
            };

            const res = await queuedGeminiFetch(body);
            if (!res.ok) return { resolved: false, reason: `gemini_${res.status}` };

            const data = await res.json();
            const raw  = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
            const parsed = JSON.parse(raw.replace(/```json|```/gi, '').trim());

            if (!parsed.winner || !['creator','joiner','draw'].includes(parsed.winner)) {
                return { resolved: false, reason: 'gemini_bad_response' };
            }
            if ((parsed.confidence ?? 0) < 70) {
                return { resolved: false, reason: 'low_confidence', confidence: parsed.confidence };
            }
            return {
                resolved:      true,
                winner:        parsed.winner,
                creatorScore:  parsed.creatorScore ?? (parsed.creatorIsHome ? score1 : score2),
                joinerScore:   parsed.joinerScore  ?? (parsed.creatorIsHome ? score2 : score1),
                score1, score2,
                confidence:    parsed.confidence,
                reasoning:     parsed.reasoning || '',
            };
        }

        if (type === 'low_score') {
            // Gemini gave low confidence on score — retry with a sharper, score-focused prompt
            const { imageBuffer } = payload;

            const resized = await sharp(imageBuffer)
                .resize(1280, null, { fit: 'inside', withoutEnlargement: true })
                .jpeg({ quality: 95 }).toBuffer();

            const prompt = `Focus ONLY on the score banner at the very top of this eFootball match result screenshot.
Find the two numbers in yellow boxes — these are the final scores.
Ignore all stats in the table below.

Respond with ONLY valid JSON, no markdown:
{
  "score1": <left/home score as integer>,
  "score2": <right/away score as integer>,
  "homeTeam": "<team name on left>",
  "awayTeam": "<team name on right>",
  "hasFullTime": <true or false>,
  "confidence": <integer 50-100>
}`;

            const body = {
                contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: 'image/jpeg', data: resized.toString('base64') } }] }],
                generationConfig: { temperature: 0, maxOutputTokens: 128 }
            };

            const res = await queuedGeminiFetch(body);
            if (!res.ok) return { resolved: false, reason: `gemini_${res.status}` };

            const data = await res.json();
            const raw  = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
            const parsed = JSON.parse(raw.replace(/```json|```/gi, '').trim());

            const s1 = parseInt(parsed.score1, 10), s2 = parseInt(parsed.score2, 10);
            if (isNaN(s1) || isNaN(s2) || s1 < 0 || s1 > 20 || s2 < 0 || s2 > 20) {
                return { resolved: false, reason: 'score_unreadable' };
            }
            if ((parsed.confidence ?? 0) < 65) {
                return { resolved: false, reason: 'low_confidence', confidence: parsed.confidence };
            }
            return {
                resolved:    true,
                score1:      s1,
                score2:      s2,
                homeTeam:    parsed.homeTeam    || null,
                awayTeam:    parsed.awayTeam    || null,
                hasFullTime: parsed.hasFullTime === true,
                confidence:  parsed.confidence,
            };
        }

        if (type === 'mismatch') {
            // Two screenshots claim different scores. Give Gemini both images and ask it to judge.
            const { creatorBuffer, joinerBuffer, creatorTeam, joinerTeam, score1A, score2A, score1B, score2B } = payload;

            const [imgA, imgB] = await Promise.all([
                sharp(creatorBuffer).resize(960, null, { fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 90 }).toBuffer(),
                sharp(joinerBuffer).resize(960, null, { fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 90 }).toBuffer(),
            ]);

            const prompt = `You are adjudicating a disputed eFootball match result.

Two players submitted different screenshots showing different scores:
- Creator (${creatorTeam || 'unknown team'}) claims: ${score1A}–${score2A}
- Joiner  (${joinerTeam  || 'unknown team'}) claims: ${score1B}–${score2B}

The FIRST image is the creator's screenshot.
The SECOND image is the joiner's screenshot.

Examine both screenshots carefully. Look for:
1. The score in the yellow boxes at the top
2. "Full Time" text
3. Whether the screenshot looks genuine vs edited
4. Timestamp or match context clues

Respond with ONLY valid JSON, no markdown:
{
  "credibleScreenshot": <"creator", "joiner", or "neither">,
  "score1": <the correct home score as integer>,
  "score2": <the correct away score as integer>,
  "winner": <"creator", "joiner", or "draw">,
  "confidence": <integer 50-100>,
  "reasoning": "<2-3 sentences explaining your decision>"
}

If you cannot determine a clear winner, set credibleScreenshot to "neither" and confidence below 60.`;

            const body = {
                contents: [{
                    parts: [
                        { text: prompt },
                        { inline_data: { mime_type: 'image/jpeg', data: imgA.toString('base64') } },
                        { inline_data: { mime_type: 'image/jpeg', data: imgB.toString('base64') } },
                    ]
                }],
                generationConfig: { temperature: 0, maxOutputTokens: 512 }
            };

            const res = await queuedGeminiFetch(body);
            if (!res.ok) return { resolved: false, reason: `gemini_${res.status}` };

            const data = await res.json();
            const raw  = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
            const parsed = JSON.parse(raw.replace(/```json|```/gi, '').trim());

            console.log(`⚖️  [geminiArbitrate/mismatch] credible=${parsed.credibleScreenshot} conf=${parsed.confidence} winner=${parsed.winner}`);
            console.log(`   Reasoning: ${parsed.reasoning}`);

            if (parsed.credibleScreenshot === 'neither' || (parsed.confidence ?? 0) < 70) {
                return { resolved: false, reason: 'gemini_undecided', confidence: parsed.confidence, reasoning: parsed.reasoning };
            }
            if (!parsed.winner || !['creator','joiner','draw'].includes(parsed.winner)) {
                return { resolved: false, reason: 'gemini_bad_response' };
            }
            return {
                resolved:           true,
                winner:             parsed.winner,
                score1:             parseInt(parsed.score1, 10),
                score2:             parseInt(parsed.score2, 10),
                confidence:         parsed.confidence,
                credibleScreenshot: parsed.credibleScreenshot,
                reasoning:          parsed.reasoning || '',
            };
        }

        return { resolved: false, reason: 'unknown_type' };

    } catch (err) {
        console.error(`❌ [geminiArbitrate/${type}] error:`, err.message);
        return { resolved: false, reason: 'exception', error: err.message };
    }
}

module.exports = { ScreenshotVerifier, geminiArbitrate };