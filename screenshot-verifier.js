/**
 * SCREENSHOT VERIFICATION MODULE
 * Multi-layer fraud detection for match result screenshots
 */

const ExifReader = require('exifreader');
const sharp = require('sharp');
const Tesseract = require('tesseract.js');

// ─── Persistent Tesseract Worker ─────────────────────────────────────────────
let _tesseractWorker = null;
let _workerInitializing = false;
let _workerInitQueue = [];

async function getTesseractWorker() {
    if (_tesseractWorker) return _tesseractWorker;
    if (_workerInitializing) {
        return new Promise((resolve, reject) => _workerInitQueue.push({ resolve, reject }));
    }
    _workerInitializing = true;
    console.log('📦 Initializing persistent Tesseract worker (one-time)...');
    try {
        const worker = await Tesseract.createWorker('eng', 1, {
            logger: () => {},
            errorHandler: (err) => console.error('Tesseract worker error:', err)
        });
        await worker.setParameters({ tessedit_char_whitelist: '0123456789-: ' });
        _tesseractWorker = worker;
        console.log('✅ Persistent Tesseract worker ready.');
        _workerInitQueue.forEach(({ resolve }) => resolve(_tesseractWorker));
        _workerInitQueue = [];
        return _tesseractWorker;
    } catch (err) {
        console.error('❌ Failed to initialize Tesseract worker:', err.message);
        _workerInitQueue.forEach(({ reject }) => reject(err));
        _workerInitQueue = [];
        _workerInitializing = false;
        throw err;
    } finally {
        _workerInitializing = false;
    }
}

getTesseractWorker().catch(() => {});
// ─────────────────────────────────────────────────────────────────────────────

class ScreenshotVerifier {
    constructor(supabase) {
        this.supabase = supabase;
    }

    async verifyScreenshot(imageBuffer, matchData) {
        const results = { isValid: true, fraudScore: 0, warnings: [], checks: {} };

        const checks = [
            ['metadata',     () => this.checkMetadata(imageBuffer, matchData),                          true  ],
            ['timestamp',    () => this.checkTimestamp(matchData),                                       false ],
            ['manipulation', () => this.checkManipulation(imageBuffer),                                  true  ],
            ['duplicate',    () => this.checkDuplicate(imageBuffer, matchData.userId, matchData.matchId), true ],
            ['device',       () => this.checkDeviceConsistency(imageBuffer, matchData.userId),           true  ],
            ['ocrSanity',    () => this.checkOcrSanity(imageBuffer),                                     true  ],
            ['matchContext', () => this.checkMatchContext(imageBuffer, matchData),                        true  ],
        ];

        const scores = { metadata: 30, timestamp: 25, manipulation: 35, duplicate: 40, device: 15, ocrSanity: 20, matchContext: 35 };

        for (const [name, fn, isAsync] of checks) {
            try {
                const check = isAsync ? await fn() : fn();
                results.checks[name] = check;
                if (!check.passed) {
                    results.fraudScore += check.score ?? scores[name];
                    if (check.warning) results.warnings.push(check.warning);
                }
            } catch (err) {
                console.error(`Check "${name}" threw:`, err.message);
                results.checks[name] = { passed: true, warning: null, details: { error: err.message } };
            }
        }

        // isValid = safe for auto-settle (no significant flags)
        // < 30  → clean, auto-settle allowed
        // 30-49 → one soft flag (e.g. missing EXIF), manual confirm required  
        // 50+   → multiple flags or one hard flag, admin review
        results.isValid = results.fraudScore < 30;
        results.confidence = results.isValid ? 'high' : 'low';
        if      (results.fraudScore >= 70) results.recommendation = 'REJECT - High fraud probability';
        else if (results.fraudScore >= 50) results.recommendation = 'MANUAL_REVIEW - Suspicious';
        else if (results.fraudScore >= 30) results.recommendation = 'MANUAL_CONFIRM - Needs opponent corroboration';
        else                               results.recommendation = 'ACCEPT - Likely authentic';

        return results;
    }

    // Check 1: EXIF metadata + timestamp against match start
    async checkMetadata(imageBuffer, matchData) {
        try {
            const tags = ExifReader.load(imageBuffer);

            if (!tags || Object.keys(tags).length < 5) {
                return { passed: false, score: 30, warning: 'Screenshot has no metadata — may have been edited or re-saved from gallery', details: { missingExif: true } };
            }

            const result = { passed: true, score: 0, warning: null, details: {} };

            const dateTime = tags.DateTime?.description || tags.DateTimeOriginal?.description || tags.CreateDate?.description;
            if (dateTime) {
                const photoTime = new Date(dateTime);
                const matchStart = new Date(matchData.startedAt);
                const diffMinutes = (photoTime - matchStart) / 60000;
                result.details.photoTime = photoTime;
                result.details.timeDiffMinutes = Math.round(diffMinutes);

                if (diffMinutes < -5) {
                    result.passed = false; result.score = 30;
                    result.warning = `Screenshot taken ${Math.abs(Math.floor(diffMinutes))} min BEFORE this match started`;
                    return result;
                }
                // Key old-screenshot check: photo outside this match's window = different session
                if (diffMinutes > 90) {
                    result.passed = false; result.score = 30;
                    result.warning = `Screenshot is ${Math.floor(diffMinutes)} minutes old — it's from a different session, not this match`;
                    return result;
                }
                // Too early for a finished game (eFootball takes ~15 min minimum)
                if (diffMinutes < 8) {
                    result.passed = false; result.score = 30;
                    result.warning = `Screenshot taken only ${Math.round(diffMinutes)} minutes into the match — too early for a final result`;
                    return result;
                }
            }

            const software = tags.Software?.description || '';
            const bad = ['photoshop', 'gimp', 'pixlr', 'canva', 'paint.net', 'lightroom', 'snapseed'];
            if (bad.some(s => software.toLowerCase().includes(s))) {
                result.passed = false; result.score = 30;
                result.warning = `Image edited with "${software}"`;
                result.details.software = software;
            }

            result.details.device = tags.Model?.description || 'Unknown';
            result.details.make   = tags.Make?.description  || 'Unknown';
            return result;
        } catch (err) {
            return { passed: false, score: 30, warning: 'Could not read screenshot metadata — may have been edited', details: { error: err.message } };
        }
    }

    // Check 2: Wall-clock upload timing
    checkTimestamp(matchData) {
        const now = new Date();
        const matchStart = new Date(matchData.startedAt);
        const delayMinutes = (now - matchStart) / 60000;
        const result = { passed: true, warning: null, details: { matchStart, uploadTime: now, delayMinutes: Math.round(delayMinutes) } };

        if (delayMinutes < 0.5) {
            result.passed = false;
            result.warning = 'Screenshot uploaded before match could have finished';
        } else if (delayMinutes > 90) {
            result.passed = false;
            result.warning = `Screenshot uploaded ${Math.floor(delayMinutes)} minutes after match started — too late`;
        }
        return result;
    }

    // Check 3: Image manipulation via file size and color stats
    async checkManipulation(imageBuffer) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const image = sharp(imageBuffer);
            const metadata = await image.metadata();
            result.details = { width: metadata.width, height: metadata.height, format: metadata.format };

            const bytesPerPixel = imageBuffer.length / (metadata.width * metadata.height);
            if (bytesPerPixel < 0.05) {
                result.passed = false;
                result.warning = 'Image is unusually small for its size — likely re-compressed after editing';
                result.details.bytesPerPixel = bytesPerPixel.toFixed(3);
                return result;
            }

            if (metadata.format === 'jpeg') {
                const stats = await image.stats();
                const ch = stats.channels;
                if (ch.length >= 3) {
                    const imbalance = Math.abs(ch[0].mean - ch[1].mean) + Math.abs(ch[1].mean - ch[2].mean) + Math.abs(ch[2].mean - ch[0].mean);
                    if (imbalance > 200) {
                        result.passed = false;
                        result.warning = 'Unusual color distribution — image may have been manipulated';
                        result.details.colorImbalance = Math.round(imbalance);
                    }
                }
            }
            return result;
        } catch (err) {
            return { passed: false, warning: 'Image analysis failed — possibly corrupted', details: { error: err.message } };
        }
    }

    // Check 4: Duplicate — checks exact AND near-duplicate hashes
    // Near-duplicate (hamming distance <= 4) catches:
    //   - Same screenshot re-cropped or slightly compressed
    //   - Screenshot of a screenshot on another screen
    //   - Same image with minor brightness/contrast edits
    async checkDuplicate(imageBuffer, userId, matchId) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const hash = await this.generatePerceptualHash(imageBuffer);
            result.details.hash = hash;

            // Fetch this user's recent screenshot hashes (last 50) for near-duplicate check
            const { data: userHashes, error: userErr } = await this.supabase
                .from('screenshot_hashes')
                .select('hash, match_id, user_id')
                .eq('user_id', userId)
                .neq('match_id', matchId)
                .order('created_at', { ascending: false })
                .limit(50);

            if (userErr) throw userErr;

            // Check user's own history for near-duplicates (hamming distance <= 4)
            if (userHashes && userHashes.length > 0) {
                for (const row of userHashes) {
                    const dist = this.hammingDistance(hash, row.hash);
                    if (dist <= 4) {
                        result.passed = false;
                        result.warning = dist === 0
                            ? 'You already used this exact screenshot in a previous match'
                            : `This screenshot is nearly identical to one you used in a previous match (similarity: ${Math.round((1 - dist/64)*100)}%)`;
                        result.details.originalMatch = row.match_id;
                        result.details.hammingDistance = dist;
                        result.details.isSameUser = true;
                        return result;
                    }
                }
            }

            // Also check globally for exact hash reuse by any user
            const { data: globalMatch, error: globalErr } = await this.supabase
                .from('screenshot_hashes')
                .select('match_id, user_id')
                .eq('hash', hash)
                .neq('match_id', matchId)
                .maybeSingle();

            if (globalErr) throw globalErr;

            if (globalMatch) {
                result.passed = false;
                result.warning = 'This exact screenshot was already submitted in another match';
                result.details.originalMatch = globalMatch.match_id;
                result.details.isSameUser = globalMatch.user_id === userId;
            }

            return result;
        } catch (err) {
            console.error('Duplicate check DB error:', err.message);
            return { passed: true, warning: null, details: { dbError: err.message } };
        }
    }

    // Hamming distance between two equal-length binary strings
    hammingDistance(a, b) {
        if (a.length !== b.length) return 64; // treat mismatched lengths as max distance
        let dist = 0;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) dist++;
        }
        return dist;
    }

    async generatePerceptualHash(imageBuffer) {
        return sharp(imageBuffer)
            .resize(8, 8, { fit: 'fill' })
            .grayscale()
            .raw()
            .toBuffer()
            .then(buf => {
                const pixels = Array.from(buf);
                const avg = pixels.reduce((a, b) => a + b, 0) / pixels.length;
                return pixels.map(p => (p > avg ? '1' : '0')).join('');
            });
    }

    // Check 5: Device consistency (only flags after 3+ previous uploads)
    async checkDeviceConsistency(imageBuffer, userId) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const tags = ExifReader.load(imageBuffer);
            const device = tags?.Model?.description || 'Unknown';
            result.details.device = device;
            if (device === 'Unknown') return result;

            const { data: history, error } = await this.supabase
                .from('user_screenshot_history')
                .select('device')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .limit(10);

            if (error) throw error;

            if (history && history.length >= 3) {
                const freq = {};
                history.forEach(h => freq[h.device] = (freq[h.device] || 0) + 1);
                const mostCommon = Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0];
                if (device !== mostCommon) {
                    result.passed = false;
                    result.warning = `Screenshot from "${device}" — you usually submit from "${mostCommon}"`;
                }
            }
            return result;
        } catch (err) {
            return { passed: true, warning: null, details: {} };
        }
    }

    // Check 6: OCR sanity — the image must contain at least some numbers
    async checkOcrSanity(imageBuffer) {
        try {
            const preprocessed = await sharp(imageBuffer)
                .resize(800, 600, { fit: 'inside' })
                .grayscale()
                .normalize()
                .toBuffer();

            const worker = await getTesseractWorker();
            const { data: { text, confidence } } = await worker.recognize(preprocessed);
            const hasNumbers = /\d/.test(text);

            return {
                passed: hasNumbers,
                warning: hasNumbers ? null : 'No numbers found in image — does not look like a game result screen',
                details: { hasNumbers, ocrConfidence: Math.round(confidence), textLength: text.trim().length }
            };
        } catch (err) {
            return { passed: true, warning: null, details: { error: err.message } };
        }
    }

    // Check 7: Match context — does the screenshot actually show THIS match?
    // OCR the full image and look for:
    //   a) The opponent's username (strongest signal)
    //   b) The match code (VUM-XXXX) if visible
    // If neither appears, the screenshot could be from any match or downloaded.
    // We don't hard-block on this (OCR isn't perfect) but it adds heavy fraud points.
    async checkMatchContext(imageBuffer, matchData) {
        // If we weren't given any context to check against, skip gracefully
        if (!matchData.opponentUsername && !matchData.matchCode) {
            return { passed: true, warning: null, details: { skipped: 'no context provided' } };
        }

        try {
            const worker = await getTesseractWorker();

            // Full alphabet whitelist to read usernames
            await worker.setParameters({ tessedit_char_whitelist: '' });

            const preprocessed = await sharp(imageBuffer)
                .resize(1920, 1080, { fit: 'inside' })
                .sharpen()
                .normalize()
                .toBuffer();

            const { data: { text } } = await worker.recognize(preprocessed);

            // Restore numeric-only whitelist for score extraction
            await worker.setParameters({ tessedit_char_whitelist: '0123456789-: ' });

            const rawText = text.toLowerCase();
            const result = { passed: true, warning: null, details: { rawTextLength: rawText.length } };

            const findName = (name) => {
                if (!name) return { found: false, partial: false };
                const n = name.toLowerCase().trim();
                if (rawText.includes(n)) return { found: true, partial: false };
                // Fuzzy: first 4+ chars (handles truncated names in UI)
                const stub = n.length >= 4 ? n.substring(0, 4) : null;
                if (stub && rawText.includes(stub)) return { found: false, partial: true };
                return { found: false, partial: false };
            };

            // Check for opponent username — must appear on final score screen
            if (matchData.opponentUsername) {
                const opponentResult = findName(matchData.opponentUsername);
                result.details.opponentUsername = matchData.opponentUsername;
                result.details.foundOpponentUsername = opponentResult.found;
                result.details.foundOpponentPartial = opponentResult.partial;

                if (!opponentResult.found && !opponentResult.partial) {
                    result.passed = false;
                    result.score = 35;
                    result.warning = `Opponent "${matchData.opponentUsername}" not found in screenshot — this may be from a different match`;
                    return result;
                }
                if (!opponentResult.found && opponentResult.partial) {
                    result.details.partialMatchOnly = true;
                    result.warning = `Could only partially match opponent name — screenshot may be from a different match`;
                }
            }

            // Check for uploader's own username — both players appear on the final screen
            // If the uploader's name also isn't there, it's very likely the wrong match
            if (matchData.uploaderUsername) {
                const uploaderResult = findName(matchData.uploaderUsername);
                result.details.uploaderUsername = matchData.uploaderUsername;
                result.details.foundUploaderUsername = uploaderResult.found;

                if (!uploaderResult.found && !uploaderResult.partial) {
                    // Combine with opponent check: if neither name is found, strong fraud signal
                    if (result.details.foundOpponentUsername === false && !result.details.foundOpponentPartial) {
                        result.passed = false;
                        result.score = 35;
                        result.warning = 'Neither player’s username found in screenshot — this is from a different match';
                        return result;
                    }
                    // Uploader alone not found — softer signal
                    result.details.uploaderMissing = true;
                    if (!result.warning) {
                        result.warning = 'Your username wasn’t clearly visible in the screenshot — make sure it’s the final result screen';
                    }
                }
            }

            // Match code is never in-game, but log it for admin audit trails
            if (matchData.matchCode) {
                result.details.matchCode = matchData.matchCode;
                result.details.foundMatchCode = rawText.includes(matchData.matchCode.toLowerCase());
            }

            return result;
        } catch (err) {
            console.error('Match context check failed:', err.message);
            // OCR failure = skip, don't penalise
            return { passed: true, warning: null, details: { error: err.message } };
        }
    }

    // Full-resolution OCR for score extraction
    async extractScoreWithConfidence(imageBuffer) {
        try {
            const preprocessed = await sharp(imageBuffer)
                .resize(1920, 1080, { fit: 'inside' })
                .sharpen()
                .normalize()
                .toBuffer();

            const worker = await getTesseractWorker();
            const { data: { text, confidence } } = await worker.recognize(preprocessed);

            const patterns = [
                /(\d+)\s*[-:]\s*(\d+)/,
                /(\d+)\s+(\d+)/,
                /HOME\s+(\d+).*AWAY\s+(\d+)/i,
            ];

            let score1, score2;
            for (const pattern of patterns) {
                const match = text.match(pattern);
                if (match) {
                    const s1 = parseInt(match[1]);
                    const s2 = parseInt(match[2]);
                    if (s1 <= 20 && s2 <= 20) { score1 = s1; score2 = s2; break; }
                }
            }

            return {
                score1, score2, confidence, rawText: text,
                isValid: score1 !== undefined && score2 !== undefined && confidence > 70
            };
        } catch (err) {
            console.error('OCR extraction failed:', err);
            return { score1: null, score2: null, confidence: 0, isValid: false, error: err.message };
        }
    }
}

module.exports = ScreenshotVerifier;