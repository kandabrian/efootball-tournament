/**
 * SIMPLIFIED ADVANCED SCREENSHOT VERIFIER
 * Works without session tracking - can be integrated later
 * Still includes most fraud detection improvements
 */

const ExifReader = require('exifreader');
const sharp = require('sharp');
const Tesseract = require('tesseract.js');
const crypto = require('crypto');

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

class SimplifiedAdvancedVerifier {
    constructor(supabase) {
        this.supabase = supabase;
        
        // Known eFootball UI elements (color signatures)
        this.eFootballSignatures = {
            scoreboardBlue: { r: [0, 50], g: [100, 200], b: [200, 255] },
            resultGreen: { r: [0, 100], g: [200, 255], b: [0, 100] },
            menuYellow: { r: [200, 255], g: [200, 255], b: [0, 100] },
            darkBackground: { r: [0, 50], g: [0, 50], b: [0, 50] }
        };
    }

    async verifyScreenshot(imageBuffer, matchData, clientMetadata = {}) {
        const results = { 
            isValid: true, 
            fraudScore: 0, 
            warnings: [], 
            checks: {},
            riskLevel: 'LOW',
            requiresManualReview: false
        };

        const checks = [
            // Core verification (no session dependency)
            ['metadata',         () => this.checkAdvancedMetadata(imageBuffer, matchData),          true],
            ['timestamp',        () => this.checkTimestamp(matchData),                              false],
            ['manipulation',     () => this.checkAdvancedManipulation(imageBuffer),                 true],
            ['duplicate',        () => this.checkAdvancedDuplicate(imageBuffer, matchData),         true],
            ['device',           () => this.checkDeviceConsistency(imageBuffer, matchData.userId),  true],
            ['gameUIRecognition',() => this.recognizeGameUI(imageBuffer),                           true],
            ['matchContext',     () => this.checkMatchContext(imageBuffer, matchData),              true],
            ['ocrSanity',        () => this.checkOcrSanity(imageBuffer),                            true],
            ['behavioral',       () => this.analyzeBehavioralPattern(matchData),                    true],
            ['crossReference',   () => this.crossReferenceOpponent(matchData),                      true]
        ];

        const scores = {
            metadata: 30,
            timestamp: 25,
            manipulation: 40,
            duplicate: 50,
            device: 20,
            gameUIRecognition: 35,
            matchContext: 40,
            ocrSanity: 20,
            behavioral: 30,
            crossReference: 30
        };

        for (const [name, fn, isAsync] of checks) {
            try {
                const check = isAsync ? await fn() : fn();
                results.checks[name] = check;
                if (!check.passed) {
                    const fraudPoints = check.score ?? scores[name];
                    results.fraudScore += fraudPoints;
                    if (check.warning) results.warnings.push(check.warning);
                    
                    if (check.critical) {
                        results.requiresManualReview = true;
                    }
                }
            } catch (err) {
                console.error(`Check "${name}" threw:`, err.message);
                results.checks[name] = { passed: true, warning: null, details: { error: err.message } };
            }
        }

        // Risk scoring (adjusted for no session tracking)
        if (results.fraudScore >= 90) {
            results.riskLevel = 'CRITICAL';
            results.recommendation = 'REJECT - Multiple fraud indicators detected';
            results.isValid = false;
        } else if (results.fraudScore >= 60) {
            results.riskLevel = 'HIGH';
            results.recommendation = 'MANUAL_REVIEW - High suspicion of fraud';
            results.isValid = false;
            results.requiresManualReview = true;
        } else if (results.fraudScore >= 35) {
            results.riskLevel = 'MEDIUM';
            results.recommendation = 'MANUAL_CONFIRM - Requires opponent verification';
            results.isValid = false;
            results.requiresManualReview = true;
        } else if (results.fraudScore >= 15) {
            results.riskLevel = 'LOW';
            results.recommendation = 'REVIEW - Minor concerns, likely authentic';
            results.isValid = true;
        } else {
            results.riskLevel = 'MINIMAL';
            results.recommendation = 'ACCEPT - Strong authenticity signals';
            results.isValid = true;
        }

        results.confidence = results.fraudScore < 35 ? 'high' : 'low';
        return results;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VERIFICATION CHECKS
    // ═══════════════════════════════════════════════════════════════════════

    async recognizeGameUI(imageBuffer) {
        const result = { passed: false, warning: null, details: {} };

        try {
            const image = sharp(imageBuffer);
            const { data, info } = await image
                .resize(800, 600, { fit: 'inside' })
                .raw()
                .toBuffer({ resolveWithObject: true });

            const samples = 1000;
            const colorCounts = {
                scoreboardBlue: 0,
                resultGreen: 0,
                menuYellow: 0,
                darkBackground: 0
            };

            for (let i = 0; i < samples; i++) {
                const offset = Math.floor(Math.random() * (data.length / 3)) * 3;
                const r = data[offset];
                const g = data[offset + 1];
                const b = data[offset + 2];

                for (const [signature, ranges] of Object.entries(this.eFootballSignatures)) {
                    if (r >= ranges.r[0] && r <= ranges.r[1] &&
                        g >= ranges.g[0] && g <= ranges.g[1] &&
                        b >= ranges.b[0] && b <= ranges.b[1]) {
                        colorCounts[signature]++;
                    }
                }
            }

            const totalGameColors = Object.values(colorCounts).reduce((a, b) => a + b, 0);
            const gameColorPercentage = (totalGameColors / samples) * 100;

            result.details.colorAnalysis = colorCounts;
            result.details.gameUIPercentage = Math.round(gameColorPercentage);

            if (gameColorPercentage < 10) {
                result.passed = false;
                result.score = 35;
                result.warning = `Only ${Math.round(gameColorPercentage)}% of image matches eFootball UI - may not be a game screenshot`;
                return result;
            }

            result.passed = true;
            result.details.verified = true;

        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }

        return result;
    }

    async checkAdvancedMetadata(imageBuffer, matchData) {
        try {
            const tags = ExifReader.load(imageBuffer);
            const result = { passed: true, score: 0, warning: null, details: {} };

            // WhatsApp strips ALL EXIF. Mobile/console screenshots almost never
            // have EXIF. Missing metadata is completely normal — do NOT penalise it.
            if (!tags || Object.keys(tags).length < 5) {
                result.details.noExif = true;
                return result; // pass silently
            }

            // Only use timestamp if EXIF is actually present
            const dateTime = tags.DateTime?.description || tags.DateTimeOriginal?.description;
            if (dateTime) {
                const photoTime = new Date(dateTime);
                const matchStart = new Date(matchData.startedAt);
                const diffMinutes = (photoTime - matchStart) / 60000;
                result.details.timeDiffMinutes = Math.round(diffMinutes);

                // Photo clearly taken before this match started (allow 5 min clock drift)
                if (diffMinutes < -5) {
                    result.passed = false;
                    result.score = 35;
                    result.warning = `Screenshot taken ${Math.abs(Math.floor(diffMinutes))} min before match started`;
                    return result;
                }
                // Photo from a very old session (over 3 hours)
                if (diffMinutes > 180) {
                    result.passed = false;
                    result.score = 25;
                    result.warning = `Screenshot is ${Math.floor(diffMinutes / 60)}h old - likely from a different session`;
                    return result;
                }
            }
            // No timestamp in EXIF = fine, just note it
            result.details.noTimestamp = !dateTime;

            // Only flag known desktop editing software (NOT mobile apps)
            const software = tags.Software?.description || '';
            const desktopEditors = ['photoshop', 'gimp', 'pixlr', 'canva', 'lightroom'];
            if (desktopEditors.some(e => software.toLowerCase().includes(e))) {
                result.passed = false;
                result.score = 30;
                result.warning = `Image edited with "${software}"`;
                result.details.editingSoftware = software;
            }

            result.details.device = tags.Model?.description || 'Unknown';
            result.details.make = tags.Make?.description || 'Unknown';

            return result;

        } catch (err) {
            // ExifReader throws on images with no EXIF — that is normal, pass silently
            return { passed: true, score: 0, warning: null, details: { noExif: true } };
        }
    }

    checkTimestamp(matchData) {
        const now = new Date();
        const matchStart = new Date(matchData.startedAt);
        const delayMinutes = (now - matchStart) / 60000;
        const result = { 
            passed: true, 
            warning: null, 
            details: { 
                matchStart, 
                uploadTime: now, 
                delayMinutes: Math.round(delayMinutes) 
            } 
        };

        // eFootball short matches can finish in ~6 min. Give 3 min minimum.
        if (delayMinutes < 3) {
            result.passed = false;
            result.score = 20;
            result.warning = 'Screenshot uploaded too quickly - match not finished yet';
        } else if (delayMinutes > 240) {
            // 4 hours is the hard limit — beyond that it's clearly a different session
            result.passed = false;
            result.score = 20;
            result.warning = `Screenshot uploaded ${Math.floor(delayMinutes / 60)}h after match started`;
        }
        return result;
    }

    async checkAdvancedManipulation(imageBuffer) {
        const result = { passed: true, warning: null, details: {} };

        try {
            const metadata = await sharp(imageBuffer).metadata();
            const image = sharp(imageBuffer);

            // JPEG compression analysis
            if (metadata.format === 'jpeg' || metadata.format === 'jpg') {
                const recompressed = await image.jpeg({ quality: 95 }).toBuffer();
                const compressionRatio = recompressed.length / imageBuffer.length;

                result.details.compressionRatio = compressionRatio.toFixed(3);

                // WhatsApp re-encodes JPEGs heavily — widen the acceptable
                // ratio range to avoid flagging legitimate shared screenshots.
                if (compressionRatio > 2.0 || compressionRatio < 0.4) {
                    result.passed = false;
                    result.score = 10; // low score — compression alone is weak signal
                    result.warning = 'Unusual compression patterns - image may have been edited';
                    result.details.abnormalCompression = true;
                }
            }

            // File size check
            const sizeKB = imageBuffer.length / 1024;
            result.details.fileSizeKB = Math.round(sizeKB);

            if (sizeKB < 10) {
                result.passed = false;
                result.score = 25;
                result.warning = 'File size suspiciously small - heavily compressed or fake';
                result.details.tooSmall = true;
            }

            if (sizeKB > 10000) {
                result.passed = false;
                result.score = 15;
                result.warning = 'File size unusually large';
                result.details.tooLarge = true;
            }

        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }

        return result;
    }

    async checkAdvancedDuplicate(imageBuffer, matchData) {
        const result = { passed: true, warning: null, details: {} };

        try {
            const hashes = await this.generatePerceptualHashes(imageBuffer);
            result.details.imageHashes = hashes;

            const { data: recentSubmissions } = await this.supabase
                .from('match_results')
                .select('screenshot_hash, created_at, match_id')
                .eq('user_id', matchData.userId)
                .neq('match_id', matchData.matchId)
                .gte('created_at', new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString())
                .order('created_at', { ascending: false })
                .limit(50);

            if (recentSubmissions) {
                for (const submission of recentSubmissions) {
                    if (!submission.screenshot_hash) continue;

                    const storedHashes = JSON.parse(submission.screenshot_hash);
                    const similarity = this.comparePerceptualHashes(hashes, storedHashes);

                    if (similarity > 0.95) {
                        result.passed = false;
                        result.score = 50;
                        result.critical = true;
                        result.warning = 'Duplicate screenshot detected - exact same image used before';
                        result.details.duplicateMatch = submission.match_id;
                        return result;
                    }

                    if (similarity > 0.85) {
                        result.passed = false;
                        result.score = 35;
                        result.warning = 'Very similar screenshot detected - may be reusing edited version';
                        result.details.similarMatch = submission.match_id;
                        return result;
                    }
                }
            }

        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }

        return result;
    }

    async checkDeviceConsistency(imageBuffer, userId) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const tags = ExifReader.load(imageBuffer);
            const currentDevice = tags.Model?.description;
            
            if (!currentDevice) {
                result.details.noDeviceInfo = true;
                return result;
            }

            const { data: recentDevices } = await this.supabase
                .from('match_results')
                .select('device_model')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .limit(10);

            if (recentDevices && recentDevices.length >= 3) {
                const devices = recentDevices
                    .map(r => r.device_model)
                    .filter(Boolean);
                
                const uniqueDevices = [...new Set(devices)];
                result.details.recentDevices = uniqueDevices;

                if (uniqueDevices.length >= 3) {
                    result.passed = false;
                    result.score = 15;
                    result.warning = 'Multiple devices used - possible account sharing';
                    result.details.suspiciousDeviceSwitching = true;
                }
            }

            result.details.currentDevice = currentDevice;
        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }
        return result;
    }

    async analyzeBehavioralPattern(matchData) {
        const result = { passed: true, warning: null, details: {} };

        try {
            const userId = matchData.userId;
            const now = new Date();

            const { data: history } = await this.supabase
                .from('match_results')
                .select('created_at, started_at, result')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .limit(20);

            if (!history || history.length < 3) {
                result.details.insufficientHistory = true;
                return result;
            }

            result.details.submissionCount = history.length;

            // Suspicious win rate
            const wins = history.filter(h => h.result === 'win').length;
            const winRate = wins / history.length;
            result.details.winRate = (winRate * 100).toFixed(1) + '%';

            if (winRate > 0.95 && history.length >= 10) {
                result.passed = false;
                result.score = 25;
                result.warning = `${(winRate * 100).toFixed(0)}% win rate - abnormally high`;
                result.details.suspiciousWinRate = true;
            }

            // Rapid submissions
            const recentCount = history.filter(h => {
                const time = new Date(h.created_at);
                return (now - time) < 60 * 60 * 1000;
            }).length;

            result.details.recentSubmissions = recentCount;

            if (recentCount >= 5) {
                result.passed = false;
                result.score = 20;
                result.warning = `${recentCount} submissions in the last hour - unusually high frequency`;
                result.details.rapidFireSubmissions = true;
            }

        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }

        return result;
    }

    async crossReferenceOpponent(matchData) {
        const result = { passed: true, warning: null, details: {} };

        try {
            const { data: opponentSubmission } = await this.supabase
                .from('match_results')
                .select('score, created_at')
                .eq('match_id', matchData.matchId)
                .neq('user_id', matchData.userId)
                .single();

            if (!opponentSubmission) {
                result.details.noOpponentSubmission = true;
                return result;
            }

            result.details.opponentSubmitted = true;

            if (matchData.score && opponentSubmission.score) {
                const [userScore, opponentScoreFromUser] = matchData.score.split('-').map(Number);
                const [opponentScore, userScoreFromOpponent] = opponentSubmission.score.split('-').map(Number);

                const scoresMatch = 
                    userScore === userScoreFromOpponent && 
                    opponentScoreFromUser === opponentScore;

                result.details.scoresMatch = scoresMatch;

                if (!scoresMatch) {
                    result.passed = false;
                    result.score = 40;
                    result.critical = true;
                    result.warning = 'Score mismatch with opponent';
                    result.details.userClaimed = matchData.score;
                    result.details.opponentClaimed = opponentSubmission.score;
                }
            }

        } catch (err) {
            result.passed = true;
            result.details.error = err.message;
        }

        return result;
    }

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
                warning: hasNumbers ? null : 'No numbers found in image',
                details: { 
                    hasNumbers, 
                    ocrConfidence: Math.round(confidence), 
                    textLength: text.trim().length 
                }
            };
        } catch (err) {
            return { passed: true, warning: null, details: { error: err.message } };
        }
    }

    async checkMatchContext(imageBuffer, matchData) {
        // eFootball results screen shows TEAM NAMES, not usernames.
        // e.g. "FC Barcelona 1 - 5 MRK FC" — the player's username "chela"
        // will never appear. We must check team names primarily.
        const hasTeamNames = matchData.creatorTeam || matchData.joinerTeam;
        if (!hasTeamNames && !matchData.opponentUsername) {
            return { passed: true, warning: null, details: { skipped: 'no context' } };
        }

        try {
            const worker = await getTesseractWorker();
            await worker.setParameters({ tessedit_char_whitelist: '' });

            const preprocessed = await sharp(imageBuffer)
                .resize(1920, 1080, { fit: 'inside' })
                .sharpen()
                .normalize()
                .toBuffer();

            const { data: { text } } = await worker.recognize(preprocessed);
            await worker.setParameters({ tessedit_char_whitelist: '0123456789-: ' });

            const rawText = text.toLowerCase();
            const result = { passed: true, warning: null, details: { rawText: rawText.substring(0, 200) } };

            // Primary check: look for team names (what actually shows on screen)
            const teamNames = [matchData.creatorTeam, matchData.joinerTeam].filter(Boolean);
            let teamFound = false;
            for (const team of teamNames) {
                const teamLower = team.toLowerCase();
                // Check full name OR first meaningful word (≥4 chars) of team name
                const firstWord = teamLower.split(/\s+/).find(w => w.length >= 4) || teamLower;
                if (rawText.includes(teamLower) || rawText.includes(firstWord)) {
                    teamFound = true;
                    result.details.teamFound = team;
                    break;
                }
            }

            if (teamFound) {
                result.details.contextVerified = 'team_name';
                return result; // strong signal — pass
            }

            // Fallback: check username (some screens may show it)
            if (matchData.opponentUsername) {
                const opponentName = matchData.opponentUsername.toLowerCase();
                const stub = opponentName.substring(0, Math.min(4, opponentName.length));
                if (rawText.includes(opponentName) || (stub.length >= 4 && rawText.includes(stub))) {
                    result.details.contextVerified = 'username';
                    return result;
                }
            }

            // Neither team name nor username found — only a soft warning, low score.
            // OCR on game screenshots is unreliable and fonts can confuse Tesseract.
            result.passed = false;
            result.score = 15; // reduced from 30 — OCR misses are common
            result.details.foundPartialUsername = false;
            result.warning = teamNames.length > 0
                ? `Team names not found in screenshot — please ensure the Full Time results screen is shown`
                : `Opponent not found in screenshot`;

            return result;
        } catch (err) {
            return { passed: true, warning: null, details: { error: err.message } };
        }
    }

    async generatePerceptualHashes(imageBuffer) {
        const image = sharp(imageBuffer);
        
        const standard = await image
            .resize(32, 32, { fit: 'fill' })
            .grayscale()
            .raw()
            .toBuffer();

        const rotated = await sharp(imageBuffer)
            .rotate(90)
            .resize(32, 32, { fit: 'fill' })
            .grayscale()
            .raw()
            .toBuffer();

        const { width, height } = await image.metadata();
        const cropped = await sharp(imageBuffer)
            .extract({ 
                left: Math.floor(width * 0.1), 
                top: Math.floor(height * 0.1), 
                width: Math.floor(width * 0.8), 
                height: Math.floor(height * 0.8) 
            })
            .resize(32, 32, { fit: 'fill' })
            .grayscale()
            .raw()
            .toBuffer();

        return {
            standard: crypto.createHash('sha256').update(standard).digest('hex'),
            rotated: crypto.createHash('sha256').update(rotated).digest('hex'),
            cropped: crypto.createHash('sha256').update(cropped).digest('hex')
        };
    }

    comparePerceptualHashes(hash1, hash2) {
        const similarities = [];

        for (const key of ['standard', 'rotated', 'cropped']) {
            if (hash1[key] && hash2[key]) {
                const sim = this.hammingDistance(hash1[key], hash2[key]);
                similarities.push(sim);
            }
        }

        return similarities.length > 0 ? Math.max(...similarities) : 0;
    }

    hammingDistance(hash1, hash2) {
        if (hash1 === hash2) return 1.0;
        
        let differences = 0;
        const len = Math.min(hash1.length, hash2.length);
        
        for (let i = 0; i < len; i++) {
            if (hash1[i] !== hash2[i]) differences++;
        }
        
        return 1 - (differences / len);
    }

    async extractScoreWithConfidence(imageBuffer) {
        try {
            // Use full-text worker (no char whitelist) so team names are readable
            const worker = await getTesseractWorker();
            await worker.setParameters({ tessedit_char_whitelist: '' });

            const preprocessed = await sharp(imageBuffer)
                .resize(1920, 1080, { fit: 'inside' })
                .sharpen()
                .normalize()
                .toBuffer();

            const { data: { text, confidence } } = await worker.recognize(preprocessed);

            // Restore whitelist for other checks
            await worker.setParameters({ tessedit_char_whitelist: '0123456789-: ' });

            const patterns = [
                // "1-5" or "1:5" directly
                /(\d+)\s*[-:]\s*(\d+)/,
                // "FC Barcelona 1 ... 5 MRK FC" — score surrounded by team-name words
                /[A-Za-z]\s+(\d{1,2})\s+[^\d]*\s+(\d{1,2})\s+[A-Za-z]/,
                // "1 5" on same line (eFootball big scoreboard)
                /^\s*(\d{1,2})\s+(\d{1,2})\s*$/m,
                /HOME\s+(\d+).*AWAY\s+(\d+)/i,
            ];

            let score1, score2;
            for (const pattern of patterns) {
                const match = text.match(pattern);
                if (match) {
                    const s1 = parseInt(match[1]);
                    const s2 = parseInt(match[2]);
                    // Sanity: football scores are 0-20
                    if (s1 <= 20 && s2 <= 20) {
                        score1 = s1;
                        score2 = s2;
                        break;
                    }
                }
            }

            return {
                score1,
                score2,
                confidence,
                rawText: text,
                isValid: score1 !== undefined && score2 !== undefined && confidence > 50
            };
        } catch (err) {
            console.error('OCR extraction failed:', err);
            return { 
                score1: null, 
                score2: null, 
                confidence: 0, 
                isValid: false, 
                error: err.message 
            };
        }
    }
}

module.exports = SimplifiedAdvancedVerifier;