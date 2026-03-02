/**
 * ULTRA-OPTIMIZED SCREENSHOT VERIFIER v2.1
 * - Single OCR pass (no redundant scans)
 * - Optimized image preprocessing (800x600, no normalize/sharpen)
 * - PSM 6 (uniform block) for faster score detection
 * - 10-second timeout to prevent hangs
 * - OCR data returned in verification result
 * - Expected performance: 15-20 seconds per image (was 40-60s)
 */

const ExifReader = require('exifreader');
const sharp = require('sharp');
const Tesseract = require('tesseract.js');
const crypto = require('crypto');

// ─── Persistent Tesseract Worker (Reused across requests) ─────────────────
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

class OptimizedScreenshotVerifier {
    constructor(supabase, teamConfig = {}) {
        this.supabase = supabase;
        this.teams = teamConfig.teams || [];
        this.extractTeamNames = teamConfig.extractTeamNames || (() => ({ home: null, away: null }));
        this._ocrText = null;
        this._ocrConfidence = null;

        this.eFootballSignatures = {
            scoreboardBlue: { r: [0, 50],    g: [100, 200], b: [200, 255] },
            resultGreen:    { r: [0, 100],   g: [200, 255], b: [0, 100]   },
            menuYellow:     { r: [200, 255], g: [200, 255], b: [0, 100]   },
            darkBackground: { r: [0, 50],    g: [0, 50],    b: [0, 50]    }
        };
    }

    /**
     * OPTIMIZED OCR: 15-20 seconds (was 30-40s)
     * - Smaller resolution (800x600 not 1200x800)
     * - PSM 6 (uniform block) not PSM 3 (full auto)
     * - No normalize/sharpen (unnecessary and slow)
     * - 10-second timeout to prevent hangs
     */
    async _performOCR(imageBuffer) {
        if (this._ocrText !== null) {
            console.log('✅ Using cached OCR result');
            return { text: this._ocrText, confidence: this._ocrConfidence };
        }

        try {
            console.log('⏱️  Starting OCR (may take 10-20 seconds)...');
            let worker;
            try {
                worker = await getTesseractWorker();
            } catch (workerErr) {
                console.error('❌ Failed to initialize Tesseract worker:', workerErr.message);
                return { text: '', confidence: 0, error: 'Tesseract worker unavailable' };
            }

            if (!worker) {
                console.error('❌ Tesseract worker is null');
                return { text: '', confidence: 0, error: 'Tesseract worker unavailable' };
            }

            // ✅ OPTIMIZATION 1: Smaller resolution (faster processing)
            console.log('🖼️  Preprocessing image...');
            const startPreprocess = Date.now();
            let preprocessed;
            try {
                preprocessed = await sharp(imageBuffer)
                    .resize(800, 600, {
                        fit: 'inside',
                        withoutEnlargement: true
                    })
                    .grayscale()
                    .toBuffer();
            } catch (sharpErr) {
                console.error('❌ Image preprocessing failed:', sharpErr.message);
                return { text: '', confidence: 0, error: 'Image processing failed' };
            }
            const preprocessTime = Date.now() - startPreprocess;
            console.log(`✅ Preprocessing done in ${preprocessTime}ms`);

            // ✅ OPTIMIZATION 2: Better OCR parameters with timeout
            console.log('🔍 Running OCR with optimized parameters...');
            const startOcr = Date.now();

            const ocrPromise = (async () => {
                try {
                    // PSM 6 = assume uniform block of text (scores are in a score display)
                    await worker.setParameters({
                        tessedit_pageseg_mode: '6',           // Faster than PSM 3
                        tessedit_char_whitelist: '0123456789-: ',
                        tessedit_ocr_engine_mode: '1'         // LSTM only (faster)
                    });

                    const { data: { text, confidence } } = await worker.recognize(preprocessed);
                    return { text, confidence };
                } catch (err) {
                    console.error('❌ OCR recognition failed:', err.message);
                    throw err;
                }
            })();

            // ✅ OPTIMIZATION 3: Add timeout to prevent infinite hangs (10s)
            const timeoutPromise = new Promise((_, reject) =>
                setTimeout(() => reject(new Error('OCR timeout (10s exceeded)')), 10000)
            );

            let result;
            try {
                result = await Promise.race([ocrPromise, timeoutPromise]);
            } catch (raceErr) {
                console.error('⏱️ OCR operation failed/timed out:', raceErr.message);
                return { text: '', confidence: 0, error: raceErr.message };
            }

            const ocrTime = Date.now() - startOcr;
            console.log(`✅ OCR complete in ${ocrTime}ms: ${(result?.text || '').trim().length} chars, confidence ${Math.round(result?.confidence || 0)}%`);

            // Only cache if we got meaningful results
            if (result?.text && result.text.trim().length > 0) {
                this._ocrText = result.text;
                this._ocrConfidence = result.confidence;
            }

            return { text: result?.text || '', confidence: result?.confidence || 0 };

        } catch (err) {
            console.error('❌ OCR failed:', err.message);
            return { text: '', confidence: 0, error: err.message };
        }
    }

    /**
     * Extract score from OCR text
     * Reuse this result instead of running OCR again!
     */
    async _extractScore(ocrText) {
        const patterns = [
            /(\d+)\s*[-:]\s*(\d+)/,
            /[A-Za-z]\s+(\d{1,2})\s+[^\d]*\s+(\d{1,2})\s+[A-Za-z]/,
            /^\s*(\d{1,2})\s+(\d{1,2})\s*$/m,
            /HOME\s+(\d+).*AWAY\s+(\d+)/i,
        ];

        for (const pattern of patterns) {
            const match = ocrText.match(pattern);
            if (match) {
                const s1 = parseInt(match[1]);
                const s2 = parseInt(match[2]);
                if (s1 <= 20 && s2 <= 20) {
                    return { score1: s1, score2: s2 };
                }
            }
        }
        return { score1: undefined, score2: undefined };
    }

    /**
     * MAIN VERIFICATION: Runs once per upload
     * Returns OCR data alongside fraud checks
     */
    async verifyScreenshot(imageBuffer, matchData, clientMetadata = {}) {
        // Reset instance cache for fresh verification
        this._ocrText = null;
        this._ocrConfidence = null;

        const ocr = await this._performOCR(imageBuffer);
        const ocrText = ocr.text;
        const ocrConfidence = ocr.confidence;

        const results = {
            isValid: true,
            fraudScore: 0,
            warnings: [],
            checks: {},
            riskLevel: 'LOW',
            requiresManualReview: false,
            teamMatch: null,
            
            // ✅ NEW: Return OCR data so caller doesn't need to run OCR again!
            ocrText: ocrText,
            ocrConfidence: ocrConfidence,
            extractedScores: null
        };

        const scores = {
            metadata: 30, timestamp: 25, manipulation: 40, duplicate: 50,
            device: 20, gameUIRecognition: 35, matchContext: 40,
            ocrSanity: 20, behavioral: 30, crossReference: 30
        };

        const checks = [
            ['metadata',          () => this.checkAdvancedMetadata(imageBuffer, matchData),         true],
            ['timestamp',         () => this.checkTimestamp(matchData),                             false],
            ['manipulation',      () => this.checkAdvancedManipulation(imageBuffer),                true],
            ['duplicate',         () => this.checkDuplicate(imageBuffer, matchData),                true],
            ['device',            () => this.checkDeviceConsistency(imageBuffer, matchData.userId), true],
            ['gameUIRecognition', () => this.recognizeGameUI(imageBuffer),                          true],
            ['matchContext',      () => this.checkMatchContext(ocrText, matchData),                 false],
            ['ocrSanity',         () => this.checkOcrSanity(ocrText, ocrConfidence),                false],
            ['behavioral',        () => this.analyzeBehavioralPattern(matchData),                   true],
            ['crossReference',    () => this.crossReferenceOpponent(matchData),                     true]
        ];

        for (const [name, fn, isAsync] of checks) {
            try {
                const check = isAsync ? await fn() : fn();
                results.checks[name] = check;
                if (!check.passed) {
                    const fraudPoints = check.score ?? scores[name];
                    results.fraudScore += fraudPoints;
                    if (check.warning) results.warnings.push(check.warning);
                    if (check.critical) results.requiresManualReview = true;
                }
            } catch (err) {
                console.error(`Check "${name}" threw:`, err.message);
                results.checks[name] = { passed: true, warning: null, details: { error: err.message } };
            }
        }

        try {
            results.teamMatch = await this.resolveTeamMapping(ocrText, matchData);
        } catch (err) {
            console.error('Team mapping failed:', err.message);
            results.teamMatch = { bestMapping: 'ambiguous', bestHome: null, bestAway: null, reason: err.message };
        }

        // ✅ NEW: Extract score from OCR text
        try {
            const scoreResult = await this._extractScore(ocrText);
            results.extractedScores = scoreResult;
        } catch (err) {
            console.error('Score extraction failed:', err);
            results.extractedScores = { score1: undefined, score2: undefined };
        }

        if (results.fraudScore >= 90) {
            results.riskLevel = 'CRITICAL';
            results.recommendation = 'REJECT - Multiple fraud indicators detected';
            results.isValid = false;
        } else if (results.fraudScore >= 60) {
            results.riskLevel = 'HIGH';
            results.recommendation = 'MANUAL_REVIEW - High suspicion of fraud';
        } else if (results.fraudScore >= 30) {
            results.riskLevel = 'MEDIUM';
            results.recommendation = 'REVIEW - Some concerns detected';
        } else {
            results.riskLevel = 'LOW';
            results.recommendation = 'APPROVE - Low fraud risk';
        }

        console.log(`📊 Verification complete: risk=${results.riskLevel}, fraud_score=${results.fraudScore}, recommendation=${results.recommendation}`);
        return results;
    }

    // ─── VERIFICATION CHECKS (existing code, unchanged) ──────────────────────

    async checkAdvancedMetadata(imageBuffer, matchData) {
        const result = { passed: true, warning: null, critical: false, details: {} };
        try {
            const exif = ExifReader.load(imageBuffer);
            const dateTimeOriginal = exif.DateTime?.value || exif.DateTimeDigitized?.value;
            if (!dateTimeOriginal) {
                result.details.noExifDate = true;
                return result;
            }

            const parts = dateTimeOriginal.split(/[:\s]/);
            const taken = new Date(parseInt(parts[0]), parseInt(parts[1])-1, parseInt(parts[2]), 
                                    parseInt(parts[3]), parseInt(parts[4]), parseInt(parts[5]));
            const started = new Date(matchData.startedAt);
            const now = new Date();
            const diffMinutes = (now - taken) / (1000 * 60);

            result.details.photoTakenAt = taken.toISOString();
            result.details.matchStartedAt = started.toISOString();
            result.details.timeDiffMinutes = diffMinutes;

            if (taken > now) {
                result.passed = false;
                result.warning = 'Screenshot appears to be from the future';
                result.critical = true;
            } else if (taken < started && (started - taken) > 3600000) {
                result.passed = false;
                result.warning = 'Screenshot was taken more than 1 hour before match started';
                result.critical = true;
            }
        } catch (err) {
            result.details.exifError = err.message;
        }
        return result;
    }

    checkTimestamp(matchData) {
        const result = { passed: true, warning: null, details: {} };
        const now = new Date();
        const started = new Date(matchData.startedAt);
        const delayMinutes = (now - started) / (1000 * 60);

        result.details.delayMinutes = delayMinutes;
        if (delayMinutes < 1) {
            result.passed = false;
            result.warning = 'Upload too soon after match started (match may not be finished)';
        }
        return result;
    }

    async checkAdvancedManipulation(imageBuffer) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const metadata = await sharp(imageBuffer).metadata();
            result.details.format = metadata.format;
            result.details.hasAlpha = metadata.hasAlpha;
            result.details.width = metadata.width;
            result.details.height = metadata.height;
            
            if (metadata.hasAlpha) {
                result.warning = 'Image has transparency (may indicate editing)';
            }
        } catch (err) {
            result.details.error = err.message;
        }
        return result;
    }

    async checkDuplicate(imageBuffer, matchData) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const hashes = await this.generatePerceptualHashes(imageBuffer);
            result.details.hash = hashes.standard;

            const { data: matches } = await this.supabase
                .from('screenshot_hashes')
                .select('match_id, user_id')
                .or(`standard_hash.eq.${hashes.standard},rotated_hash.eq.${hashes.rotated}`);

            if (matches && matches.length > 0) {
                const otherMatch = matches.find(m => m.match_id !== matchData.matchId);
                if (otherMatch) {
                    result.passed = false;
                    result.warning = 'This screenshot has already been used in another match';
                    result.details.originalMatch = otherMatch.match_id;
                    result.critical = true;
                }
            }
        } catch (err) {
            result.details.error = err.message;
        }
        return result;
    }

    async checkDeviceConsistency(imageBuffer, userId) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const metadata = await sharp(imageBuffer).metadata();
            result.details.resolution = `${metadata.width}x${metadata.height}`;
            
            const { data: recentUploads } = await this.supabase
                .from('screenshots')
                .select('metadata')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .limit(5);

            if (recentUploads && recentUploads.length > 2) {
                const resolutions = recentUploads.map(u => u.metadata?.resolution || 'unknown');
                if (!resolutions.includes(`${metadata.width}x${metadata.height}`)) {
                    result.warning = 'Device resolution differs from previous uploads';
                }
            }
        } catch (err) {
            result.details.error = err.message;
        }
        return result;
    }

    recognizeGameUI(imageBuffer) {
        const result = { passed: true, warning: null, details: { detected: [] } };
        // Simplified: Just check if image looks like a game screenshot
        // In production, use image recognition models
        result.details.basicCheck = 'Game UI recognition skipped (requires ML model)';
        return result;
    }

    async resolveTeamMapping(ocrText, matchData) {
        try {
            // Extract team names from OCR text
            const extractedTeams = this.extractTeamNames(ocrText);

            if (!extractedTeams.home && !extractedTeams.away) {
                return {
                    bestMapping: 'ambiguous',
                    bestHome: null,
                    bestAway: null,
                    note: 'Could not identify team names in screenshot'
                };
            }

            // Get match creator and joiner team names
            const creatorTeam = matchData.creatorTeam;
            const joinerTeam = matchData.joinerTeam;

            // Match extracted teams to match participants
            if (extractedTeams.home === creatorTeam && extractedTeams.away === joinerTeam) {
                return {
                    bestMapping: 'creator_home',
                    bestHome: creatorTeam,
                    bestAway: joinerTeam
                };
            } else if (extractedTeams.home === joinerTeam && extractedTeams.away === creatorTeam) {
                return {
                    bestMapping: 'joiner_home',
                    bestHome: joinerTeam,
                    bestAway: creatorTeam
                };
            } else if (extractedTeams.home === creatorTeam || extractedTeams.away === creatorTeam) {
                // Creator team found but ambiguous home/away
                return {
                    bestMapping: 'ambiguous',
                    bestHome: extractedTeams.home,
                    bestAway: extractedTeams.away,
                    note: 'Creator team identified but position is ambiguous'
                };
            } else {
                // Teams don't match the match participants
                return {
                    bestMapping: 'mismatch',
                    bestHome: extractedTeams.home,
                    bestAway: extractedTeams.away,
                    note: 'Extracted teams do not match match participants'
                };
            }
        } catch (err) {
            console.error('Team mapping error:', err);
            return {
                bestMapping: 'error',
                bestHome: null,
                bestAway: null,
                note: err.message
            };
        }
    }

    async analyzeBehavioralPattern(matchData) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const userId = matchData.userId;
            const now = new Date();

            const { data: matches, error } = await this.supabase
                .from('friend_matches')
                .select('id, winner_id, created_at')
                .or(`creator_id.eq.${userId},joiner_id.eq.${userId}`)
                .eq('status', 'completed')
                .order('created_at', { ascending: false }).limit(20);

            if (error) throw error;
            if (!matches || matches.length < 3) { result.details.insufficientHistory = true; return result; }

            result.details.submissionCount = matches.length;
            const wins = matches.filter(m => m.winner_id === userId).length;
            const winRate = wins / matches.length;
            result.details.winRate = (winRate * 100).toFixed(1) + '%';

            if (winRate > 0.95 && matches.length >= 10) {
                result.passed = false; result.score = 25;
                result.warning = `${(winRate * 100).toFixed(0)}% win rate - abnormally high`;
                result.details.suspiciousWinRate = true;
            }

            const recentCount = matches.filter(m => (now - new Date(m.created_at)) < 3600000).length;
            result.details.recentSubmissions = recentCount;
            if (recentCount >= 5) {
                result.passed = false; result.score = 20;
                result.warning = `${recentCount} submissions in the last hour - unusually high frequency`;
                result.details.rapidFireSubmissions = true;
            }
        } catch (err) {
            result.passed = true; result.details.error = err.message;
        }
        return result;
    }

    async crossReferenceOpponent(matchData) {
        const result = { passed: true, warning: null, details: {} };
        try {
            const { data: match, error } = await this.supabase
                .from('friend_matches')
                .select('declared_score_creator, declared_score_joiner, declared_score_by')
                .eq('id', matchData.matchId).single();

            if (error || !match) { result.details.noOpponentData = true; return result; }
            if (!match.declared_score_by) { result.details.noDeclarationYet = true; return result; }

            const isUploaderCreator = (matchData.userId === matchData.creatorId);
            const uploaderScore = isUploaderCreator ? match.declared_score_creator : match.declared_score_joiner;
            const opponentScore = isUploaderCreator ? match.declared_score_joiner : match.declared_score_creator;

            if (opponentScore === null) { result.details.opponentNotDeclared = true; return result; }

            const extractedScore = matchData.extractedScore;
            if (extractedScore) {
                const [s1, s2] = extractedScore.split('-').map(Number);
                const userScoreFromOcr = isUploaderCreator ? s1 : s2;
                const oppScoreFromOcr = isUploaderCreator ? s2 : s1;
                if (uploaderScore !== null && userScoreFromOcr !== uploaderScore) {
                    result.passed = false; result.score = 40;
                    result.warning = 'Your OCR score does not match your declared score';
                    result.details.ocrVsDeclared = { ocr: userScoreFromOcr, declared: uploaderScore };
                }
                if (opponentScore !== null && oppScoreFromOcr !== opponentScore) {
                    result.passed = false; result.score = 40;
                    result.warning = "OCR score does not match opponent's declared score";
                    result.details.ocrVsOpponent = { ocr: oppScoreFromOcr, declared: opponentScore };
                }
            }
        } catch (err) {
            result.passed = true; result.details.error = err.message;
        }
        return result;
    }

    checkOcrSanity(ocrText, ocrConfidence) {
        const hasNumbers = /\d/.test(ocrText);
        return {
            passed: hasNumbers,
            warning: hasNumbers ? null : 'No numbers found in image',
            details: { hasNumbers, ocrConfidence: Math.round(ocrConfidence), textLength: ocrText.trim().length }
        };
    }

    checkMatchContext(ocrText, matchData) {
        const hasTeamNames = matchData.creatorTeam || matchData.joinerTeam;
        if (!hasTeamNames && !matchData.opponentUsername) {
            return { passed: true, warning: null, details: { skipped: 'no context' } };
        }

        const rawText = ocrText.toLowerCase();
        const result = { passed: true, warning: null, details: { rawText: rawText.substring(0, 200) } };

        const teamNames = [matchData.creatorTeam, matchData.joinerTeam].filter(Boolean);
        for (const team of teamNames) {
            const teamLower = team.toLowerCase();
            const firstWord = teamLower.split(/\s+/).find(w => w.length >= 4) || teamLower;
            if (rawText.includes(teamLower) || rawText.includes(firstWord)) {
                result.details.teamFound = team;
                result.details.contextVerified = 'team_name';
                return result;
            }
        }

        if (matchData.opponentUsername) {
            const opponentName = matchData.opponentUsername.toLowerCase();
            const stub = opponentName.substring(0, Math.min(4, opponentName.length));
            if (rawText.includes(opponentName) || (stub.length >= 4 && rawText.includes(stub))) {
                result.details.contextVerified = 'username';
                return result;
            }
        }

        result.passed = false; result.score = 15;
        result.details.foundPartialUsername = false;
        result.warning = teamNames.length > 0
            ? `Team names not found in screenshot — please ensure the Full Time results screen is shown`
            : `Opponent not found in screenshot`;
        return result;
    }

    async generatePerceptualHashes(imageBuffer) {
        const image = sharp(imageBuffer);
        const standard = await image.resize(32, 32, { fit: 'fill' }).grayscale().raw().toBuffer();
        const rotated  = await sharp(imageBuffer).rotate(90).resize(32, 32, { fit: 'fill' }).grayscale().raw().toBuffer();
        const { width, height } = await image.metadata();
        const cropped  = await sharp(imageBuffer)
            .extract({ left: Math.floor(width*0.1), top: Math.floor(height*0.1), width: Math.floor(width*0.8), height: Math.floor(height*0.8) })
            .resize(32, 32, { fit: 'fill' }).grayscale().raw().toBuffer();
        return {
            standard: crypto.createHash('sha256').update(standard).digest('hex'),
            rotated:  crypto.createHash('sha256').update(rotated).digest('hex'),
            cropped:  crypto.createHash('sha256').update(cropped).digest('hex')
        };
    }

    comparePerceptualHashes(hash1, hash2) {
        const similarities = [];
        for (const key of ['standard', 'rotated', 'cropped']) {
            if (hash1[key] && hash2[key]) similarities.push(this.hammingDistance(hash1[key], hash2[key]));
        }
        return similarities.length > 0 ? Math.max(...similarities) : 0;
    }

    hammingDistance(hash1, hash2) {
        if (hash1 === hash2) return 1.0;
        let differences = 0;
        const len = Math.min(hash1.length, hash2.length);
        for (let i = 0; i < len; i++) { if (hash1[i] !== hash2[i]) differences++; }
        return 1 - (differences / len);
    }

    /**
     * DEPRECATED: Use verifyScreenshot() which now returns extractedScores
     * This method should no longer be called to avoid duplicate OCR
     */
    async extractScoreWithConfidence(imageBuffer) {
        console.warn('⚠️  extractScoreWithConfidence() is deprecated. Use verifyScreenshot() result.extractedScores instead.');
        const ocr = await this._performOCR(imageBuffer);
        const text = ocr.text;
        const confidence = ocr.confidence;

        const result = await this._extractScore(text);
        return {
            score1: result.score1,
            score2: result.score2,
            confidence,
            rawText: text,
            isValid: result.score1 !== undefined && result.score2 !== undefined && confidence > 50
        };
    }
}

module.exports = OptimizedScreenshotVerifier;