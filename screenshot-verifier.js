/**
 * SCREENSHOT VERIFICATION MODULE
 * Multi-layer fraud detection for match result screenshots
 */

const ExifReader = require('exifreader');
const sharp = require('sharp');
const Tesseract = require('tesseract.js');

class ScreenshotVerifier {
    /**
     * @param {Object} supabase - Supabase client instance (admin privileges recommended)
     */
    constructor(supabase) {
        this.supabase = supabase;
    }

    /**
     * Verify screenshot authenticity with multiple checks
     */
    async verifyScreenshot(imageBuffer, matchData) {
        const results = {
            isValid: true,
            fraudScore: 0,
            warnings: [],
            checks: {}
        };

        // Check 1: EXIF Metadata Analysis
        const metadataCheck = await this.checkMetadata(imageBuffer, matchData);
        results.checks.metadata = metadataCheck;
        if (!metadataCheck.passed) {
            results.fraudScore += 30;
            results.warnings.push(metadataCheck.warning);
        }

        // Check 2: Timestamp Validation
        const timestampCheck = this.checkTimestamp(imageBuffer, matchData);
        results.checks.timestamp = timestampCheck;
        if (!timestampCheck.passed) {
            results.fraudScore += 25;
            results.warnings.push(timestampCheck.warning);
        }

        // Check 3: Image Manipulation Detection
        const manipulationCheck = await this.checkManipulation(imageBuffer);
        results.checks.manipulation = manipulationCheck;
        if (!manipulationCheck.passed) {
            results.fraudScore += 35;
            results.warnings.push(manipulationCheck.warning);
        }

        // Check 4: Duplicate Screenshot Detection
        const duplicateCheck = await this.checkDuplicate(imageBuffer, matchData.userId, matchData.matchId);
        results.checks.duplicate = duplicateCheck;
        if (!duplicateCheck.passed) {
            results.fraudScore += 40;
            results.warnings.push(duplicateCheck.warning);
        }

        // Check 5: Resolution & Device Consistency
        const deviceCheck = await this.checkDeviceConsistency(imageBuffer, matchData.userId);
        results.checks.device = deviceCheck;
        if (!deviceCheck.passed) {
            results.fraudScore += 15;
            results.warnings.push(deviceCheck.warning);
        }

        // Final verdict
        results.isValid = results.fraudScore < 50;
        results.confidence = results.isValid ? 'high' : 'low';

        if (results.fraudScore >= 70) {
            results.recommendation = 'REJECT - High fraud probability';
        } else if (results.fraudScore >= 50) {
            results.recommendation = 'MANUAL_REVIEW - Suspicious';
        } else if (results.fraudScore >= 30) {
            results.recommendation = 'ACCEPT_WITH_WARNING';
        } else {
            results.recommendation = 'ACCEPT - Likely authentic';
        }

        return results;
    }

    /**
     * Check 1: EXIF Metadata
     */
    async checkMetadata(imageBuffer, matchData) {
        try {
            const tags = ExifReader.load(imageBuffer);

            const result = {
                passed: true,
                warning: null,
                details: {}
            };

            if (!tags || Object.keys(tags).length < 5) {
                result.passed = false;
                result.warning = 'EXIF metadata missing or stripped (possible edit)';
                return result;
            }

            const dateTime = tags.DateTime?.description ||
                tags.DateTimeOriginal?.description ||
                tags.CreateDate?.description;

            if (dateTime) {
                const photoTime = new Date(dateTime);
                const matchTime = new Date(matchData.startedAt);
                const timeDiffMinutes = Math.abs(photoTime - matchTime) / 60000;

                if (timeDiffMinutes > 60) {
                    result.passed = false;
                    result.warning = `Screenshot timestamp (${photoTime.toLocaleString()}) is ${Math.floor(timeDiffMinutes)} minutes from match time`;
                }

                result.details.photoTime = photoTime;
                result.details.timeDiffMinutes = timeDiffMinutes;
            }

            const software = tags.Software?.description || '';
            const suspiciousSoftware = ['photoshop', 'gimp', 'pixlr', 'canva', 'paint.net'];
            if (suspiciousSoftware.some(s => software.toLowerCase().includes(s))) {
                result.passed = false;
                result.warning = `Image edited with ${software} - potential manipulation`;
                result.details.software = software;
            }

            result.details.device = tags.Model?.description || 'Unknown';
            result.details.make = tags.Make?.description || 'Unknown';

            return result;
        } catch (error) {
            console.error('EXIF metadata check failed:', error);
            return {
                passed: false,
                warning: 'Failed to read EXIF data - possibly corrupted or edited',
                details: { error: error.message }
            };
        }
    }

    /**
     * Check 2: Timestamp Validation
     */
    checkTimestamp(imageBuffer, matchData) {
        const result = {
            passed: true,
            warning: null,
            details: {}
        };

        const now = new Date();
        const matchStart = new Date(matchData.startedAt);
        const maxMatchDuration = 45; // minutes
        const matchEnd = new Date(matchStart.getTime() + maxMatchDuration * 60000);
        const uploadDelay = (now - matchStart) / 60000;

        if (uploadDelay > 120) {
            result.passed = false;
            result.warning = `Screenshot uploaded ${Math.floor(uploadDelay)} minutes after match - too late`;
        }

        result.details.matchStart = matchStart;
        result.details.uploadTime = now;
        result.details.delayMinutes = uploadDelay;

        return result;
    }

    /**
     * Check 3: Image Manipulation Detection
     */
    async checkManipulation(imageBuffer) {
        const result = {
            passed: true,
            warning: null,
            details: {}
        };

        try {
            const image = sharp(imageBuffer);
            const metadata = await image.metadata();

            const fileSize = imageBuffer.length;
            const expectedSize = (metadata.width * metadata.height * 3) / 10;

            if (fileSize < expectedSize * 0.1) {
                result.passed = false;
                result.warning = 'File size too small - possibly re-compressed after editing';
            }

            if (metadata.format === 'jpeg') {
                const stats = await image.stats();
                const channels = stats.channels;
                if (channels.length > 0) {
                    const redMean = channels[0].mean;
                    const greenMean = channels[1].mean;
                    const blueMean = channels[2].mean;

                    const colorImbalance = Math.abs(redMean - greenMean) +
                        Math.abs(greenMean - blueMean) +
                        Math.abs(blueMean - redMean);

                    if (colorImbalance > 200) {
                        result.passed = false;
                        result.warning = 'Unusual color distribution - possible manipulation';
                        result.details.colorImbalance = colorImbalance;
                    }
                }
            }

            result.details.width = metadata.width;
            result.details.height = metadata.height;
            result.details.format = metadata.format;

            const commonResolutions = [
                { w: 1920, h: 1080 },
                { w: 2340, h: 1080 },
                { w: 2400, h: 1080 },
                { w: 1280, h: 720 },
                { w: 1080, h: 1920 },
                { w: 1080, h: 2340 }
            ];

            const hasCommonRes = commonResolutions.some(res =>
                Math.abs(metadata.width - res.w) < 50 &&
                Math.abs(metadata.height - res.h) < 50
            );

            if (!hasCommonRes) {
                result.details.unusualResolution = true;
            }

            return result;
        } catch (error) {
            console.error('Manipulation check failed:', error);
            return {
                passed: false,
                warning: 'Image analysis failed - possibly corrupted',
                details: { error: error.message }
            };
        }
    }

    /**
     * Check 4: Duplicate Screenshot Detection
     */
    async checkDuplicate(imageBuffer, userId, matchId) {
        const result = {
            passed: true,
            warning: null,
            details: {}
        };

        try {
            const hash = await this.generatePerceptualHash(imageBuffer);
            result.details.hash = hash;

            // Query Supabase for existing screenshot with same hash, different user
            const { data: existing, error } = await this.supabase
                .from('screenshot_hashes')
                .select('match_id, user_id')
                .eq('hash', hash)
                .neq('user_id', userId)
                .maybeSingle();

            if (error) throw error;

            if (existing) {
                result.passed = false;
                result.warning = 'Screenshot already used in another match';
                result.details.originalMatch = existing.match_id;
                return result;
            }

            return result;
        } catch (error) {
            console.error('Duplicate check failed:', error);
            return {
                passed: false,
                warning: 'Duplicate detection error',
                details: { error: error.message }
            };
        }
    }

    /**
     * Generate perceptual hash using sharp's built-in method
     */
    async generatePerceptualHash(imageBuffer) {
        try {
            const hash = await sharp(imageBuffer)
                .resize(8, 8, { fit: 'fill' })
                .grayscale()
                .raw()
                .toBuffer()
                .then(buf => {
                    const pixels = Array.from(buf);
                    const avg = pixels.reduce((a, b) => a + b, 0) / pixels.length;
                    return pixels.map(p => (p > avg ? '1' : '0')).join('');
                });
            return hash;
        } catch (error) {
            throw new Error('Failed to generate perceptual hash: ' + error.message);
        }
    }

    /**
     * Check 5: Device Consistency
     */
    async checkDeviceConsistency(imageBuffer, userId) {
        const result = {
            passed: true,
            warning: null,
            details: {}
        };

        try {
            const tags = ExifReader.load(imageBuffer);
            const device = tags.Model?.description || 'Unknown';
            result.details.device = device;

            // Get user's last 10 devices from history
            const { data: history, error } = await this.supabase
                .from('user_screenshot_history')
                .select('device')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .limit(10);

            if (error) throw error;

            if (history && history.length > 0) {
                const freq = {};
                history.forEach(h => freq[h.device] = (freq[h.device] || 0) + 1);
                const mostCommon = Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0];

                if (device !== mostCommon && device !== 'Unknown') {
                    result.passed = false;
                    result.warning = `Screenshot from different device (${device}) than usual (${mostCommon})`;
                }
            }

            return result;
        } catch (error) {
            console.error('Device consistency check failed:', error);
            return {
                passed: true,
                warning: null,
                details: {}
            };
        }
    }

    /**
     * Advanced: OCR-based score extraction with confidence checking
     */
    async extractScoreWithConfidence(imageBuffer) {
        try {
            const preprocessed = await sharp(imageBuffer)
                .resize(1920, 1080, { fit: 'inside' })
                .sharpen()
                .normalize()
                .toBuffer();

            const { data: { text, confidence } } = await Tesseract.recognize(
                preprocessed,
                'eng',
                {
                    logger: m => console.log(m),
                    tessedit_char_whitelist: '0123456789-: '
                }
            );

            const patterns = [
                /(\d+)\s*[-:]\s*(\d+)/,
                /(\d+)\s+(\d+)/,
                /HOME\s+(\d+).*AWAY\s+(\d+)/i,
            ];

            let score1, score2;
            for (const pattern of patterns) {
                const match = text.match(pattern);
                if (match) {
                    score1 = parseInt(match[1]);
                    score2 = parseInt(match[2]);
                    break;
                }
            }

            return {
                score1,
                score2,
                confidence,
                rawText: text,
                isValid: score1 !== undefined && score2 !== undefined && confidence > 70
            };
        } catch (error) {
            console.error('OCR extraction failed:', error);
            return {
                score1: null,
                score2: null,
                confidence: 0,
                isValid: false,
                error: error.message
            };
        }
    }
}

module.exports = ScreenshotVerifier;