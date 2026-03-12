# Refactoring TODO List

## Phase 1: Create Route Modules
- [ ] 1. routes/helpers.js - Shared utilities (normalizePhone, validateEFootballCode, etc.)
- [ ] 2. routes/auth.js - Authentication routes (/auth/signup, /auth/login)
- [ ] 3. routes/profile.js - Profile routes (/profile, /profile/team)
- [ ] 4. routes/wallet.js - Wallet routes (/wallet/balance, /wallet/deposit, /wallet/deposit/status)
- [ ] 5. routes/friends.js - All /friends/* routes
- [ ] 6. routes/admin.js - All /admin/* routes
- [ ] 7. routes/notifications.js - Notification routes
- [ ] 8. routes/tournaments.js - Tournament routes

## Phase 2: Background Jobs
- [ ] 9. jobs/matchJobs.js - All background timers from app.js

## Phase 3: Database Schema
- [ ] 10. migration.sql - Complete database schema for Supabase

## Phase 4: Lean Entry Point
- [ ] 11. app.js - Refactor to ~200 lines using route modules

## Phase 5: Cleanup
- [ ] 12. Update vercel.json if needed
- [ ] 13. Test the refactored application

