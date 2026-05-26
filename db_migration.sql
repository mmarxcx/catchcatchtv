-- ============================================================
-- CatchCatchTV — Database Migration
-- Adds cam_username and cam_password columns to the cameras table.
--
-- Run this ONCE against your existing database before starting
-- the updated app. It is safe to run on a live database — it
-- only adds columns and never removes or changes existing data.
-- ============================================================

-- ── SQLite (local development) ───────────────────────────────
-- Run with:  sqlite3 your_database.db < db_migration.sql
-- Or open the DB in DB Browser for SQLite and paste each line.

ALTER TABLE cameras ADD COLUMN cam_username VARCHAR(128) DEFAULT '';
ALTER TABLE cameras ADD COLUMN cam_password VARCHAR(256) DEFAULT '';


-- ── PostgreSQL (Railway / Render / any hosted DB) ────────────
-- Comment out the SQLite lines above and uncomment these instead.
-- Run with:  psql $DATABASE_URL < db_migration.sql

-- ALTER TABLE cameras ADD COLUMN IF NOT EXISTS cam_username VARCHAR(128) DEFAULT '';
-- ALTER TABLE cameras ADD COLUMN IF NOT EXISTS cam_password VARCHAR(256) DEFAULT '';
