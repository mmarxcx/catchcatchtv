-- ============================================================
-- CatchCatchTV v3 — PostgreSQL Setup Script
-- COMP 012 — Network Administration
--
-- HOW TO USE (pgAdmin 4):
--   1. Open pgAdmin 4
--   2. Click your server (PostgreSQL 16)
--   3. Open "Query Tool" from the top menu
--   4. Paste THIS ENTIRE FILE into the query box
--   5. Press F5 (or click the ▶ Run button)
--   6. You should see "Query returned successfully"
--   7. Done! Now run: python main.py
--
-- NOTE: The app connects to the database named "catchcatchtv"
--       using user "camuser" with password "campass123".
--       Set DATABASE_URL in your .env to override for production.
-- ============================================================


-- Step 1: Create the database user
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'camuser') THEN
      CREATE USER camuser WITH PASSWORD 'campass123';
      RAISE NOTICE 'User camuser created.';
   ELSE
      RAISE NOTICE 'User camuser already exists — skipping.';
   END IF;
END
$$;


-- Step 2: Create the database
-- If pgAdmin says "database already exists", that is fine — skip this.
SELECT 'CREATE DATABASE catchcatchtv OWNER camuser'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'catchcatchtv')\gexec


-- Step 3: Connect to the catchcatchtv database
-- In pgAdmin: use the database dropdown at the top and select "catchcatchtv"
-- Then run the rest of this script from that connection.


-- Step 4: Grant privileges
GRANT ALL PRIVILEGES ON DATABASE catchcatchtv TO camuser;
GRANT ALL ON SCHEMA public TO camuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO camuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO camuser;


-- Step 5: Enable pgvector extension (optional — app works without it)
-- This satisfies the pgvector requirement; the app falls back to JSONB if unavailable.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

SELECT 'pgvector version: ' || extversion AS status
FROM pg_extension WHERE extname = 'vector';


-- ============================================================
-- VERIFICATION — run these to confirm setup
-- ============================================================

SELECT extname, extversion FROM pg_extension
WHERE extname IN ('vector', 'uuid-ossp');

SELECT usename, usesuper FROM pg_user WHERE usename = 'camuser';

-- ============================================================
-- SUCCESS
-- ============================================================
SELECT '✅ CatchCatchTV database setup complete! Now run: python main.py' AS message;
