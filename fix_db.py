from app import create_app, db
from sqlalchemy import text

app = create_app()

with app.app_context():
    migrations = [
        ("users",   "admin_webhook", "VARCHAR(512)"),
        ("cameras", "audio_url",     "VARCHAR(512)"),
    ]
    for table, column, col_type in migrations:
        try:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};"))
            db.session.commit()
            print(f"OK: Added '{column}' column to '{table}'.")
        except Exception as e:
            db.session.rollback()
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                print(f"-- Skipped '{column}' on '{table}': column already exists.")
            else:
                print(f"ERROR on '{column}' in '{table}': {e}")

print("\nDone. You can run this script again safely -- it skips existing columns.")
