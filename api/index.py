import sys
import os

# Add root directory to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, run_db_migrations

# Initialize and migrate database schema for Vercel serverless environment
try:
    run_db_migrations()
except Exception as e:
    print("Cold start migration note:", e)

# Export WSGI app for Vercel
app = app
