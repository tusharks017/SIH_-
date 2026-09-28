import sys
import os

# Add root directory to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

# Initialize database schema if running in Vercel serverless environment
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print("Database initialization note:", e)

# Export WSGI app for Vercel
app = app
