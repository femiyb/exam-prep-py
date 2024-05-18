from sqlalchemy import text
from app import app, db

# Create a new application context
with app.app_context():
    # Add the new column to the existing table
    with db.engine.connect() as connection:
        connection.execute(text('ALTER TABLE user ADD COLUMN reset_token VARCHAR(200)'))
    print("Database migration completed!")
