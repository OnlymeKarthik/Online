from app import app, db
import sqlite3

def migrate_database():
    with app.app_context():
        # Connect to the database
        conn = sqlite3.connect('instance/voting.db')
        cursor = conn.cursor()
        
        # Check if the column exists
        cursor.execute("PRAGMA table_info(user)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add the column if it doesn't exist
        if 'is_email_verified' not in columns:
            print("Adding is_email_verified column to User table...")
            cursor.execute("ALTER TABLE user ADD COLUMN is_email_verified BOOLEAN DEFAULT 0")
            conn.commit()
            print("Column added successfully!")
        else:
            print("Column already exists.")
        
        # Close the connection
        conn.close()

if __name__ == "__main__":
    migrate_database() 