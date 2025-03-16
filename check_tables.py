import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    # Connect to database
    connection = mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'iris_chat')
    )

    if connection.is_connected():
        cursor = connection.cursor()
        
        # Get list of tables
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        
        print("\nExisting tables:")
        for table in tables:
            print(f"- {table[0]}")
            
            # Show table structure
            cursor.execute(f"DESCRIBE {table[0]}")
            columns = cursor.fetchall()
            print("  Columns:")
            for column in columns:
                print(f"    {column[0]}: {column[1]}")
            print()
            
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'connection' in locals() and connection.is_connected():
        cursor.close()
        connection.close() 