from database import Database
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    logging.info("Starting database initialization...")
    
    try:
        # Create database instance
        db = Database()
        
        # Force recreation of tables
        logging.info("Recreating tables...")
        if db.create_tables():
            logging.info("Tables created successfully!")
        else:
            logging.error("Failed to create tables")
            
    except Exception as e:
        logging.error(f"Error: {str(e)}")
    finally:
        if 'db' in locals():
            db.close()
            logging.info("Database connection closed")

if __name__ == "__main__":
    main() 