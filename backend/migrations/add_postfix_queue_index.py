from sqlalchemy import create_engine, text
from backend.app.config import settings
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def upgrade():
    """Add index to postfix_logs.queue_id for better performance"""
    engine = create_engine(settings.database_url)
    
    with engine.connect() as conn:
        try:
            # Check if index exists
            result = conn.execute(text("""
                SELECT COUNT(*) 
                FROM information_schema.statistics 
                WHERE table_schema = DATABASE()
                AND table_name = 'postfix_logs' 
                AND index_name = 'idx_postfix_queue_id'
            """))
            
            index_exists = result.fetchone()[0] > 0
            
            if not index_exists:
                logger.info("Creating index on postfix_logs.queue_id...")
                conn.execute(text("""
                    CREATE INDEX idx_postfix_queue_id 
                    ON postfix_logs(queue_id)
                """))
                conn.commit()
                logger.info("✅ Index created successfully!")
            else:
                logger.info("Index already exists, skipping...")
                
        except Exception as e:
            logger.error(f"❌ Failed to create index: {e}")
            conn.rollback()
            raise


def downgrade():
    """Remove index from postfix_logs.queue_id"""
    engine = create_engine(settings.database_url)
    
    with engine.connect() as conn:
        try:
            logger.info("Dropping index idx_postfix_queue_id...")
            conn.execute(text("DROP INDEX IF EXISTS idx_postfix_queue_id ON postfix_logs"))
            conn.commit()
            logger.info("✅ Index dropped successfully!")
        except Exception as e:
            logger.error(f"❌ Failed to drop index: {e}")
            conn.rollback()
            raise


if __name__ == "__main__":
    logger.info("Running migration: Add Postfix Queue ID Index")
    upgrade()
    logger.info("Migration complete!")