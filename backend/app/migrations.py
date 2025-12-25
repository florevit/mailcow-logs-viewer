"""
Database migrations and maintenance utilities

SIMPLIFIED VERSION:
- Clean up duplicate correlations by Message-ID (not Queue-ID)
- Merge duplicates into the oldest one
- Update all related logs
"""
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import MessageCorrelation, PostfixLog, RspamdLog

logger = logging.getLogger(__name__)


def cleanup_duplicate_correlations(db: Session) -> int:
    """
    Clean up duplicate correlations that share the same Message-ID
    
    With the new Message-ID-based approach, there should be only ONE
    correlation per Message-ID. This function merges any duplicates.
    
    Strategy:
    1. Find Message-IDs with multiple correlations
    2. For each, keep the oldest correlation
    3. Merge postfix_log_ids and rspamd_log_id from duplicates
    4. Update all related logs to point to the kept correlation
    5. Delete the duplicates
    
    Returns:
        Number of duplicate correlations removed
    """
    logger.info("Checking for duplicate correlations by Message-ID...")
    
    try:
        # Find Message-IDs with multiple correlations
        query = text("""
            SELECT message_id, array_agg(correlation_key ORDER BY first_seen) as keys, COUNT(*) as count
            FROM message_correlations
            WHERE message_id IS NOT NULL AND message_id != ''
            GROUP BY message_id
            HAVING COUNT(*) > 1
        """)
        
        result = db.execute(query)
        duplicates = result.fetchall()
        
        if not duplicates:
            logger.info("No duplicate correlations found")
            return 0
        
        logger.info(f"Found {len(duplicates)} Message-IDs with duplicate correlations")
        
        total_removed = 0
        for message_id, correlation_keys, count in duplicates:
            # Get all correlations for this Message-ID (ordered by first_seen)
            correlations = db.query(MessageCorrelation).filter(
                MessageCorrelation.message_id == message_id
            ).order_by(MessageCorrelation.first_seen).all()
            
            if len(correlations) <= 1:
                continue
            
            # Keep the first (oldest) correlation
            primary = correlations[0]
            duplicates_to_remove = correlations[1:]
            
            logger.info(f"Merging {len(duplicates_to_remove)} duplicate correlations for Message-ID {message_id[:50]}")
            
            # Merge data from duplicates into primary
            all_postfix_ids = set(primary.postfix_log_ids or [])
            
            for dup in duplicates_to_remove:
                # Merge postfix_log_ids
                if dup.postfix_log_ids:
                    all_postfix_ids.update(dup.postfix_log_ids)
                
                # Update rspamd_log_id if primary doesn't have one
                if not primary.rspamd_log_id and dup.rspamd_log_id:
                    primary.rspamd_log_id = dup.rspamd_log_id
                
                # Update queue_id if primary doesn't have one
                if not primary.queue_id and dup.queue_id:
                    primary.queue_id = dup.queue_id
                
                # Update sender if missing
                if not primary.sender and dup.sender:
                    primary.sender = dup.sender
                
                # Update recipient if missing
                if not primary.recipient and dup.recipient:
                    primary.recipient = dup.recipient
                
                # Update subject if missing
                if not primary.subject and dup.subject:
                    primary.subject = dup.subject
                
                # Update direction if missing
                if not primary.direction and dup.direction:
                    primary.direction = dup.direction
                
                # Update timestamps if needed
                if dup.last_seen > primary.last_seen:
                    primary.last_seen = dup.last_seen
                
                # Update status (priority: bounced > rejected > deferred > spam > delivered)
                if dup.final_status:
                    if dup.final_status in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'deferred' and primary.final_status not in ['bounced', 'rejected']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'spam' and primary.final_status not in ['bounced', 'rejected', 'deferred']:
                        primary.final_status = dup.final_status
                    elif dup.final_status == 'delivered' and not primary.final_status:
                        primary.final_status = dup.final_status
            
            # Update primary correlation with merged data
            primary.postfix_log_ids = sorted(list(all_postfix_ids))
            
            # Update all Postfix logs to point to the primary correlation
            if all_postfix_ids:
                db.query(PostfixLog).filter(
                    PostfixLog.id.in_(all_postfix_ids)
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            # Update Rspamd log to point to the primary correlation
            if primary.rspamd_log_id:
                db.query(RspamdLog).filter(
                    RspamdLog.id == primary.rspamd_log_id
                ).update(
                    {"correlation_key": primary.correlation_key},
                    synchronize_session=False
                )
            
            # Delete the duplicates
            for dup in duplicates_to_remove:
                db.delete(dup)
                total_removed += 1
        
        db.commit()
        logger.info(f"Cleanup complete: Removed {total_removed} duplicate correlations")
        return total_removed
        
    except Exception as e:
        logger.error(f"Error during duplicate cleanup: {e}")
        db.rollback()
        return 0


def add_message_id_indexes(db: Session):
    """
    Add indexes for Message-ID columns if they don't exist
    Critical for performance with the new Message-ID-based correlation
    """
    logger.info("Ensuring Message-ID indexes exist...")
    
    try:
        # Check and create index for PostfixLog.message_id
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_postfix_message_id 
            ON postfix_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        # Check and create index for RspamdLog.message_id  
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_rspamd_message_id 
            ON rspamd_logs (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        # Check and create index for MessageCorrelation.message_id
        db.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_correlation_message_id 
            ON message_correlations (message_id)
            WHERE message_id IS NOT NULL
        """))
        
        db.commit()
        logger.info("Message-ID indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")
        db.rollback()


def add_is_complete_column(db: Session):
    """
    Add is_complete column to message_correlations if it doesn't exist
    This tracks whether we've found all Postfix logs for a correlation
    """
    logger.info("Checking if is_complete column exists...")
    
    try:
        # Check if column exists
        result = db.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='message_correlations' 
            AND column_name='is_complete'
        """))
        
        if result.fetchone() is None:
            logger.info("Adding is_complete column...")
            
            # Add column
            db.execute(text("""
                ALTER TABLE message_correlations 
                ADD COLUMN is_complete BOOLEAN DEFAULT FALSE
            """))
            
            # Add index
            db.execute(text("""
                CREATE INDEX idx_correlation_is_complete 
                ON message_correlations (is_complete)
            """))
            
            # Mark existing correlations with Queue-ID as complete
            db.execute(text("""
                UPDATE message_correlations 
                SET is_complete = TRUE 
                WHERE queue_id IS NOT NULL 
                AND postfix_log_ids IS NOT NULL 
                AND array_length(postfix_log_ids, 1) > 0
            """))
            
            db.commit()
            logger.info("is_complete column added and existing data updated")
        else:
            logger.info("is_complete column already exists")
        
    except Exception as e:
        logger.error(f"Error adding is_complete column: {e}")
        db.rollback()


def run_migrations():
    """
    Run all database migrations and maintenance tasks
    Called during application startup
    """
    logger.info("Running database migrations...")
    
    db = SessionLocal()
    try:
        # Ensure Message-ID indexes exist (critical for performance)
        add_message_id_indexes(db)
        
        # Add is_complete column if missing (for tracking correlation completion)
        add_is_complete_column(db)
        
        # Clean up duplicate correlations
        removed = cleanup_duplicate_correlations(db)
        
        if removed > 0:
            logger.info(f"Migration complete: Cleaned up {removed} duplicate correlations")
        else:
            logger.info("Migration complete: No duplicates found")
            
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        db.close()