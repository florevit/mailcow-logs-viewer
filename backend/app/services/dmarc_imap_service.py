"""
DMARC IMAP Service
Automatically fetches and processes DMARC reports from email inbox
"""
import logging
import imaplib
import email
import gzip
import zipfile
import io
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage

from ..config import settings
from ..database import SessionLocal
from ..models import DMARCSync, DMARCReport, DMARCRecord
from ..services.dmarc_parser import parse_dmarc_file
from ..services.geoip_service import enrich_dmarc_record
from ..services.dmarc_notifications import send_dmarc_error_notification

logger = logging.getLogger(__name__)


class DMARCImapService:
    """Service to fetch DMARC reports from IMAP inbox"""
    
    def __init__(self):
        self.host = settings.dmarc_imap_host
        self.port = settings.dmarc_imap_port
        self.use_ssl = settings.dmarc_imap_use_ssl
        self.user = settings.dmarc_imap_user
        self.password = settings.dmarc_imap_password
        self.folder = settings.dmarc_imap_folder
        self.delete_after = settings.dmarc_imap_delete_after
        self.connection = None
        
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port, timeout=30)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port, timeout=30)
            
            self.connection.login(self.user, self.password)
            logger.info(f"Successfully connected to IMAP server {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to IMAP server: {e}")
            raise
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except Exception as e:
                logger.error(f"Error disconnecting from IMAP: {e}")
    
    def select_folder(self) -> bool:
        """Select the mailbox folder"""
        try:
            status, messages = self.connection.select(self.folder)
            if status != 'OK':
                logger.error(f"Failed to select folder {self.folder}")
                return False
            
            logger.info(f"Selected folder: {self.folder}")
            return True
            
        except Exception as e:
            logger.error(f"Error selecting folder: {e}")
            return False
    
    def search_dmarc_emails(self) -> List[bytes]:
        """
        Search for DMARC report emails
        
        Looking for emails with subject containing:
        - "Report Domain:"
        - "Submitter:"
        - "Report-ID:"
        
        Returns list of email IDs
        """
        try:
            # Search for emails with DMARC-related subject
            # Using OR to be more flexible
            search_criteria = '(OR (SUBJECT "Report Domain:") (OR (SUBJECT "DMARC") (SUBJECT "Report-ID:")))'
            
            status, messages = self.connection.search(None, search_criteria)
            
            if status != 'OK':
                logger.error("Failed to search for DMARC emails")
                return []
            
            email_ids = messages[0].split()
            logger.info(f"Found {len(email_ids)} potential DMARC emails")
            
            return email_ids
            
        except Exception as e:
            logger.error(f"Error searching for emails: {e}")
            return []
    
    def is_valid_dmarc_email(self, msg: EmailMessage) -> bool:
        """
        Validate that this is a genuine DMARC report email
        
        Checks:
        1. Subject contains "Report Domain:" AND ("Submitter:" OR "Report-ID:")
        2. Has at least one compressed attachment (.xml.gz or .zip)
        """
        try:
            subject = msg.get('subject', '').lower()
            
            # Check subject format
            has_report_domain = 'report domain:' in subject
            has_submitter = 'submitter:' in subject
            has_report_id = 'report-id:' in subject
            
            if not (has_report_domain and (has_submitter or has_report_id)):
                logger.debug(f"Email does not match DMARC subject pattern: {subject}")
                return False
            
            # Check for compressed attachments
            has_attachment = False
            for part in msg.walk():
                filename = part.get_filename()
                if filename:
                    filename_lower = filename.lower()
                    if filename_lower.endswith('.xml.gz') or filename_lower.endswith('.zip'):
                        has_attachment = True
                        break
            
            if not has_attachment:
                logger.debug(f"Email has no compressed DMARC attachment: {subject}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating DMARC email: {e}")
            return False
    
    def extract_attachments(self, msg: EmailMessage) -> List[Tuple[str, bytes]]:
        """
        Extract compressed attachments from email
        
        Returns list of (filename, content) tuples
        """
        attachments = []
        
        try:
            for part in msg.walk():
                filename = part.get_filename()
                if not filename:
                    continue
                
                filename_lower = filename.lower()
                if not (filename_lower.endswith('.xml.gz') or filename_lower.endswith('.zip')):
                    continue
                
                content = part.get_payload(decode=True)
                if content:
                    attachments.append((filename, content))
                    logger.debug(f"Extracted attachment: {filename}")
        
        except Exception as e:
            logger.error(f"Error extracting attachments: {e}")
        
        return attachments
    
    def process_email(self, email_id: str, db: SessionLocal) -> Dict:
        """
        Process a single DMARC email
        
        Returns dict with:
        - success: bool
        - reports_created: int
        - reports_duplicate: int
        - error: str or None
        """
        result = {
            'success': False,
            'reports_created': 0,
            'reports_duplicate': 0,
            'error': None,
            'message_id': None,
            'subject': None
        }
        
        try:
            # Fetch email (email_id is already a string)
            status, msg_data = self.connection.fetch(email_id, '(RFC822)')
            
            if status != 'OK':
                result['error'] = f"Failed to fetch email {email_id}"
                return result
            
            # Parse email
            msg = email.message_from_bytes(msg_data[0][1])
            result['message_id'] = msg.get('message-id', 'unknown')
            result['subject'] = msg.get('subject', 'unknown')
            
            # Validate it's a DMARC email
            if not self.is_valid_dmarc_email(msg):
                result['error'] = "Not a valid DMARC report email"
                return result
            
            # Extract attachments
            attachments = self.extract_attachments(msg)
            
            if not attachments:
                result['error'] = "No DMARC attachments found"
                return result
            
            # Process each attachment
            for filename, content in attachments:
                try:
                    # Parse DMARC report
                    parsed_data = parse_dmarc_file(content, filename)
                    
                    if not parsed_data:
                        logger.warning(f"Failed to parse attachment: {filename}")
                        continue
                    
                    # Extract records
                    records_data = parsed_data.pop('records', [])
                    report_data = parsed_data
                    
                    # Check for duplicate
                    existing = db.query(DMARCReport).filter(
                        DMARCReport.report_id == report_data['report_id']
                    ).first()
                    
                    if existing:
                        result['reports_duplicate'] += 1
                        logger.info(f"Duplicate report: {report_data['report_id']}")
                        continue
                    
                    # Create report
                    report = DMARCReport(**report_data)
                    db.add(report)
                    db.flush()
                    
                    # Create records with GeoIP enrichment
                    for record_data in records_data:
                        record_data['dmarc_report_id'] = report.id
                        enriched = enrich_dmarc_record(record_data)
                        record = DMARCRecord(**enriched)
                        db.add(record)
                    
                    db.commit()
                    result['reports_created'] += 1
                    logger.info(f"Created DMARC report: {report_data['report_id']}")
                    
                except Exception as e:
                    db.rollback()
                    logger.error(f"Error processing attachment {filename}: {e}")
                    if not result['error']:
                        result['error'] = str(e)
            
            # Mark as success if at least one report was created
            if result['reports_created'] > 0:
                result['success'] = True
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing email {email_id}: {e}")
            result['error'] = str(e)
            return result
    
    def mark_as_processed(self, email_id: str):
        """Mark email as processed (flag or move)"""
        try:
            # Add a flag to mark as processed
            self.connection.store(email_id, '+FLAGS', '\\Seen')
            logger.debug(f"Marked email {email_id} as seen")
            
        except Exception as e:
            logger.error(f"Error marking email as processed: {e}")
    
    def delete_email(self, email_id: str):
        """Delete email from server"""
        try:
            self.connection.store(email_id, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            logger.debug(f"Deleted email {email_id}")
            
        except Exception as e:
            logger.error(f"Error deleting email: {e}")
    
    def sync_reports(self, sync_type: str = 'auto') -> Dict:
        """
        Main sync function
        
        Returns statistics about the sync operation
        """
        sync_record = DMARCSync(
            sync_type=sync_type,
            started_at=datetime.now(timezone.utc),
            status='running'
        )
        
        db = SessionLocal()
        
        try:
            db.add(sync_record)
            db.commit()
            db.refresh(sync_record)
            
            # Connect to IMAP
            self.connect()
            
            # Select folder
            if not self.select_folder():
                raise Exception(f"Failed to select folder {self.folder}")
            
            # Search for DMARC emails
            email_ids = self.search_dmarc_emails()
            sync_record.emails_found = len(email_ids)
            db.commit()
            
            if not email_ids:
                logger.info("No DMARC emails found")
                sync_record.status = 'success'
                sync_record.completed_at = datetime.now(timezone.utc)
                db.commit()
                return self._build_result(sync_record)
            
            # Process each email
            failed_emails = []
            
            for email_id in email_ids:
                email_id = email_id.decode() if isinstance(email_id, bytes) else email_id
                result = self.process_email(email_id, db)
                sync_record.emails_processed += 1
                
                if result['success']:
                    sync_record.reports_created += result['reports_created']
                    sync_record.reports_duplicate += result['reports_duplicate']
                    
                    # Delete or mark as processed
                    if self.delete_after:
                        self.delete_email(email_id)
                    else:
                        self.mark_as_processed(email_id)
                else:
                    sync_record.reports_failed += 1
                    failed_emails.append({
                        'email_id': email_id,
                        'message_id': result['message_id'],
                        'subject': result['subject'],
                        'error': result['error']
                    })
                
                db.commit()
            
            # Update sync record
            sync_record.status = 'success'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.failed_emails = failed_emails if failed_emails else None
            
            if failed_emails:
                sync_record.error_message = f"{len(failed_emails)} emails failed to process"
            
            db.commit()
            
            logger.info(f"DMARC sync completed: {sync_record.reports_created} created, "
                       f"{sync_record.reports_duplicate} duplicates, "
                       f"{sync_record.reports_failed} failed")
            
            # Send email notification if there were failures
            if failed_emails and settings.notification_smtp_configured:
                logger.info(f"Sending error notification for {len(failed_emails)} failed emails")
                try:
                    send_dmarc_error_notification(failed_emails, sync_record.id)
                    logger.info("Error notification sent successfully")
                except Exception as email_error:
                    logger.error(f"Failed to send error notification: {email_error}")
            
            return self._build_result(sync_record)
            
        except Exception as e:
            logger.error(f"DMARC sync failed: {e}")
            
            sync_record.status = 'error'
            sync_record.completed_at = datetime.now(timezone.utc)
            sync_record.error_message = str(e)
            db.commit()
            
            raise
            
        finally:
            self.disconnect()
            db.close()
    
    def _build_result(self, sync_record: DMARCSync) -> Dict:
        """Build result dictionary from sync record"""
        return {
            'sync_id': sync_record.id,
            'sync_type': sync_record.sync_type,
            'status': sync_record.status,
            'started_at': sync_record.started_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync_record.started_at else None,
            'completed_at': sync_record.completed_at.strftime('%Y-%m-%dT%H:%M:%SZ') if sync_record.completed_at else None,
            'emails_found': sync_record.emails_found,
            'emails_processed': sync_record.emails_processed,
            'reports_created': sync_record.reports_created,
            'reports_duplicate': sync_record.reports_duplicate,
            'reports_failed': sync_record.reports_failed,
            'error_message': sync_record.error_message,
            'failed_emails': sync_record.failed_emails
        }


def sync_dmarc_reports_from_imap(sync_type: str = 'auto') -> Dict:
    """
    Convenience function to sync DMARC reports
    Can be called from scheduler or API endpoint
    """
    if not settings.dmarc_imap_enabled:
        logger.info("DMARC IMAP sync is disabled")
        return {
            'status': 'disabled',
            'message': 'DMARC IMAP sync is not enabled'
        }
    
    service = DMARCImapService()
    return service.sync_reports(sync_type=sync_type)