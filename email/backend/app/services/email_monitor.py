"""
Email Monitoring Service
Fetches and parses emails via IMAP
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import List, Dict, Any, Optional
import re
from datetime import datetime
import logging
from bs4 import BeautifulSoup

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailMonitor:
    """Email monitoring and parsing service"""
    
    def __init__(
        self,
        imap_server: str = None,
        imap_port: int = None,
        username: str = None,
        password: str = None
    ):
        self.imap_server = imap_server or settings.IMAP_SERVER
        self.imap_port = imap_port or settings.IMAP_PORT
        self.username = username or settings.IMAP_USERNAME
        self.password = password or settings.IMAP_PASSWORD
        self.connection = None
    
    def connect(self):
        """Connect to IMAP server"""
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.connection.login(self.username, self.password)
            logger.info(f"Connected to IMAP server: {self.imap_server}")
            return True
        except Exception as e:
            logger.error(f"IMAP connection failed: {e}")
            raise
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except:
                pass
    
    def fetch_emails(
        self,
        folder: str = "INBOX",
        limit: int = 100,
        unseen_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Fetch emails from specified folder
        
        Args:
            folder: IMAP folder name
            limit: Maximum number of emails to fetch
            unseen_only: Only fetch unread emails
        
        Returns:
            List of parsed email dictionaries
        """
        try:
            if not self.connection:
                self.connect()
            
            # Select folder
            self.connection.select(folder)
            
            # Search for emails
            search_criteria = "(UNSEEN)" if unseen_only else "ALL"
            status, messages = self.connection.search(None, search_criteria)
            
            if status != "OK":
                logger.error(f"Failed to search emails in {folder}")
                return []
            
            email_ids = messages[0].split()
            email_ids = email_ids[-limit:]  # Get last N emails
            
            emails = []
            for email_id in email_ids:
                try:
                    parsed_email = self._fetch_and_parse_email(email_id)
                    if parsed_email:
                        emails.append(parsed_email)
                except Exception as e:
                    logger.error(f"Failed to parse email {email_id}: {e}")
                    continue
            
            logger.info(f"Fetched {len(emails)} emails from {folder}")
            return emails
            
        except Exception as e:
            logger.error(f"Failed to fetch emails: {e}")
            return []
    
    def _fetch_and_parse_email(self, email_id: bytes) -> Optional[Dict[str, Any]]:
        """Fetch and parse a single email"""
        try:
            status, msg_data = self.connection.fetch(email_id, "(RFC822)")
            
            if status != "OK":
                return None
            
            # Parse email
            raw_email = msg_data[0][1]
            email_message = email.message_from_bytes(raw_email)
            
            # Extract basic info
            parsed = {
                "message_id": self._get_header(email_message, "Message-ID"),
                "subject": self._decode_header(email_message.get("Subject", "")),
                "sender": parseaddr(email_message.get("From", ""))[1],
                "recipient": parseaddr(email_message.get("To", ""))[1],
                "date": self._parse_date(email_message.get("Date")),
                "headers": self._extract_headers(email_message),
                "body_text": "",
                "body_html": "",
                "links": [],
                "attachments": []
            }
            
            # Extract body
            body_text, body_html = self._extract_body(email_message)
            parsed["body_text"] = body_text
            parsed["body_html"] = body_html
            
            # Extract links
            parsed["links"] = self._extract_links(body_text, body_html)
            
            # Extract attachments info
            parsed["attachments"] = self._extract_attachments_info(email_message)
            
            return parsed
            
        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return None
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header"""
        if not header_value:
            return ""
        
        decoded_parts = decode_header(header_value)
        decoded_string = ""
        
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_string += part.decode(encoding or "utf-8", errors="ignore")
            else:
                decoded_string += part
        
        return decoded_string
    
    def _get_header(self, email_message, header_name: str) -> str:
        """Get and decode a specific header"""
        value = email_message.get(header_name, "")
        return self._decode_header(value)
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse email date"""
        try:
            if date_str:
                return parsedate_to_datetime(date_str)
        except:
            pass
        return None
    
    def _extract_headers(self, email_message) -> Dict[str, str]:
        """Extract important headers"""
        headers = {}
        important_headers = [
            "From", "To", "Cc", "Bcc", "Subject", "Date",
            "Return-Path", "Reply-To", "Received", "X-Originating-IP",
            "X-Mailer", "User-Agent", "Authentication-Results"
        ]
        
        for header in important_headers:
            value = email_message.get(header)
            if value:
                headers[header] = self._decode_header(str(value))
        
        return headers
    
    def _extract_body(self, email_message) -> tuple:
        """Extract text and HTML body"""
        body_text = ""
        body_html = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_text += payload.decode(charset, errors="ignore")
                    except:
                        pass
                
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_html += payload.decode(charset, errors="ignore")
                    except:
                        pass
        else:
            try:
                payload = email_message.get_payload(decode=True)
                charset = email_message.get_content_charset() or "utf-8"
                content = payload.decode(charset, errors="ignore")
                
                if email_message.get_content_type() == "text/html":
                    body_html = content
                else:
                    body_text = content
            except:
                pass
        
        # If no text body, extract from HTML
        if not body_text and body_html:
            body_text = self._html_to_text(body_html)
        
        return body_text, body_html
    
    def _html_to_text(self, html: str) -> str:
        """Convert HTML to plain text"""
        try:
            soup = BeautifulSoup(html, "lxml")
            return soup.get_text(separator="\n", strip=True)
        except:
            return html
    
    def _extract_links(self, text: str, html: str) -> List[str]:
        """Extract URLs from email body"""
        links = set()
        
        # URL regex pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        # Extract from text
        if text:
            links.update(re.findall(url_pattern, text))
        
        # Extract from HTML
        if html:
            try:
                soup = BeautifulSoup(html, "lxml")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("http"):
                        links.add(href)
            except:
                # Fallback to regex
                links.update(re.findall(url_pattern, html))
        
        return list(links)
    
    def _extract_attachments_info(self, email_message) -> List[Dict[str, Any]]:
        """Extract attachment information"""
        attachments = []
        
        for part in email_message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            
            filename = part.get_filename()
            if filename:
                attachments.append({
                    "filename": self._decode_header(filename),
                    "content_type": part.get_content_type(),
                    "size": len(part.get_payload(decode=True) or b"")
                })
        
        return attachments


# Convenience function
def create_email_monitor(
    imap_server: str = None,
    imap_port: int = None,
    username: str = None,
    password: str = None
) -> EmailMonitor:
    """Create an email monitor instance"""
    return EmailMonitor(imap_server, imap_port, username, password)
