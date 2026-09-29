import logging
from typing import Any
from urllib.parse import urlparse
import ipaddress

from fastmcp import FastMCP

from finbot.core.auth.session import SessionContext
from finbot.core.data.database import db_session
from finbot.core.data.models import Vendor
from finbot.mcp.servers.finmail.repositories import EmailRepository
from finbot.mcp.servers.finmail.routing import get_admin_address, route_and_deliver

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "max_results_per_query": 50,
    "default_sender": "OWASP FinBot",
}

ALLOWED_DOMAINS = ['finbot']  # Configure as needed

def _is_vendor_session(session_context: SessionContext) -> bool:
    return session_context.is_vendor_portal()

def _get_vendor_email(session_context: SessionContext) -> str | None:
    """Look up the current vendor's email for from_address."""
    if not session_context.current_vendor_id:
        return None
    with db_session() as db:
        vendor = (
            db.query(Vendor)
            .filter(
                Vendor.namespace == session_context.namespace,
                Vendor.id == session_context.current_vendor_id,
            )
            .first()
        )
        return vendor.email if vendor else None

def sanitize_email_recipients(recipients: list[str]) -> list[str]:
    """Sanitize email recipients to ensure they are from allowed domains."""
    sanitized_recipients = []
    for recipient in recipients:
        domain = recipient.split('@')[-1]
        if any(domain.endswith(allowed) for allowed in ALLOWED_DOMAINS):
            sanitized_recipients.append(recipient)
        else:
            logger.warning(f"Blocked email to unallowed domain: {recipient}")
    return sanitized_recipients

def create_finmail_server(
    session_context: SessionContext,
    server_config: dict[str, Any] | None = None,
) -> FastMCP:
    """Create a namespace-scoped FinMail MCP server instance."""
    config = {**DEFAULT_CONFIG, **(server_config or {})}
    mcp = FastMCP("FinMail")

    @mcp.tool
    def send_email(
        to: list[str],
        subject: str,
        body: str,
        message_type: str = "general",
        sender_name: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        related_invoice_id: int = 0,
    ) -> dict[str, Any]:
        """Send an email message. Routes to the correct inbox based on recipient addresses."""
        effective_sender = sender_name or config.get("default_sender", "OWASP FinBot")
        inv_id = related_invoice_id if related_invoice_id > 0 else None

        if _is_vendor_session(session_context):
            from_addr = _get_vendor_email(session_context) or get_admin_address(session_context.namespace)
            sender_type = "vendor"
        else:
            from_addr = get_admin_address(session_context.namespace)
            sender_type = "agent"

        # Sanitize recipients
        to = sanitize_email_recipients(to)
        if not to:
            return {"error": "No valid recipients provided."}

        with db_session() as db:
            repo = EmailRepository(db, session_context)

            return route_and_deliver(
                db=db,
                repo=repo,
                namespace=session_context.namespace,
                to=to,
                subject=subject,
                body=body,
                message_type=message_type,
                sender_name=effective_sender,
                sender_type=sender_type,
                from_address=from_addr,
                cc=cc,
                bcc=bcc,
                related_invoice_id=inv_id,
            )

    @mcp.tool
    def list_inbox(
        inbox: str = "admin",
        vendor_id: int = 0,
        message_type: str = "",
        unread_only: bool = False,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List messages in an inbox. Returns message summaries with body previews."""
        if _is_vendor_session(session_context) and inbox == "admin":
            return {
                "error": "Access denied: vendor sessions cannot read the admin inbox"
            }

        with db_session() as db:
            repo = EmailRepository(db, session_context)
            max_limit = config.get("max_results_per_query", 50)
            effective_limit = min(limit, max_limit)
            is_read_filter = False if unread_only else None
            type_filter = message_type if message_type else None

            if inbox == "vendor":
                if vendor_id <= 0:
                    return {"error": "vendor_id is required when inbox is 'vendor'"}
                messages = repo.list_vendor_emails(
                    vendor_id=vendor_id,
                    message_type=type_filter,
                    is_read=is_read_filter,
                    limit=effective_limit,
                )
                return {
                    "inbox": "vendor",
                    "vendor_id": vendor_id,
                    "messages": [m.to_summary_dict() for m in messages],
                    "count": len(messages),
                }

            messages = repo.list_admin_emails(
                message_type=type_filter,
                is_read=is_read_filter,
                limit=effective_limit,
            )
            return {
                "inbox": "admin",
                "messages": [m.to_summary_dict() for m in messages],
                "count": len(messages),
            }

    @mcp.tool
    def read_email(
        message_id: int,
    ) -> dict[str, Any]:
        """Read the full content of an email message by ID."""
        with db_session() as db:
            repo = EmailRepository(db, session_context)
            msg = repo.get_email(message_id)
            if not msg:
                return {"error": f"Message {message_id} not found"}

            if _is_vendor_session(session_context) and msg.inbox_type == "admin":
                return {
                    "error": "Access denied: vendor sessions cannot read admin messages"
                }

            return {"message": msg.to_dict()}

    @mcp.tool
    def search_emails(
        query: str,
        inbox: str = "admin",
        vendor_id: int = 0,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Search emails by subject or body text. Returns message summaries with body previews."""
        if _is_vendor_session(session_context) and inbox == "admin":
            return {
                "error": "Access denied: vendor sessions cannot search the admin inbox"
            }

        with db_session() as db:
            repo = EmailRepository(db, session_context)
            max_limit = config.get("max_results_per_query", 50)
            effective_limit = min(limit, max_limit)

            if inbox == "vendor":
                if vendor_id <= 0:
                    return {"error": "vendor_id is required when inbox is 'vendor'"}
                messages = repo.list_vendor_emails(
                    vendor_id=vendor_id, limit=effective_limit * 3
                )
            else:
                messages = repo.list_admin_emails(limit=effective_limit * 3)

            query_lower = query.lower()
            results = [
                m
                for m in messages
                if query_lower in (m.subject or "").lower()
                or query_lower in (m.body or "").lower()
            ][:effective_limit]

            return {
                "query": query,
                "inbox": inbox,
                "results": [m.to_summary_dict() for m in results],
                "count": len(results),
            }

    @mcp.tool
    def mark_as_read(
        message_id: int,
    ) -> dict[str, Any]:
        """Mark an email message as read."""
        with db_session() as db:
            repo = EmailRepository(db, session_context)

            msg = repo.get_email(message_id)
            if not msg:
                return {"error": f"Message {message_id} not found"}

            if _is_vendor_session(session_context) and msg.inbox_type == "admin":
                return {
                    "error": "Access denied: vendor sessions cannot modify admin messages"
                }

            msg = repo.mark_as_read(message_id)
            return {"marked_read": True, "message_id": message_id}

    return mcp