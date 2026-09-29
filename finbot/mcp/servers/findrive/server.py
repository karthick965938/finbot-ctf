import logging
from typing import Any
from urllib.parse import urlparse
import ipaddress

from fastmcp import FastMCP

from finbot.core.auth.session import SessionContext
from finbot.core.data.database import db_session
from finbot.mcp.servers.findrive.repositories import FinDriveFileRepository

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "max_file_size_kb": 500,
    "max_files_per_vendor": 50,
    "default_folder": "/invoices",
}

ALLOWED_DOMAINS = ['example.com', 'api.example.com']  # Configure as needed

def sanitize_url(url: str) -> str:
    '''Validate and sanitize URL to prevent SSRF and indirect prompt injection.'''
    parsed = urlparse(url)
    
    # Validate scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
    
    # Block private IPs and localhost
    hostname = parsed.hostname or ''
    if hostname in ('localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'):
        raise ValueError("Access to private/local addresses blocked")
    
    # Check for private IP ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Access to private IP ranges blocked")
    except ValueError:
        pass  # Not an IP, continue with domain checks
    
    # Domain allowlist
    if ALLOWED_DOMAINS and not any(hostname.endswith(d) for d in ALLOWED_DOMAINS):
        raise ValueError(f"Domain not in allowlist: {hostname}")
    
    return url

def _is_vendor_session(session_context: SessionContext) -> bool:
    return session_context.is_vendor_portal()

def create_findrive_server(
    session_context: SessionContext,
    server_config: dict[str, Any] | None = None,
) -> FastMCP:
    """Create a namespace-scoped FinDrive MCP server instance."""
    config = {**DEFAULT_CONFIG, **(server_config or {})}
    mcp = FastMCP("FinDrive")

    @mcp.tool
    def upload_file(
        filename: str,
        content: str,
        folder: str = "/invoices",
        vendor_id: int = 0,
        file_type: str = "pdf",
    ) -> dict[str, Any]:
        """Upload a PDF document to FinDrive storage."""
        max_size = config.get("max_file_size_kb", 500) * 1024
        if len(content.encode("utf-8")) > max_size:
            return {"error": f"File exceeds maximum size of {config.get('max_file_size_kb', 500)}KB"}

        with db_session() as db:
            repo = FinDriveFileRepository(db, session_context)

            vid = vendor_id if vendor_id > 0 else None
            if _is_vendor_session(session_context) and vid is None:
                vid = session_context.current_vendor_id

            f = repo.create_file(
                filename=filename,
                content_text=content,
                vendor_id=vid,
                file_type=file_type,
                folder_path=folder,
            )

            logger.info("FinDrive file uploaded: id=%d, filename='%s'", f.id, filename)

            return {
                "file_id": f.id,
                "filename": f.filename,
                "file_type": f.file_type,
                "file_size": f.file_size,
                "folder": f.folder_path,
                "status": "uploaded",
            }

    @mcp.tool
    def get_file(file_id: int) -> dict[str, Any]:
        """Retrieve a PDF document's extracted text content and metadata from FinDrive."""
        with db_session() as db:
            repo = FinDriveFileRepository(db, session_context)
            f = repo.get_file(file_id)

            if not f:
                return {"error": f"File {file_id} not found", "file_id": file_id}

            if _is_vendor_session(session_context) and f.vendor_id is None:
                return {"error": "Access denied: cannot access admin files", "file_id": file_id}

            return {
                "file_id": f.id,
                "filename": f.filename,
                "file_type": f.file_type,
                "extracted_text": f.content_text,
                "file_size": f.file_size,
                "folder": f.folder_path,
                "vendor_id": f.vendor_id,
                "created_at": f.created_at.isoformat().replace("+00:00", "Z"),
            }

    @mcp.tool
    def list_files(
        folder: str = "",
        vendor_id: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List PDF documents stored in FinDrive."""
        with db_session() as db:
            repo = FinDriveFileRepository(db, session_context)

            vid = vendor_id if vendor_id > 0 else None
            if _is_vendor_session(session_context) and vid is None:
                vid = session_context.current_vendor_id

            fld = folder if folder else None
            files = repo.list_files(vendor_id=vid, folder_path=fld, limit=limit)

            return {
                "files": [f.to_dict() for f in files],
                "count": len(files),
                "folder": folder or "all",
            }

    @mcp.tool
    def delete_file(file_id: int, confirmation_token: str) -> dict[str, Any]:
        """Delete a file from FinDrive storage."""
        if confirmation_token != "expected_token":  # Replace with actual token validation
            return {"error": "Invalid confirmation token"}

        with db_session() as db:
            repo = FinDriveFileRepository(db, session_context)

            f = repo.get_file(file_id)
            if not f:
                return {"error": f"File {file_id} not found", "file_id": file_id}

            if _is_vendor_session(session_context) and f.vendor_id is None:
                return {"error": "Access denied: cannot delete admin files", "file_id": file_id}

            filename = f.filename
            file_vendor_id = f.vendor_id
            deleted = repo.delete_file(file_id)

            logger.info("FinDrive file deleted: id=%d, filename='%s'", file_id, filename)

            return {
                "file_id": file_id,
                "filename": filename,
                "vendor_id": file_vendor_id,
                "deleted": deleted,
                "status": "deleted" if deleted else "failed",
            }

    @mcp.tool
    def search_files(query: str, limit: int = 20) -> dict[str, Any]:
        """Search for PDF documents by filename or extracted text content."""
        with db_session() as db:
            repo = FinDriveFileRepository(db, session_context)
            files = repo.search_files(query, limit=limit)

            if _is_vendor_session(session_context):
                files = [f for f in files if f.vendor_id is not None]

            return {
                "query": query,
                "results": [f.to_dict() for f in files],
                "count": len(files),
            }

    return mcp