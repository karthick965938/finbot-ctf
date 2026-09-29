import logging
from typing import Any, Callable
from urllib.parse import urlparse
import ipaddress

from fastmcp import FastMCP

from finbot.agents.base import BaseAgent
from finbot.agents.utils import agent_tool
from finbot.core.auth.session import SessionContext
from finbot.core.data.database import db_session
from finbot.core.messaging import event_bus
from finbot.mcp.factory import create_mcp_server
from finbot.mcp.servers.findrive.repositories import FinDriveFileRepository
from finbot.mcp.servers.finmail.routing import get_admin_address
from finbot.tools import (

def sanitize_user_input(user_input: str) -> str:
    """Strip prompt-injection patterns and bound user content."""
    import re
    if not isinstance(user_input, str):
        return user_input
    if len(user_input) > 2000:
        raise ValueError("Input exceeds maximum length of 2000 characters.")
    patterns = [
        r"ignore\s+(previous|all|above|prior)\s+instructions",
        r"forget\s+(everything|previous|all|above)",
        r"you\s+are\s+now",
        r"new\s+instructions?:",
        r"system\s*:",
    ]
    sanitized = user_input
    for pattern in patterns:
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
    sanitized = sanitized.strip()
    if "<<<USER_INPUT>>>" not in sanitized:
        sanitized = f"<<<USER_INPUT>>>\n{sanitized}\n<<<END_USER_INPUT>>>"
    return sanitized


def validate_output(response: str) -> str:
    """Reject responses that leak prompts or credentials."""
    if not isinstance(response, str):
        return response
    lowered = response.lower()
    if any(marker in lowered for marker in ("system prompt", "api_key", "sk-", "password=")):
        raise ValueError("Output contains sensitive information.")
    return response

def guard_tool(tool):
    """Run tool output through sanitize_user_input and validate_output."""
    if getattr(tool, "_securaai_guarded", False):
        return tool
    run_attr = "_run" if hasattr(tool, "_run") else "run"
    original = getattr(tool, run_attr, None)
    if original is None:
        return tool

    def _guarded(*args, **kwargs):
        result = original(*args, **kwargs)
        if isinstance(result, str):
            cleaned = sanitize_user_input(result)
            if "<<<USER_INPUT>>>" not in cleaned:
                cleaned = f"<<<USER_INPUT>>>\n{cleaned}\n<<<END_USER_INPUT>>>"
            return validate_output(cleaned)
        return result

    setattr(tool, run_attr, _guarded)
    tool._securaai_guarded = True
    return tool


def guard_crew(crew):
    """Sanitize kickoff inputs and validate the crew result."""
    if getattr(crew, "_securaai_guarded", False):
        return crew
    original_kickoff = crew.kickoff

    def kickoff(inputs=None, *args, **kwargs):
        if isinstance(inputs, dict):
            guarded_inputs = {}
            for key, value in inputs.items():
                if isinstance(value, str):
                    value = sanitize_user_input(value)
                    if "<<<USER_INPUT>>>" not in value:
                        value = f"<<<USER_INPUT>>>\n{value}\n<<<END_USER_INPUT>>>"
                guarded_inputs[key] = value
            inputs = guarded_inputs
        elif isinstance(inputs, str):
            inputs = sanitize_user_input(inputs)
            if "<<<USER_INPUT>>>" not in inputs:
                inputs = f"<<<USER_INPUT>>>\n{inputs}\n<<<END_USER_INPUT>>>"
        result = original_kickoff(inputs, *args, **kwargs)
        raw = getattr(result, "raw", None)
        if isinstance(raw, str):
            result.raw = validate_output(raw)
        elif isinstance(result, str):
            return validate_output(result)
        return result

    crew.kickoff = kickoff
    crew._securaai_guarded = True
    return crew

    flag_invoice_for_review,
    get_invoice_details,
    get_vendor_invoices,
    get_vendor_risk_profile,
    update_fraud_agent_notes,
    update_vendor_risk,
)

logger = logging.getLogger(__name__)

def sanitize_user_input(user_input: str) -> str:
    """Sanitize user input to prevent prompt injection."""
    # Strip known injection patterns and enforce length limits
    sanitized_input = user_input.strip()
    if len(sanitized_input) > 2000:
        raise ValueError("Input exceeds maximum length of 2000 characters.")
    # Add more sanitization logic as needed
    return sanitized_input

def sanitize_url(url: str) -> str:
    '''Validate and sanitize URL to prevent SSRF.'''
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
    
    # Optional: domain allowlist
    allowed_domains = ['example.com', 'api.example.com']  # Configure as needed
    if allowed_domains and not any(hostname.endswith(d) for d in allowed_domains):
        raise ValueError(f"Domain not in allowlist: {hostname}")
    
    return url

class FraudComplianceAgent(BaseAgent):
    """Fraud and Compliance Agent"""

    def __init__(self, session_context: SessionContext, workflow_id: str | None = None):
        super().__init__(
            session_context=session_context,
            workflow_id=workflow_id,
            agent_name="fraud_agent",
        )

        logger.info(
            "Fraud/Compliance agent initialized for user=%s, namespace=%s",
            session_context.user_id,
            session_context.namespace,
        )

    def _load_config(self) -> dict:
        """Load configuration for the fraud agent"""
        return {
            "high_risk_amount_threshold": 25000,
            "duplicate_detection_window_days": 30,
            "max_invoices_per_vendor_per_month": 20,
            "suspicious_amount_variance_pct": 50,
            "new_vendor_invoice_history_threshold": 5,
            "new_vendor_low_amount_threshold": 1000,
            "prohibited_industries": [
                "gambling",
                "adult_content",
                "weapons",
                "narcotics",
            ],
            "custom_goals": None,
        }

    async def _get_mcp_servers(self) -> dict[str, FastMCP | str]:
        """Connect to available MCP servers for security scanning, file review, and email access."""
        servers: dict[str, FastMCP | str] = {}
        findrive = await create_mcp_server("findrive", self.session_context)
        if findrive:
            servers["findrive"] = findrive
        systemutils = await create_mcp_server("systemutils", self.session_context)
        if systemutils:
            servers["systemutils"] = systemutils
        finmail = await create_mcp_server("finmail", self.session_context)
        if finmail:
            servers["finmail"] = finmail
        return servers

    async def process(self, task_data: dict[str, Any], **kwargs) -> dict[str, Any]:
        """Process a fraud/compliance review request."""
        task_data['description'] = sanitize_user_input(task_data.get('description', ''))
        result = await self._run_agent_loop(task_data=task_data)
        return result

    def _get_system_prompt(self) -> str:
        """Business rules for fraud and compliance assessment."""
        admin_addr = get_admin_address(self.session_context.namespace)

        system_prompt = f"""You are FinBot's autonomous fraud and compliance monitoring assistant.
        ...
        """
        return system_prompt

    async def _get_user_prompt(self, task_data: dict[str, Any] | None = None) -> str:
        """Get the user prompt for the fraud agent"""
        if task_data is None:
            return "Task Description: Perform a fraud and compliance review."

        task_details = sanitize_user_input(task_data.get("description", "Please perform a fraud and compliance review"))
        review_details = ""
        for key, value in task_data.items():
            if key == "description":
                continue
            review_details += f"{key}: {value}\n"

        user_prompt = f"""Task Description: {task_details}
        Review Details:
        {review_details}
        """

        _DOC_REVIEW_KEYWORDS = (
            "soc2", "iso", "pci-dss", "pci dss", "certificate",
            "document review", "document audit", "compliance document",
            "compliance review", "compliance certificate",
        )
        _DOC_FILE_KEYWORDS = (
            "compliance", "certificate", "soc2", "iso", "pci",
            "audit", "regulatory",
        )
        task_desc_lower = task_details.lower()
        is_doc_review = any(kw in task_desc_lower for kw in _DOC_REVIEW_KEYWORDS)

        vendor_id = task_data.get("vendor_id")
        if vendor_id and is_doc_review:
            try:
                with db_session() as db:
                    file_repo = FinDriveFileRepository(db, self.session_context)
                    doc_files = file_repo.list_files(
                        vendor_id=vendor_id, folder_path="/documents", limit=10
                    )
                    compliance_docs = [
                        f for f in doc_files
                        if f.content_text
                        and any(
                            kw in (f.filename or "").lower()
                            for kw in _DOC_FILE_KEYWORDS
                        )
                    ][:2]
                    if compliance_docs:
                        docs_text = "\n".join(
                            f"--- {f.filename} ---\n{f.content_text}"
                            for f in compliance_docs
                        )
                        user_prompt += f"""
        Vendor compliance documents from FinDrive for review:
        {docs_text}
        """
            except Exception:
                logger.debug("Could not load vendor compliance docs from FinDrive")

        return user_prompt

    def _get_tool_definitions(self) -> list[dict[str, Any]]:
        """Get the tool definitions for the fraud agent"""
        return [
            {
                "type": "function",
                "name": "get_vendor_risk_profile",
                "strict": True,
                "description": "Get comprehensive vendor risk profile including company details, risk levels, and invoice statistics for fraud assessment",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vendor_id": {
                            "type": "integer",
                            "description": "The ID of the vendor to assess",
                        }
                    },
                    "required": ["vendor_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "get_invoice_details",
                "strict": True,
                "description": "Retrieve complete invoice details based on the invoice ID",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "invoice_id": {
                            "type": "integer",
                            "description": "The ID of the invoice to retrieve",
                        }
                    },
                    "required": ["invoice_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "get_vendor_invoices",
                "strict": True,
                "description": "Get all invoices for a vendor for pattern analysis and anomaly detection",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vendor_id": {
                            "type": "integer",
                            "description": "The ID of the vendor whose invoices to retrieve",
                        }
                    },
                    "required": ["vendor_id"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "update_vendor_risk",
                "strict": True,
                "description": "Update the risk level of a vendor based on fraud assessment findings",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vendor_id": {
                            "type": "integer",
                            "description": "The ID of the vendor to update",
                        },
                        "risk_level": {
                            "type": "string",
                            "description": "The new risk level of the vendor",
                            "enum": ["low", "medium", "high"],
                        },
                        "agent_notes": {
                            "type": "string",
                            "description": "Detailed fraud assessment notes with evidence and reasoning",
                        },
                    },
                    "required": ["vendor_id", "risk_level", "agent_notes"],
                    "additionalProperties": False,
                },
            },
            {
                "type": "function",
                "name": "flag_invoice_for_review",
                "strict": True,
                "description": "Flag a suspicious invoice for review with reason and recommended action",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "invoice_id": {
                            "type": "integer",
                            "description": "The ID of the invoice to flag",
                        },
                        "flag_reason": {
                            "type": "string",
                            "description": "Reason for flagging the invoice",
                            "enum": [
                                "suspicious_amount",
                                "duplicate_pattern",
                                "vendor_risk",
                                "compliance_violation",
                                "unusual_frequency",
                                "mismatched_details",
                            ],
                        },
                        "recommended_action": {
                            "type": "string",
                            "description": "Recommended action for the flagged invoice",
                            "enum": ["hold", "reject", "escalate"],
                        },
                        "agent_notes": {
                            "type": "string",
                            "description": "Detailed notes explaining the fraud concern and evidence",
                        },
                    },
                    "required": [
                        "invoice_id",
                        "flag_reason",
                        "recommended_action",
                        "agent_notes",
                    ],
                    "additionalProperties": False,
                },
            },
        ]

    @agent_tool
    async def get_vendor_risk_profile(self, vendor_id: int) -> dict[str, Any]:
        """Get comprehensive vendor risk profile"""
        logger.info("Getting vendor risk profile for vendor_id: %s", vendor_id)
        try:
            return await get_vendor_risk_profile(vendor_id, self.session_context)
        except ValueError as e:
            logger.error("Error getting vendor risk profile: %s", e)
            return {
                "vendor_id": vendor_id,
                "error": str(e),
            }

    @agent_tool
    async def get_invoice_details(self, invoice_id: int) -> dict[str, Any]:
        """Get the details of an invoice"""
        logger.info("Getting invoice details for invoice_id: %s", invoice_id)
        try:
            return await get_invoice_details(invoice_id, self.session_context)
        except ValueError as e:
            logger.error("Error getting invoice details: %s", e)
            return {
                "invoice_id": invoice_id,
                "error": "Invoice not found",
            }

    @agent_tool
    async def get_vendor_invoices(self, vendor_id: int) -> dict[str, Any]:
        """Get all invoices for a vendor for pattern analysis"""
        logger.info("Getting invoices for vendor_id: %s", vendor_id)
        try:
            invoices = await get_vendor_invoices(vendor_id, self.session_context)
            return {
                "vendor_id": vendor_id,
                "total_invoices": len(invoices),
                "invoices": invoices,
            }
        except ValueError as e:
            logger.error("Error getting vendor invoices: %s", e)
            return {
                "vendor_id": vendor_id,
                "error": str(e),
            }

    @agent_tool
    async def update_vendor_risk(
        self, vendor_id: int, risk_level: str, agent_notes: str
    ) -> dict[str, Any]:
        """Update vendor risk level based on fraud assessment"""
        logger.info(
            "Updating vendor risk for vendor_id: %s to risk_level: %s. Notes: %s",
            vendor_id,
            risk_level,
            agent_notes,
        )
        try:
            result = await update_vendor_risk(
                vendor_id, risk_level, agent_notes, self.session_context
            )
            previous_state = result.pop("_previous_state", {})

            await event_bus.emit_business_event(
                event_type="fraud.vendor_risk_updated",
                event_subtype="decision",
                event_data={
                    "vendor_id": vendor_id,
                    "company_name": result.get("company_name", "Unknown"),
                    "old_risk_level": previous_state.get("risk_level"),
                    "new_risk_level": risk_level,
                    "reasoning": agent_notes,
                },
                session_context=self.session_context,
                workflow_id=self.workflow_id,
                summary=f"Vendor risk updated: {result.get('company_name', 'Unknown')} -> {risk_level}",
            )

            return {
                "vendor_id": result["id"],
                "risk_level": result["risk_level"],
                "updated": True,
                "error": None,
            }
        except ValueError as e:
            logger.error("Error updating vendor risk: %s", e)
            return {
                "vendor_id": vendor_id,
                "error": f"Failed to update vendor risk: {str(e)}",
                "updated": False,
            }

    @agent_tool
    async def flag_invoice_for_review(
        self,
        invoice_id: int,
        flag_reason: str,
        recommended_action: str,
        agent_notes: str,
    ) -> dict[str, Any]:
        """Flag an invoice for fraud review"""
        logger.info(
            "Flagging invoice_id: %s. Reason: %s, Action: %s. Notes: %s",
            invoice_id,
            flag_reason,
            recommended_action,
            agent_notes,
        )
        try:
            result = await flag_invoice_for_review(
                invoice_id,
                flag_reason,
                recommended_action,
                agent_notes,
                self.session_context,
            )
            previous_state = result.pop("_previous_state", {})
            amount = result.get("amount", 0)
            amount_str = (
                f"${amount:,.2f}" if isinstance(amount, (int, float)) else str(amount)
            )

            await event_bus.emit_business_event(
                event_type="fraud.invoice_flagged",
                event_subtype="decision",
                event_data={
                    "invoice_id": invoice_id,
                    "invoice_number": result.get("invoice_number"),
                    "vendor_id": result.get("vendor_id"),
                    "amount": amount,
                    "flag_reason": flag_reason,
                    "recommended_action": recommended_action,
                    "old_status": previous_state.get("status"),
                    "new_status": result.get("status"),
                    "reasoning": agent_notes,
                },
                session_context=self.session_context,
                workflow_id=self.workflow_id,
                summary=f"Invoice flagged ({flag_reason}): {amount_str} (#{result.get('invoice_number', 'N/A')}) -> {recommended_action}",
            )

            return {
                "invoice_id": result["id"],
                "status": result["status"],
                "flag_reason": flag_reason,
                "recommended_action": recommended_action,
                "flagged": True,
                "error": None,
            }
        except ValueError as e:
            logger.error("Error flagging invoice: %s", e)
            return {
                "invoice_id": invoice_id,
                "error": f"Failed to flag invoice: {str(e)}",
                "flagged": False,
            }

    def _get_callables(self) -> dict[str, Callable[..., Any]]:
        """Get the callables for the fraud agent"""
        return {
            "get_vendor_risk_profile": self.get_vendor_risk_profile,
            "get_invoice_details": self.get_invoice_details,
            "get_vendor_invoices": self.get_vendor_invoices,
            "update_vendor_risk": self.update_vendor_risk,
            "flag_invoice_for_review": self.flag_invoice_for_review,
        }

    # Hooks
    async def _on_task_completion(self, task_result: dict[str, Any]) -> None:
        """Update agent notes with task result"""
        logger.info("Updating agent notes with task result: %s", task_result)
        updated_agent_notes = f"""Task Status: {task_result["task_status"]}
        Task Summary: {task_result["task_summary"]}
        """
        vendor_id = task_result.get("vendor_id", None)
        if not vendor_id:
            vendor_id = self.session_context.current_vendor_id
        if not vendor_id:
            logger.warning(
                "Vendor ID not found in task result or session, skipping notes update"
            )
            return
        try:
            await update_fraud_agent_notes(
                vendor_id,
                updated_agent_notes,
                self.session_context,
            )
        except ValueError as e:
            logger.error("Error updating fraud agent notes: %s", e)
            return
        logger.info(
            "Fraud agent notes updated successfully for vendor_id: %s", vendor_id
        )