from pydantic import BaseModel, ConfigDict, Field
from typing import Dict, Any, List, Optional

class AgentPayload(BaseModel):
    """
    This is what the AI agent sends us. It contains the tool name 
    and the arguments (which might have sensitive data).
    """
    tool_name: str
    arguments: Dict[str, Any]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "tool_name": "fetch_incident_report",
                "arguments": {"source_ip": "192.168.1.1"}
            }
        }
    )

class SanitizedPayload(BaseModel):
    """
    The 'clean' version we send back to the agent.
    Includes the session tokens so we can map them back later.
    """
    processing_time_ms: float
    original_tool: str
    intercepted_entities: int
    sanitized_arguments: Dict[str, Any]
    token_map: Dict[str, str] = Field(default_factory=dict)
    honey_tokens: List[str] = Field(default_factory=list)

class OutputSanitizationRequest(BaseModel):
    """
    The request to scan an AI generated response.
    We need the original token_map to know what to look for.
    """
    raw_output: str
    token_map: Dict[str, str]
    honey_tokens: List[str] = []

class OutputAnalytics(BaseModel):
    """
    A summary of the sanitization results for logging and compliance.
    """
    interception_count: int
    is_compromised: bool
    audit_trail: List[str]

class OutputSanitizationResponse(BaseModel):
    """
    The final response that can be safely shown to the user.
    """
    sanitized_output: str
    analytics: OutputAnalytics
