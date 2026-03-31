from fastapi import APIRouter, HTTPException
from app.models.schemas import AgentPayload, SanitizedPayload, OutputSanitizationRequest, OutputSanitizationResponse, OutputAnalytics
from app.core.engine import traverse_and_sanitize, generate_honey_tokens, run_output_guardrail
import time
import logging

router = APIRouter(prefix="/api/v1")
logger = logging.getLogger("PII-Safe-Audit")

@router.post("/sanitize", response_model=SanitizedPayload)
async def sanitize_payload(payload: AgentPayload):
    """
    Entry point for masking PII before it reaches the AI. 
    Returns the clean payload and the session tokens.
    """
    start_time = time.perf_counter()
    try:
        # We start with a fresh mapping and generate new honey-token traps
        token_map = {}
        honey_tokens = generate_honey_tokens()
        
        # Scrubbing the sensitive data from the agent's query
        clean_args, count = traverse_and_sanitize(payload.arguments, token_map)
        
        elapsed = (time.perf_counter() - start_time) * 1000
        return SanitizedPayload(
            processing_time_ms=round(elapsed, 3),
            original_tool=payload.tool_name,
            sanitized_arguments=clean_args,
            intercepted_entities=count,
            token_map=token_map,
            honey_tokens=honey_tokens
        )
    except Exception as e:
        logger.error(f"Error during input sanitization: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Scrubbing Error")

@router.post("/sanitize_output", response_model=OutputSanitizationResponse)
async def sanitize_output(request: OutputSanitizationRequest):
    """
    Final guardrail for AI responses.
    This scans the output for leaked data or honey-token traps.
    """
    try:
        # Running the optimized Aho-Corasick scan
        clean_text, is_compromised, pii_count, audit_trail = run_output_guardrail(
            request.raw_output, 
            request.token_map, 
            request.honey_tokens
        )
        
        # Soft-redaction: we don't block the whole response, but we mask the sensitive parts
        analytics = OutputAnalytics(
            interception_count=pii_count,
            is_compromised=is_compromised,
            audit_trail=audit_trail
        )
        
        return OutputSanitizationResponse(
            sanitized_output=clean_text,
            analytics=analytics
        )
    except Exception as e:
        logger.error(f"Error during output guardrail check: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Guardrail Error")
