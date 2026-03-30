import re
import uuid
import time
from typing import Dict, List, Tuple, Any
from app.core.guardrails import AhoCorasick

# Core PII detection regex
EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
IP_REGEX = re.compile(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)")

def generate_honey_tokens(count: int = 2) -> List[str]:
    return [f"PII_SAFE_TRAP_{uuid.uuid4().hex[:8].upper()}" for _ in range(count)]

def scrub_payload(text: str, token_map: Dict[str, str]) -> Tuple[str, int]:
    """
    This handles the discovery of PII when we first receive input.
    Since we don't know what's there yet, we use Regex to 'hunt' for it.
    """
    count = 0
    # Search for Emails and IPs and swap them for placeholders
    for regex in [EMAIL_REGEX, IP_REGEX]:
        matches = list(set(regex.findall(text)))
        for match in matches:
            if match not in token_map:
                p_type = "EMAIL" if "@" in match else "IP"
                token_map[match] = f"[USER_{p_type}_{len(token_map) + 1}]"
            text = text.replace(match, token_map[match])
            count += 1
    return text, count

def traverse_and_sanitize(node: Any, token_map: Dict[str, str]) -> Tuple[Any, int]:
    """
    Recursively walks through any JSON-like object (Dicts/Lists) 
    to make sure no string field is left unmasked.
    """
    total = 0
    if isinstance(node, dict):
        clean = {}
        for k, v in node.items():
            res, c = traverse_and_sanitize(v, token_map)
            clean[k] = res
            total += c
        return clean, total
    elif isinstance(node, list):
        clean = []
        for item in node:
            res, c = traverse_and_sanitize(item, token_map)
            clean.append(res)
            total += c
        return clean, total
    elif isinstance(node, str):
        # Once we find a string, we call our 'hunt' logic
        return scrub_payload(node, token_map)
    return node, 0

def run_output_guardrail(text: str, token_map: Dict[str, str], honey_tokens: List[str]):
    """
    This is our last line of defense. It scans the AI response 
    for both real PII and our secret traps in one pass.
    """
    audit_trail = []
    is_compromised = False
    
    # We combine everything we're looking for into one map.
    # Honey-traps get a special mask, and real PII gets its specific token.
    unified_map = {trap: "[REDACTED_SECURITY_SENSITIVE]" for trap in honey_tokens}
    unified_map.update(token_map)
    
    if not unified_map:
        return text, False, 0, []

    # Building the search tree with all patterns
    patterns = list(unified_map.keys())
    ac_engine = AhoCorasick(patterns)
    
    # We scan the text character by character only once (O(M)).
    clean_text, match_count, found_patterns = ac_engine.search_and_replace(text, unified_map)
    
    # Now we check: Did any of the patterns we found happen to be secret honey-traps?
    # This is how we know if a malicious injection actually reached the context.
    matched_traps = [p for p in found_patterns if p in honey_tokens]
    
    if matched_traps:
        is_compromised = True # Mark that an attack was detected
        audit_trail.append(f"SECURITY ALERT: {len(matched_traps)} Honey-tokens were found.")

    # We also log how many pieces of sensitive data were redacted in this turn.
    if match_count > 0 and not is_compromised:
        audit_trail.append(f"PII Redaction: Replaced {match_count} instances in the output.")

    return clean_text, is_compromised, match_count, audit_trail
