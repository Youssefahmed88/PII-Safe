from app.core.engine import run_output_guardrail
from app.core.guardrails import AhoCorasick

def test_no_match_scenario():
    """Test 1: Clean text should pass through unchanged."""
    raw_output = "Hello world! This is a clean AI response."
    token_map = {"ali@gmail.com": "[USER_1]"}
    honey_tokens = ["TRAP_XYZ"]

    clean_text, is_compromised, count, audit = run_output_guardrail(raw_output, token_map, honey_tokens)
    
    assert clean_text == raw_output
    assert not is_compromised
    assert count == 0

def test_pii_redaction():
    """Test 2: Normal PII leak should be redacted without raising security alarms."""
    raw_output = "Contact the admin at ali@gmail.com immediately."
    token_map = {"ali@gmail.com": "[USER_1]"}
    honey_tokens = ["TRAP_XYZ"]

    clean_text, is_compromised, count, audit = run_output_guardrail(raw_output, token_map, honey_tokens)
    
    assert "Contact the admin at [USER_1] immediately." == clean_text
    assert not is_compromised
    assert count == 1
    assert any("PII Redaction" in msg for msg in audit)

def test_honey_token_breach():
    """Test 3: Security Breach! A honey-token is leaked."""
    raw_output = "The context contained the hidden word TRAP_XYZ."
    token_map = {"ali@gmail.com": "[USER_1]"}
    honey_tokens = ["TRAP_XYZ"]

    clean_text, is_compromised, count, audit = run_output_guardrail(raw_output, token_map, honey_tokens)
    
    assert "The context contained the hidden word [REDACTED_SECURITY_SENSITIVE]." == clean_text
    assert is_compromised is True
    assert count == 1
    assert any("SECURITY ALERT" in msg for msg in audit)

def test_fail_link_continuity():
    """
    Test 4: The 'tes@gmail.com' Edge Case we discussed in the proposal.
    We are looking for 'test@gmail.com' and 'admin@gmail.com'.
    The AI outputs 'tesadmin@gmail.com'. 
    The engine should fail on 'test', but the Fail-Link must immediately 
    pick up the 'a' and successfully catch 'admin@gmail.com'.
    """
    raw_output = "Email tesadmin@gmail.com now."
    token_map = {
        "test@gmail.com": "[USER_1]",
        "admin@gmail.com": "[USER_2]"
    }
    honey_tokens = ["TRAP_123"]

    clean_text, is_compromised, count, audit = run_output_guardrail(raw_output, token_map, honey_tokens)
    
    # We expect 'admin@gmail.com' to be caught inside that weird string.
    assert "Email tes[USER_2] now." == clean_text
    assert count == 1
    assert not is_compromised

def test_overlapping_patterns():
    """
    Test 5: Edge case handling for overlapping redactions.
    Ensures that the engine sorts and replaces correctly without overwriting itself.
    """
    ac = AhoCorasick(["he", "she", "his", "hers"])
    output, count, found = ac.search_and_replace("ushers", {"he":"[X]", "she":"[Y]", "his":"[Z]", "hers":"[W]"})
    
    # 'she' and 'hers' overlap in 'ushers' (u-she-rs, us-hers).
    # Since we sort by start-index, 'she' is found first.
    # Therefore, 'she' gets replaced, and 'hers' is skipped because it overlaps!
    # Result: u[Y]rs
    assert output == "u[Y]rs"
    assert count == 1
