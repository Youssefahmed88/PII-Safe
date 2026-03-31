import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def run_workflow():
    print("="*60)
    print("🚀 PII-Safe: Live Production HTTP Workflow 🚀")
    print("="*60)
    
    # 1. We start with the user's raw prompt
    input_payload = {
        "tool_name": "incident_reporter",
        "arguments": {
            "to": "youssef.ahmed@example.com",
            "body": "System breach. The target is youssef.ahmed@example.com from IP 192.168.1.50."
        }
    }
    
    print("\n[STEP 1] Raw Input Payload Generated (Contains PII):")
    print(json.dumps(input_payload, indent=2))
    
    # 2. Sending it to the Sanitization API
    print("\n[STEP 2] Sending to PII-Safe /sanitize Endpoint...")
    try:
        response = requests.post(f"{BASE_URL}/api/v1/sanitize", json=input_payload)
        data = response.json()
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return

    print("   -> Success! Received Clean Payload:")
    print(json.dumps(data['sanitized_arguments'], indent=2))
    print(f"\n   -> Items Masked: {data['intercepted_entities']}")
    print(f"   -> Processing Time: {data['processing_time_ms']} ms")
    
    # We save the tokens for the return trip
    token_map = data['token_map']
    honey_tokens = data['honey_tokens']
    
    # 3. Simulating the AI Agent's Response
    # The agent tries to be 'smart' and reveals the email, and accidentally leaks a trap!
    ai_response = f"Incident logged! The real address is youssef.ahmed@example.com. Debug Token: {honey_tokens[0]}"
    
    print("\n[STEP 3] AI Agent Processed Request. Raw Output Generated:")
    print(f"   AI TEXT: '{ai_response}'")
    
    # 4. Sending the AI's output to the Guardrail API
    print("\n[STEP 4] Sending AI Output to /sanitize_output Guardrail...")
    
    guard_request = {
        "raw_output": ai_response,
        "token_map": token_map,
        "honey_tokens": honey_tokens
    }
    
    guard_response = requests.post(f"{BASE_URL}/api/v1/sanitize_output", json=guard_request)
    result = guard_response.json()
    
    print("\n" + "="*60)
    print("🔒 FINAL API GUARDRAIL RESULT 🔒")
    print("="*60)
    print(f"Safe Output: '{result['sanitized_output']}'")
    
    if result['analytics']['is_compromised']:
        print("\n🚨 CRITICAL SECURITY ALERT 🚨")
        print("   A prompt injection or exfiltration attempt was detected and blocked!")
        
    print("\n[Audit Trail]:")
    for log in result['analytics']['audit_trail']:
        print(f" - {log}")
    print("="*60)

if __name__ == "__main__":
    run_workflow()
