#!/usr/bin/env python3
"""
Comprehensive test script for Honeypot API with multiple parameters
"""

import requests
import json

# API configuration
BASE_URL = "http://localhost:8000"
API_KEY = "honeypot_key_2026_eval"
HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_root():
    """Test root endpoint"""
    print("🔍 Testing root endpoint...")
    response = requests.get(f"{BASE_URL}/")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_scam_analysis():
    """Test scam analysis with various scam messages"""
    test_cases = [
        {
            "name": "Bank Phishing with UPI",
            "message": "Your SBI account has been blocked due to KYC issues. Please pay 500 to unblock@oksbi to unlock. Call 9876543210 immediately. Visit http://secure-sbi.com/update",
            "session_id": "test_session_001"
        },
        {
            "name": "UPI Fraud with Multiple UPI IDs", 
            "message": "You have received 50000 in your UPI. Click here to claim: http://fake-upi.com/claim. Send processing fee to payment@paytm or refund@phonepe",
            "session_id": None
        },
        {
            "name": "Loan Scam with Bank Account",
            "message": "Instant loan approval! Get 1 lakh in 5 minutes. Transfer processing fee to account 1234567890123456. Contact loan@quickcash.com. Call 8765432109",
            "session_id": "loan_test_002"
        },
        {
            "name": "Investment Scam with Multiple Contacts",
            "message": "Double your money in 30 days! Invest 10000 get 20000. Call +91-9876543210 or 7890123456. Send money to invest@okaxis. Website: www.getrichquick.com",
            "session_id": None
        },
        {
            "name": "Job Scam with Email",
            "message": "Work from home job! Earn 50000 per month. Send your resume to hr@fakejob.com. Call 9876543210 for interview. Apply at www.career-portal.com/jobs",
            "session_id": "job_session_003"
        },
        {
            "name": "Prize Scam",
            "message": "Congratulations! You won 25 lakh in lottery. Claim your prize by calling 9123456789. Pay tax to prize@okicici. Visit http://winner-claim.com",
            "session_id": None
        },
        {
            "name": "Complex Multi-Scam",
            "message": "URGENT: Your account 987654321098 will be blocked. Pay 1000 to verify@okhdfcbank. Call +91 8765432109. Also apply for instant loan at quickloan@oksbi. Visit http://bank-secure.com",
            "session_id": "complex_test_004"
        },
        {
            "name": "Normal Message",
            "message": "Hi, how are you doing today? Let's meet tomorrow at 5pm.",
            "session_id": None
        },
        {
            "name": "Edge Case - Only Numbers",
            "message": "Account 123456789. Call 9876543210. Pay to user@paytm",
            "session_id": None
        },
        {
            "name": "Edge Case - Multiple Links",
            "message": "Visit http://fake-bank.com or www.scam-site.net. Also check https://phishing-page.org/secure",
            "session_id": None
        }
    ]
    
    for test_case in test_cases:
        print(f"🔍 Testing {test_case['name']}...")
        payload = {"message": test_case['message']}
        
        # Add session_id if provided
        if test_case['session_id']:
            payload["session_id"] = test_case['session_id']
        
        response = requests.post(
            f"{BASE_URL}/analyze",
            headers=HEADERS,
            json=payload
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Session ID: {result['session_id']}")
            print(f"Scam Type: {result['extracted_intelligence']['scam_type']}")
            print(f"Confidence: {result['extracted_intelligence']['confidence_score']}")
            print(f"UPI IDs: {result['extracted_intelligence']['upi_ids']}")
            print(f"Bank Accounts: {result['extracted_intelligence']['bank_accounts']}")
            print(f"Phone Numbers: {result['extracted_intelligence']['phone_numbers']}")
            print(f"Links: {result['extracted_intelligence']['phishing_links']}")
            print(f"Response: {result['agent_response']}")
        else:
            print(f"Error: {response.text}")
        print("-" * 60)

def test_edge_cases():
    """Test edge cases and error conditions"""
    print("🔍 Testing edge cases...")
    
    edge_cases = [
        {
            "name": "Empty message",
            "payload": {"message": ""}
        },
        {
            "name": "Very long message",
            "payload": {"message": "SCAM " * 1000}
        },
        {
            "name": "Special characters",
            "payload": {"message": "Your account @#$%^&*() blocked! Call +91-9876543210! Pay to user@oksbi 💰"}
        },
        {
            "name": "Mixed case UPI",
            "payload": {"message": "Pay to USER@OKSBI or admin@PAYTM now!"}
        },
        {
            "name": "Invalid JSON structure test",
            "payload": {"invalid_field": "test"}
        }
    ]
    
    for case in edge_cases:
        print(f"Testing {case['name']}...")
        response = requests.post(
            f"{BASE_URL}/analyze",
            headers=HEADERS,
            json=case['payload']
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Handled successfully - Scam Type: {result['extracted_intelligence']['scam_type']}")
        else:
            print(f"⚠️  Error response: {response.text}")
        print("-" * 40)

def test_performance():
    """Test API performance with multiple requests"""
    print("🔍 Testing performance with 10 concurrent requests...")
    import time
    import threading
    
    def make_request():
        payload = {"message": "Your bank account is blocked. Call 9876543210. Pay to unblock@oksbi"}
        start_time = time.time()
        response = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
        end_time = time.time()
        return response.status_code, end_time - start_time
    
    threads = []
    results = []
    
    def worker():
        status, duration = make_request()
        results.append((status, duration))
    
    start_time = time.time()
    for _ in range(10):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    
    success_count = sum(1 for status, _ in results if status == 200)
    avg_response_time = sum(duration for _, duration in results) / len(results)
    
    print(f"Total time: {end_time - start_time:.2f}s")
    print(f"Success rate: {success_count}/10 ({success_count*10}%)")
    print(f"Average response time: {avg_response_time:.3f}s")
    print()

if __name__ == "__main__":
    print("🚀 Comprehensive Testing of Honeypot API")
    print("=" * 60)
    
    try:
        test_health()
        test_root()
        test_scam_analysis()
        test_edge_cases()
        test_performance()
        
        print("✅ All comprehensive tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to API. Make sure the server is running on localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")
