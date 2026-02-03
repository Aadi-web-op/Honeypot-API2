#!/usr/bin/env python3
"""
Test script for Honeypot API
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
            "name": "Bank Phishing",
            "message": "Your SBI account has been blocked. Please pay 500 to unblock@sbi to unlock. Call 9876543210 immediately."
        },
        {
            "name": "UPI Fraud", 
            "message": "You have received 50000 in your UPI. Click here to claim: http://fake-upi.com/claim"
        },
        {
            "name": "Loan Scam",
            "message": "Instant loan approval! Get 1 lakh in 5 minutes. Contact loan@quickcash.com. Call 8765432109"
        },
        {
            "name": "Job Scam",
            "message": "Work from home job! Earn 50000 per month. Send your resume to hr@fakejob.com"
        },
        {
            "name": "Normal Message",
            "message": "Hi, how are you doing today?"
        }
    ]
    
    for test_case in test_cases:
        print(f"🔍 Testing {test_case['name']}...")
        payload = {"message": test_case['message']}
        
        response = requests.post(
            f"{BASE_URL}/analyze",
            headers=HEADERS,
            json=payload
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Scam Type: {result['extracted_intelligence']['scam_type']}")
            print(f"Confidence: {result['extracted_intelligence']['confidence_score']}")
            print(f"UPI IDs: {result['extracted_intelligence']['upi_ids']}")
            print(f"Phone Numbers: {result['extracted_intelligence']['phone_numbers']}")
            print(f"Links: {result['extracted_intelligence']['phishing_links']}")
            print(f"Response: {result['agent_response']}")
        else:
            print(f"Error: {response.text}")
        print("-" * 50)

def test_invalid_api_key():
    """Test with invalid API key"""
    print("🔍 Testing invalid API key...")
    invalid_headers = {
        "x-api-key": "invalid_key",
        "Content-Type": "application/json"
    }
    
    payload = {"message": "Test message"}
    response = requests.post(
        f"{BASE_URL}/analyze",
        headers=invalid_headers,
        json=payload
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

if __name__ == "__main__":
    print("🚀 Testing Honeypot API")
    print("=" * 50)
    
    try:
        test_health()
        test_root()
        test_scam_analysis()
        test_invalid_api_key()
        
        print("✅ All tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to API. Make sure the server is running on localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")
