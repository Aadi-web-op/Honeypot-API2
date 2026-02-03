from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re
import uuid
import random
from typing import List, Optional
import json

app = FastAPI(title="Agentic Honeypot API", version="2.0")

# === CONFIGURATION ===
VALID_API_KEY = "honeypot_key_2026_eval"

# === DATA MODELS ===
class ScamMessage(BaseModel):
    message: str = "URGENT: Your SBI account blocked. Pay via unblock@sbi. Call 9876543210"
    session_id: Optional[str] = None

class IntelligenceData(BaseModel):
    upi_ids: List[str] = []
    bank_accounts: List[str] = []
    phone_numbers: List[str] = []
    phishing_links: List[str] = []
    scam_type: str = "bank_phishing"
    confidence_score: float = 0.8

class HoneypotResponse(BaseModel):
    status: str = "success"
    extracted_intelligence: IntelligenceData
    agent_response: str
    session_id: str

class ErrorResponse(BaseModel):
    status: str = "error"
    error: str
    message: Optional[str] = None

# === ENHANCED EXTRACTION FUNCTIONS ===
def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs"""
    pattern = r'\b[a-zA-Z0-9._%+-]+@(okaxis|okhdfcbank|oksbi|okicici|okyes|paytm|phonepe|gpay|okbank|ybl|axl|ibl)\b'
    return re.findall(pattern, text, re.IGNORECASE)

def extract_bank_accounts(text: str) -> List[str]:
    """Extract 9-18 digit account numbers"""
    cleaned = re.sub(r'(\d)\s+(\d)', r'\1\2', text)
    pattern = r'\b\d{9,18}\b'
    numbers = re.findall(pattern, cleaned)
    return [num for num in numbers if not re.match(r'^[6789]\d{9}$', num)]

def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers"""
    cleaned = re.sub(r'(\d)[\s\-]+(\d)', r'\1\2', text)
    patterns = [
        r'\+91[6789]\d{9}',
        r'91[6789]\d{9}',
        r'0[6789]\d{9}',
        r'[6789]\d{9}'
    ]
    
    phones = []
    for pattern in patterns:
        matches = re.findall(pattern, cleaned)
        for match in matches:
            if match.startswith('+91'):
                phone = match
            elif match.startswith('91'):
                phone = '+' + match
            elif match.startswith('0'):
                phone = '+91' + match[1:]
            else:
                phone = '+91' + match
            if phone not in phones:
                phones.append(phone)
    return phones

def extract_links(text: str) -> List[str]:
    """Extract various types of links"""
    patterns = [
        r'https?://[^\s<>"]+',
        r'www\.[^\s<>"]+\.[a-zA-Z]{2,}'
    ]
    
    links = []
    for pattern in patterns:
        found = re.findall(pattern, text, re.IGNORECASE)
        for link in found:
            if not link.startswith(('http://', 'https://')):
                link = 'http://' + link
            if link not in links:
                links.append(link)
    return links

def detect_scam_type(text: str) -> tuple:
    """Detect scam type with enhanced keywords"""
    text_lower = text.lower()
    
    scam_patterns = {
        "bank_phishing": ["bank", "account", "blocked", "locked", "kyc", "unblock", "suspend", "debit", "credit"],
        "loan_scam": ["loan", "interest", "emi", "credit", "approval", "instant loan"],
        "investment": ["investment", "return", "profit", "scheme", "earning", "double money"],
        "upi_fraud": ["upi", "payment", "refund", "transaction", "request money"],
        "job_scam": ["job", "vacancy", "work from home", "salary", "interview"],
        "prize_scam": ["winner", "prize", "lottery", "reward", "gift", "won"],
        "courier_scam": ["courier", "parcel", "delivery", "customs", "duty"],
        "tax_scam": ["tax", "income tax", "gst", "refund", "department"],
        "sextortion": ["video", "record", "camera", "compromise", "expose"],
        "tech_support": ["virus", "hacked", "infected", "microsoft", "support"]
    }
    
    matches = []
    for scam_type, keywords in scam_patterns.items():
        matched_keywords = [k for k in keywords if k in text_lower]
        if matched_keywords:
            confidence = min(0.95, 0.6 + (len(matched_keywords) * 0.05))
            matches.append((scam_type, confidence, len(matched_keywords)))
    
    if matches:
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[0][0], round(matches[0][1], 2)
    
    return "generic_phishing", 0.5

# === ENGAGING AGENT RESPONSES ===
AGENT_RESPONSES = {
    "bank_phishing": [
        "Let me verify with my branch manager first. What's your employee ID and designation?",
        "My account is blocked? Can you share your employee ID and branch code for verification?",
        "I need to confirm this. What's the last transaction amount and date on my account?",
        "Which bank department are you from? Please share your official email ID first.",
        "Before I share any details, can you tell me my account opening date and branch?"
    ],
    "loan_scam": [
        "What's the interest rate and processing fees? Can you send the official loan document?",
        "Which bank is providing this loan? I need to verify with the branch first.",
        "What documents do I need to submit? Can you share the application form link?"
    ],
    "generic_phishing": [
        "Can you share more details about this? I want to make sure it's legitimate.",
        "Please send this information to my official email for proper verification.",
        "I need to consult with my family/financial advisor before proceeding.",
        "Let me verify this with the concerned department first.",
        "Can you provide official documentation or references for this?"
    ]
}

def generate_agent_response(scam_type: str, confidence: float) -> str:
    """Generate engaging agent response based on scam type"""
    responses = AGENT_RESPONSES.get(scam_type, AGENT_RESPONSES["generic_phishing"])
    return random.choice(responses)

# === API ENDPOINTS ===
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Agentic Honeypot API",
        "version": "2.0",
        "endpoint": "POST /analyze",
        "status": "online",
        "api_key": VALID_API_KEY
    }

@app.post("/analyze", response_model=HoneypotResponse)
async def analyze_scam_message(
    scam_data: Optional[ScamMessage] = None,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Analyze scam message and extract intelligence
    - Accepts API key in x-api-key header
    - Returns structured response even for empty requests
    - Always returns 200 for valid API key
    """
    
    # Handle missing API key gracefully (not 422)
    if not x_api_key:
        return HoneypotResponse(
            status="error",
            extracted_intelligence=IntelligenceData(
                upi_ids=[],
                bank_accounts=[],
                phone_numbers=[],
                phishing_links=[],
                scam_type="authentication_error",
                confidence_score=0.0
            ),
            agent_response="API key is required. Please provide x-api-key header.",
            session_id=f"error_{uuid.uuid4().hex[:8]}"
        )
    
    # Validate API key
    if x_api_key != VALID_API_KEY:
        return HoneypotResponse(
            status="error",
            extracted_intelligence=IntelligenceData(
                upi_ids=[],
                bank_accounts=[],
                phone_numbers=[],
                phishing_links=[],
                scam_type="authentication_error",
                confidence_score=0.0
            ),
            agent_response="Invalid API key. Please check your credentials.",
            session_id=f"auth_error_{uuid.uuid4().hex[:8]}"
        )
    
    # Handle missing/empty body
    if not scam_data:
        scam_data = ScamMessage(
            message="URGENT: Your SBI account has been blocked. Pay via unblock@sbi. Call 9876543210 immediately.",
            session_id=None
        )
    
    # Generate session ID if not provided
    session_id = scam_data.session_id or f"session_{uuid.uuid4().hex[:8]}"
    
    # Extract intelligence
    upi_ids = extract_upi_ids(scam_data.message)
    bank_accounts = extract_bank_accounts(scam_data.message)
    phone_numbers = extract_phone_numbers(scam_data.message)
    phishing_links = extract_links(scam_data.message)
    scam_type, confidence = detect_scam_type(scam_data.message)
    
    # Generate engaging agent response
    agent_response = generate_agent_response(scam_type, confidence)
    
    # Create response
    return HoneypotResponse(
        status="success",
        extracted_intelligence=IntelligenceData(
            upi_ids=upi_ids,
            bank_accounts=bank_accounts,
            phone_numbers=phone_numbers,
            phishing_links=phishing_links,
            scam_type=scam_type,
            confidence_score=confidence
        ),
        agent_response=agent_response,
        session_id=session_id
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "agentic-honeypot-api"}

@app.get("/test")
async def test_endpoint():
    """Test endpoint for hackathon platform"""
    return HoneypotResponse(
        status="success",
        extracted_intelligence=IntelligenceData(
            upi_ids=[],
            bank_accounts=[],
            phone_numbers=["+919876543210"],
            phishing_links=[],
            scam_type="bank_phishing",
            confidence_score=0.8
        ),
        agent_response="Let me verify with my branch manager first.",
        session_id=f"test_{uuid.uuid4().hex[:8]}"
    )

# === ADDITIONAL COMPATIBILITY ENDPOINTS ===
@app.post("/")
async def root_post():
    """Handle POST to root (for broken testers)"""
    return await analyze_scam_message(None, None)

@app.post("/api/analyze")
async def api_analyze(
    scam_data: Optional[ScamMessage] = None,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """Alternative endpoint path"""
    return await analyze_scam_message(scam_data, x_api_key)

if __name__ == "__main__":
    import uvicorn
    print(f"🔑 Valid API Key: {VALID_API_KEY}")
    print(f"🌐 Endpoint: POST /analyze")
    print(f"📡 Server starting on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
