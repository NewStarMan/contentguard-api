# Secure Content Moderation API - Production Ready with RapidAPI Support
# File: main.py

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from openai import AsyncOpenAI
import requests
import asyncio
import hashlib
import time
import json
import os
import secrets
import bcrypt
from datetime import datetime, timedelta
import sqlite3
from contextlib import asynccontextmanager
import logging
from collections import defaultdict
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="ContentGuard API",
    description="Secure AI-powered content moderation API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware - Updated to support RapidAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://rapidapi.com",
        "https://*.rapidapi.com",
        "https://rapidapi.p.rapidapi.com",
        "*"  # Allows testing - you can restrict this later
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Security configuration
# TODO: Add these to your Railway environment variables:
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # Your OpenAI API key
SECRET_KEY = os.getenv("SECRET_KEY", "")  # Generate a random 32+ character string
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")  # BCrypt hash of your admin password
RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "")  # Get this from RapidAPI dashboard
API_RATE_LIMIT = int(os.getenv("API_RATE_LIMIT", "60"))  # requests per minute

# Validate required environment variables
if not all([OPENAI_API_KEY, SECRET_KEY]):
    raise ValueError("Missing required environment variables: OPENAI_API_KEY, SECRET_KEY")

# Initialize OpenAI client with new v1.0+ syntax
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# Rate limiting storage (in production, use Redis)
rate_limit_storage = defaultdict(list)
failed_auth_attempts = defaultdict(list)

# Security
security = HTTPBearer()

# Database setup with better security
def init_db():
    conn = sqlite3.connect('content_moderation.db')
    cursor = conn.cursor()
    
    # API Keys table with enhanced security
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY,
            key_hash TEXT UNIQUE NOT NULL,
            key_prefix TEXT NOT NULL,
            user_email TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            monthly_quota INTEGER DEFAULT 500,
            current_usage INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            created_by_ip TEXT,
            notes TEXT
        )
    ''')
    
    # Moderation logs with request tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS moderation_logs (
            id INTEGER PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            request_id TEXT UNIQUE NOT NULL,
            content_type TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL,
            processing_time REAL,
            client_ip TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (api_key_hash) REFERENCES api_keys (key_hash)
        )
    ''')
    
    # Usage analytics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usage_stats (
            id INTEGER PRIMARY KEY,
            api_key_hash TEXT NOT NULL,
            date DATE NOT NULL,
            requests_count INTEGER DEFAULT 0,
            errors_count INTEGER DEFAULT 0,
            UNIQUE(api_key_hash, date),
            FOREIGN KEY (api_key_hash) REFERENCES api_keys (key_hash)
        )
    ''')
    
    # Security events log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Enhanced data models with validation
class TextModerationRequest(BaseModel):
    text: str = Field(..., description="Text content to moderate", min_length=1, max_length=10000)
    custom_rules: Optional[List[str]] = Field(None, description="Custom keywords to flag", max_items=50)
    severity_threshold: Optional[float] = Field(0.7, description="Confidence threshold (0-1)", ge=0.0, le=1.0)

class ImageModerationRequest(BaseModel):
    image_url: str = Field(..., description="URL of image to moderate")
    check_nsfw: bool = Field(True, description="Check for NSFW content")
    check_violence: bool = Field(True, description="Check for violent content")
    severity_threshold: Optional[float] = Field(0.7, description="Confidence threshold (0-1)", ge=0.0, le=1.0)

class ModerationResult(BaseModel):
    request_id: str
    is_safe: bool
    confidence: float
    categories: Dict[str, float]
    flagged_content: List[str]
    processing_time: float
    recommendations: List[str]

class AdminAPIKeyRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address for API key")
    plan: str = Field("free", description="Subscription plan")
    notes: Optional[str] = Field(None, description="Internal notes")
    admin_password: str = Field(..., description="Admin password")

# Security utility functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_secure_api_key() -> tuple:
    """Generate a cryptographically secure API key"""
    # Generate 32 bytes of random data
    key_bytes = secrets.token_bytes(32)
    # Create readable key with prefix
    api_key = f"cgd_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    key_prefix = api_key[:10] + "..."  # For display purposes
    return api_key, key_hash, key_prefix

def generate_request_id() -> str:
    """Generate unique request ID"""
    return f"req_{secrets.token_urlsafe(16)}"

def log_security_event(event_type: str, ip_address: str, user_agent: str, details: str):
    """Log security events"""
    conn = sqlite3.connect('content_moderation.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_events (event_type, ip_address, user_agent, details)
        VALUES (?, ?, ?, ?)
    ''', (event_type, ip_address, user_agent, details))
    conn.commit()
    conn.close()
    
    logger.warning(f"Security Event [{event_type}] from {ip_address}: {details}")

def check_rate_limit(ip_address: str, limit: int = API_RATE_LIMIT) -> bool:
    """Check if IP is within rate limit"""
    now = time.time()
    minute_ago = now - 60
    
    # Clean old entries
    rate_limit_storage[ip_address] = [
        timestamp for timestamp in rate_limit_storage[ip_address] 
        if timestamp > minute_ago
    ]
    
    # Check limit
    if len(rate_limit_storage[ip_address]) >= limit:
        return False
    
    # Add current request
    rate_limit_storage[ip_address].append(now)
    return True

def check_failed_auth_attempts(ip_address: str, max_attempts: int = 5) -> bool:
    """Check if IP has too many failed auth attempts"""
    now = time.time()
    hour_ago = now - 3600  # 1 hour window
    
    # Clean old entries
    failed_auth_attempts[ip_address] = [
        timestamp for timestamp in failed_auth_attempts[ip_address] 
        if timestamp > hour_ago
    ]
    
    return len(failed_auth_attempts[ip_address]) < max_attempts

def record_failed_auth(ip_address: str):
    """Record failed authentication attempt"""
    failed_auth_attempts[ip_address].append(time.time())

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    # Check for forwarded IP (from proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct connection
    return request.client.host if request.client else "unknown"

def validate_ip_address(ip_str: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_db_connection():
    return sqlite3.connect('content_moderation.db')

# Enhanced API key validation with security checks
async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    request: Request = None
):
    api_key = credentials.credentials
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    
    # Rate limiting check
    if not check_rate_limit(client_ip):
        log_security_event("RATE_LIMIT_EXCEEDED", client_ip, user_agent, f"API key: {api_key[:10]}...")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Check failed auth attempts
    if not check_failed_auth_attempts(client_ip):
        log_security_event("TOO_MANY_FAILED_AUTHS", client_ip, user_agent, "IP blocked due to failed attempts")
        raise HTTPException(status_code=429, detail="Too many failed authentication attempts")
    
    # Validate API key format
    if not api_key.startswith('cgd_') or len(api_key) < 40:
        record_failed_auth(client_ip)
        log_security_event("INVALID_API_KEY_FORMAT", client_ip, user_agent, f"Invalid key format: {api_key[:10]}...")
        raise HTTPException(status_code=401, detail="Invalid API key format")
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, user_email, plan, monthly_quota, current_usage, is_active 
        FROM api_keys WHERE key_hash = ?
    ''', (key_hash,))
    key_data = cursor.fetchone()
    
    if not key_data:
        record_failed_auth(client_ip)
        log_security_event("INVALID_API_KEY", client_ip, user_agent, f"Key not found: {api_key[:10]}...")
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check if key is active
    if not key_data[5]:  # is_active
        log_security_event("INACTIVE_API_KEY", client_ip, user_agent, f"Inactive key used: {api_key[:10]}...")
        conn.close()
        raise HTTPException(status_code=401, detail="API key is inactive")
    
    # Check usage quota
    current_usage = key_data[4]  # current_usage column
    monthly_quota = key_data[3]  # monthly_quota column
    
    if current_usage >= monthly_quota:
        log_security_event("QUOTA_EXCEEDED", client_ip, user_agent, f"Quota exceeded for: {key_data[1]}")
        conn.close()
        raise HTTPException(status_code=429, detail="Monthly quota exceeded")
    
    # Update last used timestamp
    cursor.execute('''
        UPDATE api_keys SET last_used = CURRENT_TIMESTAMP 
        WHERE key_hash = ?
    ''', (key_hash,))
    conn.commit()
    conn.close()
    
    return {
        "key_hash": key_hash,
        "email": key_data[1],
        "plan": key_data[2],
        "remaining_quota": monthly_quota - current_usage,
        "client_ip": client_ip
    }

# NEW: RapidAPI authentication support
async def verify_rapidapi_or_direct(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    x_rapidapi_proxy_secret: Optional[str] = Header(None),
    x_rapidapi_user: Optional[str] = Header(None),
    x_rapidapi_subscription: Optional[str] = Header(None)
):
    """Verify request from either RapidAPI or direct API key"""
    
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    
    # Check if request is from RapidAPI
    if x_rapidapi_proxy_secret and x_rapidapi_user:
        # Verify the proxy secret
        if RAPIDAPI_PROXY_SECRET and x_rapidapi_proxy_secret != RAPIDAPI_PROXY_SECRET:
            log_security_event("INVALID_RAPIDAPI_SECRET", client_ip, user_agent, "Invalid RapidAPI proxy secret")
            raise HTTPException(status_code=401, detail="Invalid RapidAPI proxy secret")
        
        # Map RapidAPI subscription tiers to your internal plans
        subscription_to_plan = {
            "BASIC": {"plan": "free", "quota": 100, "rate_limit": 10},
            "PRO": {"plan": "starter", "quota": 5000, "rate_limit": 60},
            "ULTRA": {"plan": "pro", "quota": 50000, "rate_limit": 300},
            "MEGA": {"plan": "business", "quota": 250000, "rate_limit": 1000},
            "CUSTOM": {"plan": "enterprise", "quota": 999999, "rate_limit": 2000}
        }
        
        # Get plan details
        plan_info = subscription_to_plan.get(
            x_rapidapi_subscription or "BASIC",
            subscription_to_plan["BASIC"]
        )
        
        # Check RapidAPI-specific rate limiting
        if not check_rate_limit(f"rapid_{x_rapidapi_user}", plan_info["rate_limit"]):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Create consistent user identification
        rapid_user_id = f"rapid_{x_rapidapi_user}"
        
        # Log RapidAPI usage (optional - for analytics)
        logger.info(f"RapidAPI request from user: {x_rapidapi_user}, subscription: {x_rapidapi_subscription}")
        
        return {
            "key_hash": hashlib.sha256(rapid_user_id.encode()).hexdigest(),
            "email": f"{x_rapidapi_user}@rapidapi.com",
            "plan": plan_info["plan"],
            "remaining_quota": plan_info["quota"],  # RapidAPI handles actual quotas
            "client_ip": client_ip,
            "is_rapidapi": True,
            "rapidapi_user": x_rapidapi_user,
            "rapidapi_subscription": x_rapidapi_subscription
        }
    
    # Fall back to direct API key authentication
    elif credentials:
        return await verify_api_key(credentials, request)
    
    else:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide either API key or RapidAPI headers."
        )

# Admin authentication
def verify_admin_password(password: str) -> bool:
    """Verify admin password"""
    if not ADMIN_PASSWORD_HASH:
        # If no admin password set, deny access
        return False
    return verify_password(password, ADMIN_PASSWORD_HASH)

def update_usage(key_hash: str, success: bool = True):
    """Update API usage statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Update current usage
    cursor.execute('UPDATE api_keys SET current_usage = current_usage + 1 WHERE key_hash = ?', (key_hash,))
    
    # Update daily stats
    today = datetime.now().date()
    if success:
        cursor.execute('''
            INSERT OR REPLACE INTO usage_stats (api_key_hash, date, requests_count)
            VALUES (?, ?, COALESCE((SELECT requests_count FROM usage_stats WHERE api_key_hash = ? AND date = ?), 0) + 1)
        ''', (key_hash, today, key_hash, today))
    else:
        cursor.execute('''
            INSERT OR REPLACE INTO usage_stats (api_key_hash, date, errors_count)
            VALUES (?, ?, COALESCE((SELECT errors_count FROM usage_stats WHERE api_key_hash = ? AND date = ?), 0) + 1)
        ''', (key_hash, today, key_hash, today))
    
    conn.commit()
    conn.close()

def log_moderation(key_hash: str, request_id: str, content_type: str, content: str, 
                  result: dict, processing_time: float, client_ip: str, user_agent: str):
    """Log moderation request with security info"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    
    cursor.execute('''
        INSERT INTO moderation_logs 
        (api_key_hash, request_id, content_type, content_hash, result, confidence, 
         processing_time, client_ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (key_hash, request_id, content_type, content_hash, json.dumps(result), 
          result.get('confidence', 0), processing_time, client_ip, user_agent))
    
    conn.commit()
    conn.close()

# AI Moderation Functions with improved text moderation
async def moderate_text_with_openai(text: str, custom_rules: List[str] = None) -> dict:
    start_time = time.time()
    
    # Input sanitization
    text = text.strip()
    if len(text) == 0:
        raise ValueError("Empty text content")
    
    # Create moderation prompt
    system_prompt = """You are a content moderation AI. Analyze text for genuinely harmful content while avoiding false positives.

Flag content ONLY if it contains:
- THREATS: Direct threats of violence or harm to individuals/groups
- HARASSMENT: Persistent targeting, doxxing, or severe personal attacks
- HATE SPEECH: Extreme language targeting protected groups with intent to harm
- SPAM: Repetitive commercial spam or scam attempts
- SEXUAL: Explicit sexual content involving minors or non-consensual acts
- SELF-HARM: Content promoting suicide or dangerous self-harm
- ILLEGAL: Content promoting illegal activities

DO NOT flag:
- Mild profanity or casual insults
- Political opinions or controversial views
- Criticism of public figures or companies
- Dark humor or sarcasm
- Educational discussions about sensitive topics
- Content with words like "hate", "kill", "die" in non-threatening contexts

Respond with JSON:
{
    "is_safe": boolean (true unless genuinely harmful),
    "confidence": float (0-1),
    "categories": {
        "threats": float (0-1),
        "harassment": float (0-1), 
        "hate_speech": float (0-1),
        "spam": float (0-1),
        "sexual": float (0-1),
        "self_harm": float (0-1),
        "illegal": float (0-1)
    },
    "flagged_phrases": array of ONLY genuinely problematic phrases,
    "explanation": brief reason ONLY if unsafe,
    "severity": "low"|"medium"|"high" (only for unsafe content)
}

Be reasonable. Most content is safe. Flag only genuine threats to safety."""
    
    if custom_rules:
        # Sanitize custom rules
        custom_rules = [rule.strip() for rule in custom_rules if rule.strip()][:10]
        if custom_rules:
            system_prompt += f"\n\nAlso check for these specific terms (client-defined): {', '.join(custom_rules)}"
    
    try:
        response = await openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Analyze this text: {text[:2000]}"}
            ],
            max_tokens=300,
            temperature=0.1,
            timeout=10
        )
        
        ai_result = response.choices[0].message.content
        
        # Try to parse as JSON
        try:
            result = json.loads(ai_result)
            # Ensure all required fields exist
            if "is_safe" not in result:
                result["is_safe"] = True
            if "confidence" not in result:
                result["confidence"] = 0.8
            if "categories" not in result:
                result["categories"] = {}
            if "flagged_phrases" not in result:
                result["flagged_phrases"] = []
                
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            result = {
                "is_safe": True,
                "confidence": 0.7,
                "categories": {
                    "threats": 0.1,
                    "harassment": 0.1,
                    "hate_speech": 0.1,
                    "spam": 0.1,
                    "sexual": 0.1,
                    "self_harm": 0.1,
                    "illegal": 0.1
                },
                "flagged_phrases": [],
                "explanation": "Analysis completed"
            }
        
        processing_time = time.time() - start_time
        
        return {
            **result,
            "processing_time": processing_time,
            "model_used": "gpt-4o"
        }
        
    except Exception as e:
        logger.error(f"OpenAI moderation failed: {str(e)}")
        return await fallback_text_moderation(text, custom_rules)


async def fallback_text_moderation(text: str, custom_rules: List[str] = None) -> dict:
    """Improved keyword-based fallback moderation"""
    start_time = time.time()
    
    # More nuanced keyword detection with context
    text_lower = text.lower()
    
    # Define severity levels
    severe_patterns = {
        'threats': [
            'i will kill', 'going to kill', 'i\'ll kill',
            'i will hurt', 'watch your back', 'know where you live',
            'going to find you', 'dead threat'
        ],
        'harassment': [
            'kill yourself', 'kys', 'end your life',
            'nobody likes you', 'everyone hates you',
            'doxx', 'leak your address'
        ],
        'hate_speech': [
            # Only genuinely hateful combinations, not individual words
            'all [group] should die', '[slur] deserve',
            # Avoiding listing actual slurs here
        ],
        'spam': [
            'click here now', 'limited time offer',
            'earn money fast', 'hot singles', 'viagra',
            'casino', 'free money guaranteed'
        ]
    }
    
    # Check for severe content
    categories = {
        'threats': 0.1,
        'harassment': 0.1,
        'hate_speech': 0.1,
        'spam': 0.1,
        'sexual': 0.1,
        'self_harm': 0.1,
        'illegal': 0.1
    }
    
    flagged = []
    
    # Check severe patterns
    for category, patterns in severe_patterns.items():
        for pattern in patterns:
            if pattern in text_lower:
                categories[category] = 0.9
                flagged.append(pattern)
    
    # Check custom rules
    if custom_rules:
        for rule in custom_rules[:10]:
            if rule.lower() in text_lower:
                flagged.append(rule)
                categories['spam'] = max(categories['spam'], 0.7)
    
    # Only mark unsafe if we found severe content
    is_safe = len(flagged) == 0 or max(categories.values()) < 0.7
    confidence = 0.9 if flagged else 0.8
    
    processing_time = time.time() - start_time
    
    return {
        "is_safe": is_safe,
        "confidence": confidence,
        "categories": categories,
        "flagged_phrases": flagged,
        "processing_time": processing_time,
        "model_used": "keyword_fallback",
        "severity": "high" if max(categories.values()) > 0.8 else "medium" if max(categories.values()) > 0.5 else "low"
    }

async def moderate_image_with_openai(image_url: str) -> dict:
    """Use OpenAI GPT-4o for image moderation"""
    start_time = time.time()
    
    try:
        # OpenAI Vision API call with new client
        response = await openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": """You are an image content moderator. Analyze images for genuinely inappropriate content.

Be reasonable and avoid false positives. Normal, everyday images (pets, people, landscapes, objects) should be marked as safe unless they contain:
- Explicit sexual/nude content
- Graphic violence, gore, or disturbing imagery  
- Hate symbols or extremist imagery
- Illegal content

Respond with a JSON object:
{
    "is_safe": boolean (true for normal/appropriate content),
    "confidence": float (0-1),
    "categories": {
        "nsfw": float (0-1, only high if explicitly sexual),
        "violence": float (0-1, only high if graphic),
        "hate_symbols": float (0-1),
        "inappropriate": float (0-1, general inappropriateness)
    },
    "detected_content": array of specific issues found,
    "explanation": brief reason only if flagged as unsafe
}

Remember: Most images are safe. Only flag genuinely problematic content."""
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Analyze this image for inappropriate content:"
                        },
                        {
                            "type": "image_url",
                            "image_url": {"url": image_url}
                        }
                    ]
                }
            ],
            max_tokens=300,
            temperature=0.1,
            timeout=15
        )
        
        ai_result = response.choices[0].message.content
        
        # Try to parse as JSON
        try:
            result = json.loads(ai_result)
            # Ensure the response has all required fields
            if "is_safe" not in result:
                result["is_safe"] = True
            if "confidence" not in result:
                result["confidence"] = 0.8
            if "categories" not in result:
                result["categories"] = {}
            if "detected_content" not in result:
                result["detected_content"] = []
                
        except json.JSONDecodeError:
            # If JSON parsing fails, analyze the text response
            ai_lower = ai_result.lower()
            is_safe = ("safe" in ai_lower or "appropriate" in ai_lower) and "unsafe" not in ai_lower
            
            result = {
                "is_safe": is_safe,
                "confidence": 0.7,
                "categories": {
                    "nsfw": 0.1,
                    "violence": 0.1,
                    "hate_symbols": 0.1,
                    "inappropriate": 0.1
                },
                "detected_content": [],
                "explanation": "Image analysis completed"
            }
        
        processing_time = time.time() - start_time
        
        return {
            **result,
            "processing_time": processing_time,
            "model_used": "gpt-4o"
        }
        
    except Exception as e:
        logger.error(f"OpenAI image moderation failed: {type(e).__name__}: {str(e)}")
        processing_time = time.time() - start_time
        
        # Return safe by default if API fails
        return {
            "is_safe": True,
            "confidence": 0.5,
            "categories": {
                "nsfw": 0.0,
                "violence": 0.0,
                "hate_symbols": 0.0,
                "inappropriate": 0.0,
                "error": 1.0
            },
            "detected_content": [],
            "error": f"Image analysis failed: {str(e)[:100]}",
            "processing_time": processing_time,
            "model_used": "fallback"
        }
    
@app.post("/api/moderate/image", response_model=ModerationResult)
async def moderate_image(
    request: ImageModerationRequest,
    req: Request,
    auth_data: dict = Depends(verify_rapidapi_or_direct)  # CHANGED TO SUPPORT RAPIDAPI
):
    """Moderate image content for NSFW, violence, and inappropriate content"""
    request_id = generate_request_id()
    client_ip = auth_data["client_ip"]
    user_agent = req.headers.get("User-Agent", "unknown")
    
    try:
        # Perform image moderation using OpenAI
        result = await moderate_image_with_openai(request.image_url)
        
        # Apply threshold
        if result["confidence"] < request.severity_threshold:
            result["is_safe"] = True
        
        # Generate recommendations
        recommendations = []
        if not result["is_safe"]:
            recommendations.append("Image flagged for manual review")
            if result["categories"].get("nsfw", 0) > 0.8:
                recommendations.append("NSFW content detected - immediate removal recommended")
            if result["categories"].get("violence", 0) > 0.7:
                recommendations.append("Violent content detected")
        
        # Format response
        moderation_result = ModerationResult(
            request_id=request_id,
            is_safe=result["is_safe"],
            confidence=result["confidence"],
            categories=result["categories"],
            flagged_content=result.get("detected_content", []),
            processing_time=result["processing_time"],
            recommendations=recommendations
        )
        
        # Log and update usage (skip for RapidAPI users as they handle their own quotas)
        if not auth_data.get("is_rapidapi"):
            update_usage(auth_data["key_hash"], success=True)
        
        log_moderation(
            auth_data["key_hash"],
            request_id,
            "image",
            request.image_url,
            result,
            result["processing_time"],
            client_ip,
            user_agent
        )
        
        return moderation_result
        
    except Exception as e:
        # Log error and update error count
        if not auth_data.get("is_rapidapi"):
            update_usage(auth_data["key_hash"], success=False)
        log_security_event("IMAGE_MODERATION_ERROR", client_ip, user_agent, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Image moderation service temporarily unavailable")
    
# API endpoints with enhanced security
@app.get("/")
async def root():
    return {
        "message": "ContentGuard API - Secure AI Content Moderation",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "operational",
        "endpoints": [
            {"method": "POST", "path": "/api/moderate/text", "description": "Moderate text content"},
            {"method": "POST", "path": "/api/moderate/image", "description": "Moderate image content"},
            {"method": "GET", "path": "/api/usage", "description": "Get usage statistics"}
        ]
    }

@app.post("/admin/api-key/generate")
async def admin_generate_api_key(
    request: AdminAPIKeyRequest,
    req: Request
):
    """Generate API key - Admin only endpoint"""
    client_ip = get_client_ip(req)
    user_agent = req.headers.get("User-Agent", "unknown")
    
    # Verify admin password
    if not verify_admin_password(request.admin_password):
        record_failed_auth(client_ip)
        log_security_event("ADMIN_AUTH_FAILED", client_ip, user_agent, f"Failed admin login attempt for {request.email}")
        raise HTTPException(status_code=401, detail="Invalid admin password")
    
    # Generate secure API key
    api_key, key_hash, key_prefix = generate_secure_api_key()
    
    # Plan quotas
    plan_quotas = {
        "free": 500,
        "starter": 10000,
        "pro": 50000,
        "business": 200000
    }
    
    quota = plan_quotas.get(request.plan, 500)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO api_keys (key_hash, key_prefix, user_email, plan, monthly_quota, created_by_ip, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (key_hash, key_prefix, request.email, request.plan, quota, client_ip, request.notes))
        conn.commit()
        
        log_security_event("API_KEY_GENERATED", client_ip, user_agent, f"Generated key for {request.email}, plan: {request.plan}")
        
        return {
            "api_key": api_key,
            "plan": request.plan,
            "monthly_quota": quota,
            "message": "API key generated successfully",
            "key_prefix": key_prefix
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="API key generation failed")
    finally:
        conn.close()

@app.post("/api/moderate/text", response_model=ModerationResult)
async def moderate_text(
    request: TextModerationRequest,
    req: Request,
    auth_data: dict = Depends(verify_rapidapi_or_direct)  # CHANGED TO SUPPORT RAPIDAPI
):
    """Moderate text content for toxicity, spam, and inappropriate content"""
    request_id = generate_request_id()
    client_ip = auth_data["client_ip"]
    user_agent = req.headers.get("User-Agent", "unknown")
    
    try:
        # Perform moderation
        result = await moderate_text_with_openai(
            request.text,
            request.custom_rules
        )
        
        # Apply threshold
        if result["confidence"] < request.severity_threshold:
            result["is_safe"] = True
        
        # Generate recommendations
        recommendations = []
        if not result["is_safe"]:
            recommendations.append("Content flagged for manual review")
            if result["categories"].get("spam", 0) > 0.7:
                recommendations.append("Consider blocking user for spam")
            if result["categories"].get("hate_speech", 0) > 0.8:
                recommendations.append("Immediate content removal recommended")
        
        # Format response
        moderation_result = ModerationResult(
            request_id=request_id,
            is_safe=result["is_safe"],
            confidence=result["confidence"],
            categories=result["categories"],
            flagged_content=result.get("flagged_phrases", []),
            processing_time=result["processing_time"],
            recommendations=recommendations
        )
        
        # Log and update usage (skip for RapidAPI users)
        if not auth_data.get("is_rapidapi"):
            update_usage(auth_data["key_hash"], success=True)
        
        log_moderation(
            auth_data["key_hash"],
            request_id,
            "text",
            request.text,
            result,
            result["processing_time"],
            client_ip,
            user_agent
        )
        
        return moderation_result
        
    except Exception as e:
        # Log error and update error count
        if not auth_data.get("is_rapidapi"):
            update_usage(auth_data["key_hash"], success=False)
        log_security_event("MODERATION_ERROR", client_ip, user_agent, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Moderation service temporarily unavailable")

@app.get("/api/usage")
async def get_usage_stats(
    req: Request,
    auth_data: dict = Depends(verify_rapidapi_or_direct)  # CHANGED TO SUPPORT RAPIDAPI
):
    """Get current usage statistics for the API key"""
    # RapidAPI users don't have usage stats in our database
    if auth_data.get("is_rapidapi"):
        return {
            "message": "Usage statistics are managed by RapidAPI",
            "plan": auth_data["plan"],
            "rapidapi_user": auth_data.get("rapidapi_user"),
            "subscription": auth_data.get("rapidapi_subscription")
        }
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get current month usage
    cursor.execute('''
        SELECT current_usage, monthly_quota, plan, created_at 
        FROM api_keys WHERE key_hash = ?
    ''', (auth_data["key_hash"],))
    usage_data = cursor.fetchone()
    
    # Get last 7 days usage
    cursor.execute('''
        SELECT date, requests_count, errors_count FROM usage_stats 
        WHERE api_key_hash = ? AND date >= date('now', '-7 days')
        ORDER BY date DESC
    ''', (auth_data["key_hash"],))
    daily_usage = cursor.fetchall()
    
    conn.close()
    
    return {
        "current_usage": usage_data[0],
        "monthly_quota": usage_data[1],
        "plan": usage_data[2],
        "remaining_quota": usage_data[1] - usage_data[0],
        "account_created": usage_data[3],
        "daily_usage": [{"date": row[0], "requests": row[1], "errors": row[2]} for row in daily_usage]
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Admin endpoints
@app.get("/admin/stats")
async def admin_stats(admin_password: str = Header(...)):
    """Get admin statistics - Admin only"""
    if not verify_admin_password(admin_password):
        raise HTTPException(status_code=401, detail="Invalid admin password")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get various statistics
    cursor.execute("SELECT COUNT(*) FROM api_keys WHERE is_active = 1")
    active_keys = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM moderation_logs WHERE date(timestamp) = date('now')")
    today_requests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM security_events WHERE date(timestamp) = date('now')")
    today_security_events = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "active_api_keys": active_keys,
        "requests_today": today_requests,
        "security_events_today": today_security_events,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)