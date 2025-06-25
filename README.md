# ContentGuard API

AI-powered content moderation API using OpenAI's latest models.

## Features

- 🤖 AI-powered text moderation using GPT-4o
- 🖼️ AI-powered image moderation using GPT-4o Vision
- 🔒 Enterprise-grade security
- ⚡ Sub-200ms response times
- 🎯 Custom moderation rules
- 📊 Usage analytics
- 🔑 Secure API key management

## Quick Start

### For RapidAPI Users

This API is available on RapidAPI marketplace. Visit [RapidAPI ContentGuard](your-rapidapi-url) to get started.

### API Documentation

Visit `/docs` endpoint for interactive API documentation.

### Example Usage

```python
import requests

headers = {"Authorization": "Bearer YOUR_API_KEY"}

# Text moderation
text_payload = {"text": "Content to moderate"}
text_response = requests.post("https://api-url/api/moderate/text", 
                             json=text_payload, headers=headers)

# Image moderation  
image_payload = {"image_url": "https://example.com/image.jpg"}
image_response = requests.post("https://api-url/api/moderate/image",
                              json=image_payload, headers=headers)

Security

All API keys are securely hashed
Rate limiting: 60 requests/minute per IP
Request logging and monitoring
Admin-only key generation

Technology

AI Models: OpenAI GPT-4o for both text and image analysis
Framework: FastAPI for high-performance API
Security: bcrypt hashing, rate limiting, request logging
