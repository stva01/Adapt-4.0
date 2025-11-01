from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from groq import Groq
import httpx
import os
import json
import hmac
import hashlib
from typing import Optional, Union, Dict, Any
from enum import IntEnum

# Configuration
SEND_URL = "http://localhost:8008"  # Fixed URL format
GITHUB_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')

# Initialize FastAPI app
app = FastAPI(
    title="Cyber Security API",
    description="Combined API for threat classification and GitHub webhook security analysis using Groq AI",
    version="1.0.0"
)

# Groq client initialization
groq_client = Groq(
    api_key=GROQ_API_KEY
)

# Define threat levels
class ThreatLevel(IntEnum):
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

# Request model for threat analysis
class ThreatAnalysisRequest(BaseModel):
    data: Union[str, Dict[str, Any]] = Field(
        ...,
        description="Unstructured data as string or JSON object to analyze for cyber threats"
    )
    model: Optional[str] = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model to use for analysis"
    )

# Response model for threat analysis
class ThreatAnalysisResponse(BaseModel):
    threat_level: int = Field(..., ge=1, le=5, description="Threat level from 1-5")
    threat_category: str = Field(..., description="Category of the threat")
    analysis: str = Field(..., description="Detailed analysis of the threat")
    raw_data: Union[str, Dict[str, Any]] = Field(..., description="Original input data")
    model_used: str = Field(..., description="Groq model used for analysis")

# Endpoint forwarding model
class ForwardedResult(BaseModel):
    success: bool
    message: str
    original_response: Optional[ThreatAnalysisResponse] = None

# GitHub webhook models
class GitHubWebhookResponse(BaseModel):
    status: str
    reason: Optional[str] = None
    severity: Optional[str] = None
    recommendation: Optional[str] = None

# Helper functions for threat analysis
def create_threat_analysis_prompt(data: Union[str, Dict[str, Any]]) -> str:
    """Create a detailed prompt for threat analysis"""
    
    # Convert dict to string if needed
    if isinstance(data, dict):
        data_str = json.dumps(data, indent=2)
    else:
        data_str = str(data)
    
    prompt = f"""You are a cyber security expert analyzing potential security threats. 
Analyze the following data and classify it as a cyber security threat on a scale of 1-5:

1 = MINIMAL - No apparent threat, normal activity
2 = LOW - Suspicious but likely benign, minimal concern
3 = MEDIUM - Potentially malicious activity, requires monitoring
4 = HIGH - Likely malicious activity, immediate attention needed
5 = CRITICAL - Active attack or severe vulnerability, urgent response required

Data to analyze:
{data_str}

Provide your response in the following JSON format:
{{
    "threat_level": <1-5>,
    "threat_category": "<category name such as: Malware, Phishing, DDoS, SQL Injection, Unauthorized Access, Data Exfiltration, Normal Activity, etc.>",
    "analysis": "<detailed explanation of why you assigned this threat level, including specific indicators and reasoning>"
}}

Only respond with valid JSON, no additional text."""
    
    return prompt

# Helper functions for GitHub webhook
def verify_signature(payload_body: bytes, signature_header: Optional[str]) -> bool:
    """Verify that the payload was sent from GitHub"""
    if not signature_header or not GITHUB_SECRET:
        return False
    
    hash_object = hmac.new(
        GITHUB_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

async def analyze_code_with_groq(files_changed: list) -> Optional[str]:
    """Send code changes to Groq for security analysis"""
    code_content = "\n\n".join([
        f"File: {file['filename']}\n```\n{file.get('patch', '')}\n```"
        for file in files_changed if file.get('patch')
    ])
    
    if not code_content:
        return None
    
    prompt = f"""Analyze the following code changes for security vulnerabilities. 
Focus on:
- SQL injection risks
- XSS vulnerabilities
- Authentication/authorization issues
- Hardcoded secrets or credentials
- Unsafe file operations
- Command injection risks
- Insecure dependencies

Code changes:
{code_content}

Respond in JSON format:
{{
    "is_safe": true/false,
    "vulnerabilities": ["list of issues found"],
    "severity": "low/medium/high/critical",
    "recommendation": "brief recommendation"
}}"""

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a security expert analyzing code for vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        print(f"Groq API error: {e}")
        return None

async def block_push(repo_full_name: str, commit_sha: str, reason: str) -> bool:
    """Create a commit status to block the push"""
    if not GITHUB_TOKEN:
        return False
    
    url = f"https://api.github.com/repos/{repo_full_name}/statuses/{commit_sha}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "state": "failure",
        "description": reason[:140],  # GitHub limits to 140 chars
        "context": "groq-security-review"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data, timeout=10.0)
            return response.status_code == 201
    except Exception as e:
        print(f"Error blocking push: {e}")
        return False

async def approve_push(repo_full_name: str, commit_sha: str) -> bool:
    """Create a commit status to approve the push"""
    if not GITHUB_TOKEN:
        return False
    
    url = f"https://api.github.com/repos/{repo_full_name}/statuses/{commit_sha}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "state": "success",
        "description": "No security vulnerabilities detected",
        "context": "groq-security-review"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data, timeout=10.0)
            return response.status_code == 201
    except Exception as e:
        print(f"Error approving push: {e}")
        return False

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Cyber Security API - Combined Threat Classifier and GitHub Webhook Security",
        "version": "1.0.0",
        "endpoints": {
            "/analyze": "POST - Analyze data for cyber threats",
            "/webhook": "POST - GitHub webhook for code security analysis",
            "/health": "GET - Check API health",
            "/test-example": "POST - Test endpoint with example data"
        }
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "cyber-security-api"}

# Threat analysis endpoint
@app.post("/analyze", response_model=ForwardedResult)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Analyze unstructured data for cyber security threats using Groq AI.
    Classifies threats on a scale of 1-5 and forwards results to configured endpoint
    """
    
    try:
        # Create analysis prompt
        prompt = create_threat_analysis_prompt(request.data)
        
        # Call Groq API
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a cyber security expert. Respond only with valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=request.model,
            temperature=0.2,
            max_tokens=1000,
            response_format={"type": "json_object"}
        )
        
        # Parse Groq response
        response_content = chat_completion.choices[0].message.content
        analysis_result = json.loads(response_content)
        
        # Validate threat level
        threat_level = analysis_result.get("threat_level")
        if not isinstance(threat_level, int) or not (1 <= threat_level <= 5):
            raise ValueError("Invalid threat level returned by model")
        
        # Create response object
        threat_response = ThreatAnalysisResponse(
            threat_level=threat_level,
            threat_category=analysis_result.get("threat_category", "Unknown"),
            analysis=analysis_result.get("analysis", "No analysis provided"),
            raw_data=request.data,
            model_used=request.model
        )
        
        # Forward to configured endpoint
        try:
            async with httpx.AsyncClient() as client:
                forward_response = await client.post(
                    SEND_URL,
                    json=threat_response.model_dump(),
                    timeout=10.0
                )
                
                if forward_response.status_code == 200:
                    return ForwardedResult(
                        success=True,
                        message="Threat analysis completed and forwarded successfully",
                        original_response=threat_response
                    )
                else:
                    return ForwardedResult(
                        success=False,
                        message=f"Threat analysis completed but forwarding failed with status {forward_response.status_code}",
                        original_response=threat_response
                    )
                    
        except httpx.ConnectError:
            return ForwardedResult(
                success=False,
                message=f"Threat analysis completed but could not connect to {SEND_URL}",
                original_response=threat_response
            )
        except Exception as forward_error:
            return ForwardedResult(
                success=False,
                message=f"Threat analysis completed but forwarding error: {str(forward_error)}",
                original_response=threat_response
            )
            
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse Groq response as JSON: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error during threat analysis: {str(e)}"
        )

# GitHub webhook endpoint
@app.post("/webhook", response_model=GitHubWebhookResponse)
async def webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event")
):
    """
    GitHub webhook endpoint for code security analysis.
    Analyzes code changes in push events for security vulnerabilities.
    """
    
    # Get raw body for signature verification
    body = await request.body()
    
    # Verify signature
    if not verify_signature(body, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Only process push events
    if x_github_event != 'push':
        return GitHubWebhookResponse(
            status="ignored",
            reason=f"Event type '{x_github_event}' is not processed"
        )
    
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Extract relevant information
    repo_full_name = payload.get('repository', {}).get('full_name')
    commits = payload.get('commits', [])
    
    if not repo_full_name:
        raise HTTPException(status_code=400, detail="Missing repository information")
    
    if not commits:
        return GitHubWebhookResponse(
            status="skipped",
            reason="No commits to analyze"
        )
    
    # Get the latest commit SHA
    commit_sha = commits[-1].get('id')
    
    if not commit_sha:
        raise HTTPException(status_code=400, detail="Missing commit SHA")
    
    # Get commit details from GitHub API
    if not GITHUB_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="GITHUB_TOKEN environment variable not set"
        )
    
    commit_url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            commit_response = await client.get(commit_url, headers=headers, timeout=10.0)
            
            if commit_response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to fetch commit details from GitHub"
                )
            
            files_changed = commit_response.json().get('files', [])
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error fetching commit details: {str(e)}"
        )
    
    # Analyze with Groq
    analysis = await analyze_code_with_groq(files_changed)
    
    if analysis:
        try:
            # Try to parse as JSON
            result = json.loads(analysis)
            
            if not result.get('is_safe', True):
                # Block the push
                vulnerabilities = ", ".join(
                    result.get('vulnerabilities', ['Security issues detected'])
                )
                await block_push(
                    repo_full_name,
                    commit_sha,
                    f"Security issues: {vulnerabilities}"
                )
                
                return GitHubWebhookResponse(
                    status="blocked",
                    reason=vulnerabilities,
                    severity=result.get('severity', 'unknown'),
                    recommendation=result.get('recommendation', '')
                )
            else:
                # Approve the push
                await approve_push(repo_full_name, commit_sha)
                return GitHubWebhookResponse(
                    status="approved",
                    reason="No security vulnerabilities detected"
                )
                
        except json.JSONDecodeError:
            # If not JSON, treat as text analysis
            analysis_lower = analysis.lower()
            if "vulnerability" in analysis_lower or "risk" in analysis_lower:
                await block_push(
                    repo_full_name,
                    commit_sha,
                    "Potential security issues detected"
                )
                return GitHubWebhookResponse(
                    status="blocked",
                    reason="Potential security issues detected",
                    severity="unknown"
                )
    
    # Default to approval if analysis fails
    await approve_push(repo_full_name, commit_sha)
    return GitHubWebhookResponse(
        status="approved",
        reason="Analysis completed with no issues found"
    )

# Example usage and testing endpoint
@app.post("/test-example")
async def test_example():
    """Test endpoint with example data"""
    example_data = {
        "timestamp": "2024-11-02T10:30:00Z",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "event_type": "failed_login",
        "attempts": 50,
        "user_agent": "Mozilla/5.0",
        "log": "Multiple failed authentication attempts detected"
    }
    
    request_model = ThreatAnalysisRequest(data=example_data)
    return await analyze_threat(request_model)

if __name__ == "__main__":
    import uvicorn
    
    # Check for API key
    if not os.environ.get("GROQ_API_KEY"):
        print("WARNING: GROQ_API_KEY environment variable not set!")
        print("Set it using: export GROQ_API_KEY='your-api-key-here'")
    
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8080)