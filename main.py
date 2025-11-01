from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from groq import Groq
import httpx
import os
import json
from typing import Optional, Union, Dict, Any
from enum import IntEnum


sendUrl="localhost:8008"
# Initialize FastAPI app
app = FastAPI(
    title="Cyber Security Threat Classifier",
    description="Analyzes unstructured data and classifies cyber security threats using Groq AI",
    version="1.0.0"
)

# Groq client initialization
groq_client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)

# Define threat levels
class ThreatLevel(IntEnum):
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

# Request model
class ThreatAnalysisRequest(BaseModel):
    data: Union[str, Dict[str, Any]] = Field(
        ...,
        description="Unstructured data as string or JSON object to analyze for cyber threats"
    )
    model: Optional[str] = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model to use for analysis"
    )

# Response model
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

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Cyber Security Threat Classifier API",
        "version": "1.0.0",
        "endpoints": {
            "/analyze": "POST - Analyze data for cyber threats",
            "/health": "GET - Check API health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "threat-classifier"}

@app.post("/analyze", response_model=ForwardedResult)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Analyze unstructured data for cyber security threats using Groq AI.
    Classifies threats on a scale of 1-5 and forwards results to localhost:8000
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
        
        # Forward to localhost:8000
        try:
            async with httpx.AsyncClient() as client:
                forward_response = await client.post(
                    sendUrl,
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
                message="Threat analysis completed but could not connect to localhost:8000",
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
    
    request = ThreatAnalysisRequest(data=example_data)
    return await analyze_threat(request)

if __name__ == "__main__":
    import uvicorn
    
    # Check for API key
    if not os.environ.get("GROQ_API_KEY"):
        print("WARNING: GROQ_API_KEY environment variable not set!")
        print("Set it using: export GROQ_API_KEY='your-api-key-here'")
    
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8080)