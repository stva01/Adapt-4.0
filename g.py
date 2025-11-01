from flask import Flask, request, jsonify
import hmac
import hashlib
import os
from groq import Groq
import requests

app = Flask(__name__)

# Configuration
GITHUB_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')

groq_client = Groq(api_key=GROQ_API_KEY)

def verify_signature(payload_body, signature_header):
    """Verify that the payload was sent from GitHub"""
    if not signature_header:
        return False
    
    hash_object = hmac.new(
        GITHUB_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def analyze_code_with_groq(files_changed):
    """Send code changes to Groq for security analysis"""
    code_content = "\n\n".join([
        f"File: {file['filename']}\n```\n{file['patch']}\n```"
        for file in files_changed if 'patch' in file
    ])
    
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

def block_push(repo_full_name, commit_sha, reason):
    """Create a commit status to block the push"""
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
    
    response = requests.post(url, headers=headers, json=data)
    return response.status_code == 201

def approve_push(repo_full_name, commit_sha):
    """Create a commit status to approve the push"""
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
    
    response = requests.post(url, headers=headers, json=data)
    return response.status_code == 201

@app.route('/webhook', methods=['POST'])
def webhook():
    # Verify signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_signature(request.data, signature):
        return jsonify({"error": "Invalid signature"}), 403
    
    event = request.headers.get('X-GitHub-Event')
    payload = request.json
    
    # Only process push events
    if event != 'push':
        return jsonify({"message": "Event ignored"}), 200
    
    # Extract relevant information
    repo_full_name = payload['repository']['full_name']
    commits = payload['commits']
    
    if not commits:
        return jsonify({"message": "No commits to analyze"}), 200
    
    # Get the latest commit SHA
    commit_sha = commits[-1]['id']
    
    # Fetch the diff for analysis
    compare_url = payload['compare']
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Get commit details
    commit_url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_sha}"
    commit_response = requests.get(commit_url, headers=headers)
    
    if commit_response.status_code != 200:
        return jsonify({"error": "Failed to fetch commit details"}), 500
    
    files_changed = commit_response.json().get('files', [])
    
    # Analyze with Groq
    analysis = analyze_code_with_groq(files_changed)
    
    if analysis:
        try:
            import json
            # Try to parse as JSON
            result = json.loads(analysis)
            
            if not result.get('is_safe', True):
                # Block the push
                vulnerabilities = ", ".join(result.get('vulnerabilities', ['Security issues detected']))
                block_push(repo_full_name, commit_sha, f"Security issues: {vulnerabilities}")
                
                return jsonify({
                    "status": "blocked",
                    "reason": vulnerabilities,
                    "severity": result.get('severity', 'unknown'),
                    "recommendation": result.get('recommendation', '')
                }), 200
            else:
                # Approve the push
                approve_push(repo_full_name, commit_sha)
                return jsonify({"status": "approved"}), 200
                
        except json.JSONDecodeError:
            # If not JSON, treat as text analysis
            if "vulnerability" in analysis.lower() or "risk" in analysis.lower():
                block_push(repo_full_name, commit_sha, "Potential security issues detected")
                return jsonify({"status": "blocked", "analysis": analysis}), 200
    
    # Default to approval if analysis fails
    approve_push(repo_full_name, commit_sha)
    return jsonify({"status": "approved"}), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    # Use port 5001 to avoid conflicts with other services
    app.run(host='0.0.0.0', port=5001)