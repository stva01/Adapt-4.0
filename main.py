#!/usr/bin/env python3
"""
Adapt Security CLI & Webhook - AI-Powered Code Security Review
Inspired by CodeRabbit, powered by Groq AI
"""

import os
import sys
import subprocess
import json
import hmac
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import argparse
from groq import Groq
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich import box
from rich.prompt import Confirm

# Web server imports
from flask import Flask, request, jsonify, Response

console = Console()
app = Flask(__name__)

class AdaptSecurityCLI:
    def __init__(self, repo_path=None):
        self.groq_api_key = os.environ.get('GROQ_API_KEY')
        if not self.groq_api_key:
            console.print("[red]❌ GROQ_API_KEY not found in environment variables[/red]")
            sys.exit(1)
        
        self.client = Groq(api_key=self.groq_api_key)
        if repo_path:
            self.repo_root = Path(repo_path)
        else:
            self.repo_root = self._get_repo_root()
        
    def _get_repo_root(self) -> Path:
        """Get the git repository root directory"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                capture_output=True,
                text=True,
                check=True
            )
            return Path(result.stdout.strip())
        except subprocess.CalledProcessError:
            console.print("[red]❌ Not a git repository[/red]")
            sys.exit(1)
    
    def _get_staged_changes(self) -> List[Dict[str, str]]:
        """Get all staged changes as diffs"""
        try:
            # Get list of staged files
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only'],
                capture_output=True,
                text=True,
                check=True
            )
            
            if not result.stdout.strip():
                return []
            
            files = result.stdout.strip().split('\n')
            changes = []
            
            for file in files:
                # Get the diff for each file
                diff_result = subprocess.run(
                    ['git', 'diff', '--cached', file],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                changes.append({
                    'filename': file,
                    'diff': diff_result.stdout,
                    'status': self._get_file_status(file)
                })
            
            return changes
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Error getting staged changes: {e}[/red]")
            return []

    def _get_changes_between_commits(self, base_commit: str, head_commit: str) -> List[Dict[str, str]]:
        """Get all changes between two commits as diffs"""
        try:
            # Get list of changed files
            result = subprocess.run(
                ['git', 'diff', '--name-only', base_commit, head_commit],
                capture_output=True,
                text=True,
                check=True
            )
            
            if not result.stdout.strip():
                return []
            
            files = result.stdout.strip().split('\n')
            changes = []
            
            for file in files:
                # Get the diff for each file
                diff_result = subprocess.run(
                    ['git', 'diff', base_commit, head_commit, '--', file],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                changes.append({
                    'filename': file,
                    'diff': diff_result.stdout,
                    'status': self._get_file_status_between_commits(base_commit, head_commit, file)
                })
            
            return changes
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]❌ Error getting changes between commits: {e}[/red]")
            return []

    def _get_file_status_between_commits(self, base_commit: str, head_commit: str, filename: str) -> str:
        """Get the status of a file between two commits"""
        try:
            # Check if file was added, modified, or deleted
            result = subprocess.run(
                ['git', 'diff', '--name-status', base_commit, head_commit, '--', filename],
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.stdout:
                status_code = result.stdout[0]
                status_map = {
                    'A': 'Added',
                    'M': 'Modified', 
                    'D': 'Deleted'
                }
                return status_map.get(status_code, 'Modified')
            return 'Modified'
        except:
            return 'Modified'
    
    def _get_file_status(self, filename: str) -> str:
        """Get the git status of a file"""
        try:
            result = subprocess.run(
                ['git', 'status', '--short', filename],
                capture_output=True,
                text=True,
                check=True
            )
            status_code = result.stdout[:2].strip()
            status_map = {
                'M': 'Modified',
                'A': 'Added',
                'D': 'Deleted',
                'R': 'Renamed',
                'C': 'Copied'
            }
            return status_map.get(status_code, 'Modified')
        except:
            return 'Unknown'
    
    def _analyze_with_groq(self, changes: List[Dict[str, str]]) -> Dict:
        """Analyze code changes with Groq AI"""
        
        # Prepare code context
        code_context = "\n\n".join([
            f"File: {change['filename']} ({change['status']})\n```diff\n{change['diff']}\n```"
            for change in changes
        ])
        
        prompt = f"""You are an expert security code reviewer. Analyze these code changes comprehensively.

{code_context}

Provide a detailed security analysis in JSON format:
{{
    "overall_risk": "safe|low|medium|high|critical",
    "is_safe_to_commit": true/false,
    "summary": "Brief one-line summary",
    "vulnerabilities": [
        {{
            "file": "filename",
            "line": "approximate line number or range",
            "severity": "low|medium|high|critical",
            "type": "vulnerability type (e.g., SQL Injection, XSS, etc.)",
            "description": "detailed description",
            "recommendation": "how to fix it",
            "code_snippet": "the problematic code"
        }}
    ],
    "security_score": 0-100,
    "positive_findings": ["list of good security practices found"],
    "recommendations": ["general recommendations for improvement"]
}}

Focus on:
- SQL injection, XSS, CSRF vulnerabilities
- Authentication/authorization issues
- Hardcoded secrets, API keys, passwords
- Insecure cryptography
- Command injection
- Path traversal
- Insecure deserialization
- Dependency vulnerabilities
- Information disclosure
- Logic flaws

Be thorough but also acknowledge good security practices."""

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Analyzing code with AI..."),
                console=console
            ) as progress:
                progress.add_task("analyze", total=None)
                
                response = self.client.chat.completions.create(
                    model="llama-3.1-70b-versatile",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a senior security engineer and code reviewer. Provide detailed, actionable security feedback."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.1,
                    max_tokens=4000,
                    response_format={"type": "json_object"}
                )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            console.print(f"[red]❌ Groq API error: {e}[/red]")
            return None
    
    def _display_results(self, analysis: Dict, changes: List[Dict[str, str]]):
        """Display analysis results in a beautiful format"""
        
        console.print()
        
        # Header
        risk_level = analysis.get('overall_risk', 'unknown').upper()
        risk_colors = {
            'SAFE': 'green',
            'LOW': 'yellow',
            'MEDIUM': 'orange',
            'HIGH': 'red',
            'CRITICAL': 'bold red'
        }
        risk_color = risk_colors.get(risk_level, 'white')
        
        is_safe = analysis.get('is_safe_to_commit', True)
        status_icon = "✅" if is_safe else "⛔"
        
        console.print(Panel(
            f"{status_icon} [bold]Security Analysis Complete[/bold]\n\n"
            f"Risk Level: [{risk_color}]{risk_level}[/{risk_color}]\n"
            f"Security Score: [cyan]{analysis.get('security_score', 0)}/100[/cyan]\n"
            f"Safe to Commit: [{'green' if is_safe else 'red'}]{'YES' if is_safe else 'NO'}[/{'green' if is_safe else 'red'}]",
            title="🛡️  Adapt Security Review",
            border_style="blue"
        ))
        
        # Summary
        console.print(f"\n[bold]Summary:[/bold] {analysis.get('summary', 'No summary available')}\n")
        
        # Vulnerabilities
        vulnerabilities = analysis.get('vulnerabilities', [])
        if vulnerabilities:
            console.print("[bold red]🔴 Security Issues Found:[/bold red]\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'unknown').upper()
                severity_colors = {
                    'LOW': 'yellow',
                    'MEDIUM': 'orange',
                    'HIGH': 'red',
                    'CRITICAL': 'bold red'
                }
                severity_color = severity_colors.get(severity, 'white')
                
                console.print(Panel(
                    f"[bold]Type:[/bold] {vuln.get('type', 'Unknown')}\n"
                    f"[bold]File:[/bold] {vuln.get('file', 'Unknown')}\n"
                    f"[bold]Line:[/bold] {vuln.get('line', 'Unknown')}\n"
                    f"[bold]Severity:[/bold] [{severity_color}]{severity}[/{severity_color}]\n\n"
                    f"[bold]Description:[/bold]\n{vuln.get('description', 'No description')}\n\n"
                    f"[bold]Recommendation:[/bold]\n{vuln.get('recommendation', 'No recommendation')}\n\n"
                    f"[bold]Code:[/bold]\n```\n{vuln.get('code_snippet', 'N/A')}\n```",
                    title=f"Issue #{i}",
                    border_style=severity_color
                ))
                console.print()
        
        # Positive findings
        positive = analysis.get('positive_findings', [])
        if positive:
            console.print("[bold green]✅ Good Security Practices:[/bold green]\n")
            for finding in positive:
                console.print(f"  • {finding}")
            console.print()
        
        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            console.print("[bold cyan]💡 Recommendations:[/bold cyan]\n")
            for rec in recommendations:
                console.print(f"  • {rec}")
            console.print()
        
        # Files analyzed
        console.print("[bold]📁 Files Analyzed:[/bold]")
        table = Table(box=box.ROUNDED)
        table.add_column("File", style="cyan")
        table.add_column("Status", style="yellow")
        
        for change in changes:
            table.add_row(change['filename'], change['status'])
        
        console.print(table)
        console.print()
    
    def _save_report(self, analysis: Dict, changes: List[Dict[str, str]]):
        """Save analysis report to file"""
        report_dir = self.repo_root / '.adapt-security'
        report_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = report_dir / f'review_{timestamp}.json'
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis,
            'files_reviewed': [
                {
                    'filename': change['filename'],
                    'status': change['status']
                }
                for change in changes
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"[dim]💾 Report saved to: {report_file}[/dim]\n")
    
    def review(self, save_report: bool = True, base_commit: str = None, head_commit: str = None):
        """Main review function"""
        console.print("[bold blue]🚀 Starting Adapt Security Review...[/bold blue]\n")
        
        # Get changes based on input type
        if base_commit and head_commit:
            changes = self._get_changes_between_commits(base_commit, head_commit)
        else:
            changes = self._get_staged_changes()
        
        if not changes:
            console.print("[yellow]⚠️  No changes found.[/yellow]")
            return None
        
        console.print(f"[cyan]Found {len(changes)} file(s) to review[/cyan]\n")
        
        # Analyze
        analysis = self._analyze_with_groq(changes)
        
        if not analysis:
            console.print("[red]❌ Analysis failed[/red]")
            return None
        
        # Display results
        self._display_results(analysis, changes)
        
        # Save report
        if save_report:
            self._save_report(analysis, changes)
        
        return analysis
    
    def history(self, limit: int = 10):
        """Show review history"""
        report_dir = self.repo_root / '.adapt-security'
        
        if not report_dir.exists():
            console.print("[yellow]No review history found[/yellow]")
            return
        
        reports = sorted(report_dir.glob('review_*.json'), reverse=True)[:limit]
        
        if not reports:
            console.print("[yellow]No review history found[/yellow]")
            return
        
        console.print(f"[bold]📊 Last {len(reports)} Reviews:[/bold]\n")
        
        table = Table(box=box.ROUNDED)
        table.add_column("Date", style="cyan")
        table.add_column("Risk", style="yellow")
        table.add_column("Score", style="green")
        table.add_column("Issues", style="red")
        table.add_column("Files", style="blue")
        
        for report_file in reports:
            with open(report_file) as f:
                data = json.load(f)
                analysis = data.get('analysis', {})
                
                timestamp = datetime.fromisoformat(data['timestamp'])
                date_str = timestamp.strftime('%Y-%m-%d %H:%M')
                
                risk = analysis.get('overall_risk', 'unknown').upper()
                score = f"{analysis.get('security_score', 0)}/100"
                issues = len(analysis.get('vulnerabilities', []))
                files = len(data.get('files_reviewed', []))
                
                table.add_row(date_str, risk, score, str(issues), str(files))
        
        console.print(table)

# Webhook Handler Functions
def verify_webhook_signature(payload_body, secret_token, signature_header):
    """Verify that the webhook signature matches our secret"""
    if not secret_token:
        console.print("[yellow]⚠️  No webhook secret configured, skipping signature verification[/yellow]")
        return True  # No secret configured
    
    if not signature_header:
        console.print("[red]❌ No signature header received[/red]")
        return False
    
    # GitHub prefixes the signature with "sha256="
    if signature_header.startswith('sha256='):
        signature_header = signature_header[7:]
    
    # Create our own signature
    mac = hmac.new(
        secret_token.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = mac.hexdigest()
    
    # Compare signatures
    is_valid = hmac.compare_digest(expected_signature, signature_header)
    
    if not is_valid:
        console.print(f"[red]❌ Signature verification failed[/red]")
        console.print(f"[dim]Expected: {expected_signature}[/dim]")
        console.print(f"[dim]Received: {signature_header}[/dim]")
    
    return is_valid

@app.route('/webhook', methods=['POST', 'GET'])
def handle_webhook():
    """Handle GitHub webhook requests"""
    if request.method == 'GET':
        return jsonify({'message': 'Adapt Security Webhook is running', 'status': 'ok'}), 200
    
    # Get webhook secret from environment
    webhook_secret = os.environ.get('WEBHOOK_SECRET', '')
    
    # Verify signature if secret is configured
    signature = request.headers.get('X-Hub-Signature-256', '')
    
    console.print(f"[dim]Webhook received: {request.headers.get('X-GitHub-Event', 'unknown')}[/dim]")
    console.print(f"[dim]Signature present: {bool(signature)}[/dim]")
    console.print(f"[dim]Secret configured: {bool(webhook_secret)}[/dim]")
    
    if not verify_webhook_signature(request.data, webhook_secret, signature):
        return jsonify({'error': 'Invalid signature'}), 403
    
    # Get event type
    event_type = request.headers.get('X-GitHub-Event', 'ping')
    
    if event_type == 'ping':
        console.print("[green]✅ Webhook ping received and verified[/green]")
        return jsonify({'message': 'pong'}), 200
    
    elif event_type == 'push':
        console.print("[green]✅ Push event received and verified[/green]")
        return handle_push_event(request.json)
    
    else:
        console.print(f"[yellow]⚠️  Unsupported event type: {event_type}[/yellow]")
        return jsonify({'message': f'Event {event_type} not supported'}), 200

def handle_push_event(payload):
    """Handle push events from GitHub"""
    try:
        # Extract repository information
        repo_name = payload['repository']['name']
        repo_full_name = payload['repository']['full_name']
        clone_url = payload['repository']['clone_url']
        
        # Extract commit information
        base_commit = payload['before']
        head_commit = payload['after']
        branch = payload['ref'].replace('refs/heads/', '')
        
        console.print(f"[green]📦 Processing push to {repo_full_name} on branch {branch}[/green]")
        console.print(f"[dim]Commits: {base_commit[:8]} → {head_commit[:8]}[/dim]")
        
        # Skip if this is a delete event or initial commit
        if base_commit == '0' * 40:
            console.print("[yellow]⚠️  Initial commit, skipping analysis[/yellow]")
            return jsonify({'message': 'Initial commit, no changes to analyze'}), 200
        
        if head_commit == '0' * 40:
            console.print("[yellow]⚠️  Branch deletion, skipping analysis[/yellow]")
            return jsonify({'message': 'Branch deletion, no changes to analyze'}), 200
        
        # Create temporary directory for the repository
        import tempfile
        import shutil
        
        temp_dir = tempfile.mkdtemp(prefix=f"adapt_{repo_name}_")
        
        try:
            # Clone the repository
            console.print(f"[cyan]Cloning repository to {temp_dir}...[/cyan]")
            clone_result = subprocess.run([
                'git', 'clone', '--depth=10', clone_url, temp_dir
            ], check=True, capture_output=True, text=True)
            
            # Analyze the changes
            os.chdir(temp_dir)  # Change to the repo directory
            cli = AdaptSecurityCLI(temp_dir)
            analysis = cli.review(
                save_report=False,
                base_commit=base_commit,
                head_commit=head_commit
            )
            
            if analysis:
                # Prepare response
                response = {
                    'repository': repo_full_name,
                    'branch': branch,
                    'analysis': analysis,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Log results
                risk_level = analysis.get('overall_risk', 'unknown')
                security_score = analysis.get('security_score', 0)
                issues_count = len(analysis.get('vulnerabilities', []))
                
                console.print(f"[bold]Webhook Analysis Complete:[/bold]")
                console.print(f"  Risk Level: {risk_level}")
                console.print(f"  Security Score: {security_score}/100")
                console.print(f"  Issues Found: {issues_count}")
                
                return jsonify(response), 200
            else:
                return jsonify({'error': 'Analysis failed'}), 500
                
        finally:
            # Clean up temporary directory
            os.chdir('/')  # Change back to root to avoid permission issues
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        console.print(f"[red]❌ Error processing push event: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return jsonify({'error': str(e)}), 500

def main():
    parser = argparse.ArgumentParser(
        description='🛡️  Adapt Security - AI-Powered Code Security Review',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  adapt review              # Review staged changes
  adapt review --no-save    # Review without saving report
  adapt history             # Show review history
  adapt history --limit 20  # Show last 20 reviews
  adapt serve               # Start webhook server
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Review command
    review_parser = subparsers.add_parser('review', help='Review staged changes')
    review_parser.add_argument('--no-save', action='store_true', help='Don\'t save report')
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show review history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of reports to show')
    
    # Serve command
    serve_parser = subparsers.add_parser('serve', help='Start webhook server')
    serve_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    serve_parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    serve_parser.add_argument('--no-verify', action='store_true', help='Disable webhook signature verification')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'serve':
        if args.no_verify:
            console.print("[yellow]⚠️  Webhook signature verification disabled[/yellow]")
            os.environ['WEBHOOK_SECRET'] = ''
        
        console.print(f"[bold green]🚀 Starting Adapt Security Webhook Server...[/bold green]")
        console.print(f"[cyan]Listening on {args.host}:{args.port}[/cyan]")
        console.print(f"[dim]Webhook URL: https://your-ngrok-subdomain.ngrok-free.app/webhook[/dim]")
        if os.environ.get('WEBHOOK_SECRET'):
            console.print(f"[green]✅ Webhook signature verification enabled[/green]")
        else:
            console.print(f"[yellow]⚠️  Webhook signature verification disabled[/yellow]")
        
        app.run(host=args.host, port=args.port, debug=False)
    
    else:
        cli = AdaptSecurityCLI()
        
        if args.command == 'review':
            cli.review(save_report=not args.no_save)
        elif args.command == 'history':
            cli.history(limit=args.limit)

if __name__ == '__main__':
    main()