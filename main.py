#!/usr/bin/env python3
"""
Adapt Security CLI - AI-Powered Code Security Review
Inspired by CodeRabbit, powered by Groq AI
"""

import os
import sys
import subprocess
import json
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

console = Console()

class AdaptSecurityCLI:
    def __init__(self):
        self.groq_api_key = os.environ.get('GROQ_API_KEY')
        if not self.groq_api_key:
            console.print("[red]❌ GROQ_API_KEY not found in environment variables[/red]")
            sys.exit(1)
        
        self.client = Groq(api_key=self.groq_api_key)
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
    
    def review(self, save_report: bool = True):
        """Main review function"""
        console.print("[bold blue]🚀 Starting Adapt Security Review...[/bold blue]\n")
        
        # Get staged changes
        changes = self._get_staged_changes()
        
        if not changes:
            console.print("[yellow]⚠️  No staged changes found. Use 'git add' first.[/yellow]")
            return
        
        console.print(f"[cyan]Found {len(changes)} file(s) to review[/cyan]\n")
        
        # Analyze
        analysis = self._analyze_with_groq(changes)
        
        if not analysis:
            console.print("[red]❌ Analysis failed[/red]")
            return
        
        # Display results
        self._display_results(analysis, changes)
        
        # Save report
        if save_report:
            self._save_report(analysis, changes)
        
        # Ask to proceed
        is_safe = analysis.get('is_safe_to_commit', True)
        
        if not is_safe:
            console.print("[bold red]⚠️  SECURITY ISSUES DETECTED[/bold red]")
            console.print("[yellow]It's recommended to fix the issues before committing.[/yellow]\n")
            
            if Confirm.ask("Do you want to proceed with commit anyway?"):
                console.print("[yellow]⚠️  Proceeding with commit (not recommended)[/yellow]")
            else:
                console.print("[green]✅ Commit cancelled. Fix the issues and try again.[/green]")
                sys.exit(1)
        else:
            console.print("[bold green]✅ All checks passed! Safe to commit.[/bold green]")
    
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
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Review command
    review_parser = subparsers.add_parser('review', help='Review staged changes')
    review_parser.add_argument('--no-save', action='store_true', help='Don\'t save report')
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show review history')
    history_parser.add_argument('--limit', type=int, default=10, help='Number of reports to show')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = AdaptSecurityCLI()
    
    if args.command == 'review':
        cli.review(save_report=not args.no_save)
    elif args.command == 'history':
        cli.history(limit=args.limit)


if __name__ == '__main__':
    main()