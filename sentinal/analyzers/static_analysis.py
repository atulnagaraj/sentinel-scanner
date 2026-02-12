"""Wrapper for external static analysis tools"""
import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Optional

class StaticAnalyzer:
    def __init__(self):
        self.timeout = 300  # 5 minutes
        
    async def run_slither(self, source: Dict[str, str]) -> List[Dict]:
        """Execute Slither analysis"""
        findings = []
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write source files
            for filename, content in source.items():
                filepath = Path(tmpdir) / filename
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content)
            
            try:
                cmd = [
                    "slither", 
                    tmpdir,
                    "--json", "-",
                    "--filter-paths", "node_modules",
                    "--exclude-informational", "false",
                    "--exclude-low", "false"
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=self.timeout
                )
                
                if result.returncode == 0 or result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        findings = data.get("results", {}).get("detectors", [])
                    except json.JSONDecodeError:
                        pass
                        
            except subprocess.TimeoutExpired:
                print("[!] Slither analysis timed out")
            except FileNotFoundError:
                print("[!] Slither not installed. Install with: pip install slither-analyzer")
                
        return findings
    
    async def run_semgrep(self, source: Dict[str, str], rules_path: Optional[str] = None) -> List[Dict]:
        """Run Semgrep with custom Solidity rules"""
        findings = []
        
        with tempfile.TemporaryDirectory() as tmpdir:
            for filename, content in source.items():
                filepath = Path(tmpdir) / filename
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content)
            
            try:
                cmd = ["semgrep", "--config=auto", "--json", str(tmpdir)]
                if rules_path:
                    cmd = ["semgrep", f"--config={rules_path}", "--json", str(tmpdir)]
                    
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for match in data.get("results", []):
                        findings.append({
                            "check": match.get("check_id"),
                            "description": match.get("extra", {}).get("message"),
                            "severity": match.get("extra", {}).get("severity", "Medium"),
                            "lines": [match.get("start", {}).get("line")],
                            "filename": match.get("path")
                        })
            except Exception as e:
                print(f"[!] Semgrep error: {e}")
                
        return findings
    
    async def run_mythril(self, source: Dict[str, str]) -> List[Dict]:
        """Symbolic execution with Mythril"""
        findings = []
        # Note: Mythril works best on single file contracts
        # Implementation would require aggregating imports or using mythril on specific files
        return findings
