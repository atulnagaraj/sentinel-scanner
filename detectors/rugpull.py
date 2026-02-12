"""Advanced rug pull and honeypot detection"""
import re
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class RiskPattern:
    pattern: str
    severity: str
    description: str
    category: str

class RugPullDetector:
    def __init__(self):
        self.patterns = self._load_patterns()
        
    def _load_patterns(self) -> List[RiskPattern]:
        """Define malicious code patterns"""
        return [
            RiskPattern(
                r"function\s+transfer\s*\([^)]*\)\s*.*?\{[^}]*if\s*\([^)]*seller[^}]*revert",
                "Critical",
                "Anti-sell mechanism (honeypot)",
                "Honeypot"
            ),
            RiskPattern(
                r"balanceOf\s*\[\s*msg\.sender\s*\]\s*=\s*0\s*;\s*return\s*true",
                "Critical",
                "Hidden token burn on transfer",
                "RugPull"
            ),
            RiskPattern(
                r"require\s*\(\s*!?\s*isContract\s*\(\s*[^)]*\)\s*\)",
                "High",
                "Contract interaction blocked (possible honeypot)",
                "Honeypot"
            ),
            RiskPattern(
                r"function\s+mint\s*\([^)]*\)\s*.*?(public|external|internal)",
                "Critical",
            "Hidden mint function detected",
                "PrivilegedMint"
            ),
            RiskPattern(
                r"_owner\s*=\s*msg\.sender\s*;[^}]*renounceOwnership\s*\(\s*\)",
                "Medium",
                "Owner can be restored after renounce (fake renounce)",
                "OwnershipRisk"
            ),
            RiskPattern(
                r"selfdestruct\s*\(\s*(payable\s*)?\s*_\w+\s*\)",
                "Critical",
                "Contract can be self-destructed",
                "Selfdestruct"
            ),
            RiskPattern(
                r"transfer\(\s*[^,]+,\s*balanceOf\s*\[\s*this\s*\]",
                "High",
                "Contract can drain all tokens",
                "DrainRisk"
            )
        ]
    
    async def analyze(self, bundle: Dict) -> List[Dict]:
        """Analyze contract for rug pull patterns"""
        findings = []
        source = bundle.get("source", {})
        
        if isinstance(source, dict):
            # Multiple files
            for filepath, content in source.items():
                findings.extend(self._analyze_file(content, filepath))
        else:
            # Single file
            findings.extend(self._analyze_file(source, "contract.sol"))
            
        # Check proxy-specific risks
        if bundle.get("proxy_info", {}).get("is_proxy"):
            findings.extend(self._check_proxy_risks(bundle))
            
        return findings
    
    def _analyze_file(self, content: str, filename: str) -> List[Dict]:
        findings = []
        content_lower = content.lower()
        
        for risk in self.patterns:
            matches = re.finditer(risk.pattern, content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                findings.append({
                    "title": risk.category,
                    "severity": risk.severity,
                    "description": f"{risk.description}\nPattern matched at: {match.group()[:50]}...",
                    "file": filename,
                    "line": content[:match.start()].count("\n") + 1,
                    "category": "RugPull/Honeypot",
                    "confidence": "High" if risk.severity == "Critical" else "Medium",
                    "tool": "Heuristics"
                })
        
        # Check for hidden functionality via assembly
        if "assembly" in content_lower and any(x in content_lower for x in ["sstore", "call", "delegatecall"]):
            findings.append({
                "title": "Hidden Assembly Logic",
                "severity": "Medium",
                "description": "Contract uses assembly which may hide malicious logic",
                "file": filename,
                "category": "CodeQuality",
                "confidence": "Low"
            })
            
        return findings
    
    def _check_proxy_risks(self, bundle: Dict) -> List[Dict]:
        """Check for proxy-specific rug pull risks"""
        findings = []
        proxy_info = bundle.get("proxy_info", {})
        
        # Check if admin is EOA or contract
        admin = proxy_info.get("admin")
        if admin and admin[:6] != "0x0000":  # Not burned
            findings.append({
                "title": "Proxy Admin Not Renounced",
                "severity": "High",
                "description": f"Proxy can be upgraded by {admin}. Risk of rug pull via logic change.",
                "category": "Upgradeability",
                "confidence": "High"
            })
            
        return findings
