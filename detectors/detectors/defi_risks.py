"""DeFi protocol-specific vulnerability detection"""
import re
from typing import List, Dict, Set

class DeFiRiskDetector:
    def __init__(self):
        self.flashloan_patterns = [
            "flashLoan",
            "flash loan",
            "flashloan",
            "FlashLoan",
            "onFlashLoan"
        ]
        
        self.oracle_patterns = [
            "Chainlink",
            "getReserves",
            "consult",
            "latestAnswer",
            "latestRoundData"
        ]
    
    async def analyze(self, source: Dict, metadata: Dict) -> List[Dict]:
        findings = []
        
        # Flatten source if multi-file
        all_code = ""
        if isinstance(source, dict):
            all_code = "\n".join(source.values())
        else:
            all_code = source
            
        # Flash Loan Risk Analysis
        if self._has_flashloan_capability(all_code):
            findings.extend(self._analyze_flashloan_risks(all_code))
            
        # Oracle Manipulation
        oracle_findings = self._analyze_oracle_usage(all_code)
        findings.extend(oracle_findings)
        
        # AMM/Router specific
        if self._is_amm_contract(all_code):
            findings.extend(self._analyze_amm_risks(all_code))
            
        # Lending protocol checks
        if self._is_lending_protocol(all_code):
            findings.extend(self._analyze_lending_risks(all_code))
            
        return findings
    
    def _has_flashloan_capability(self, code: str) -> bool:
        return any(pattern in code for pattern in self.flashloan_patterns)
    
    def _analyze_flashloan_risks(self, code: str) -> List[Dict]:
        findings = []
        
        # Check for reentrancy guards in flash loan callbacks
        if "onFlashLoan" in code or "executeOperation" in code:
            if "nonReentrant" not in code and "ReentrancyGuard" not in code:
                findings.append({
                    "title": "Flash Loan Without Reentrancy Guard",
                    "severity": "Critical",
                    "description": "Flash loan callback lacks reentrancy protection. May be vulnerable to reentrancy attacks.",
                    "category": "Reentrancy",
                    "confidence": "High"
                })
                
        # Check for external call validation
        if re.search(r'function\s+executeOperation\s*\([^)]*\)\s*', code):
            if not re.search(r'require\s*\(\s*msg\.sender\s*==\s*pool|initiator\s*==', code):
                findings.append({
                    "title": "Flash Loan Initiator Not Validated",
                    "severity": "High",
                    "description": "Flash loan callback does not validate initiator/pool, may allow arbitrary execution",
                    "category": "AccessControl",
                    "confidence": "Medium"
                })
                
        return findings
    
    def _analyze_oracle_usage(self, code: str) -> List[Dict]:
        findings = []
        
        # Check for price manipulation via spot price
        if "getReserves" in code and "consult" not in code:
            findings.append({
                "title": "Spot Price Manipulation Risk",
                "severity": "Critical",
                "description": "Contract uses pool reserves directly without TWAP oracle. Vulnerable to flash loan price manipulation.",
                "category": "OracleManipulation",
                "confidence": "High"
            })
            
        # Check Chainlink validation
        if "latestRoundData" in code:
            if not re.search(r'updatedAt\s*>\s*0|answer\s*>\s*0', code):
                findings.append({
                    "title": "Insufficient Chainlink Validation",
                    "severity": "High",
                    "description": "Chainlink price may not be validated for stale/incorrect data",
                    "category": "OracleManipulation",
                    "confidence": "Medium"
                })
                
        return findings
    
    def _is_amm_contract(self, code: str) -> bool:
        return any(x in code for x in ["pairFor", "getReserves", "UniswapV2", "UniswapV3"])
    
    def _analyze_amm_risks(self, code: str) -> List[Dict]:
        findings = []
        
        # Sandwich attack protection
        if "amountOutMin" not in code and "sqrtPriceLimitX96" not in code:
            findings.append({
                "title": "Missing Slippage Protection",
                "severity": "High",
                "description": "AMM interaction lacks minimum output amount check. Vulnerable to sandwich attacks.",
                "category": "MEV",
                "confidence": "High"
            })
            
        return findings
    
    def _is_lending_protocol(self, code: str) -> bool:
        return any(x in code for x in ["borrow", "supply", "collateral", "liquidation"])
    
    def _analyze_lending_risks(self, code: str) -> List[Dict]:
        findings = []
        
        # Isolation mode check
        if "enterMarkets" in code and "isolation" not in code.lower():
            findings.append({
                "title": "Cross-Asset Risk Exposure",
                "severity": "Medium",
                "description": "Lending protocol allows entering multiple markets without isolation. Risk of cross-collateral liquidation cascades.",
                "category": "DeFi",
                "confidence": "Medium"
            })
            
        return findings
