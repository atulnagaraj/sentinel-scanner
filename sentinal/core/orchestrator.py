"""Main analysis orchestrator with parallel execution"""
import asyncio
import time
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import logging

from ..fetchers.blockchain import BlockchainFetcher
from ..fetchers.source_fetcher import SourceFetcher
from ..analyzers.static_analysis import StaticAnalyzer
from ..analyzers.bytecode_analysis import BytecodeAnalyzer
from ..detectors.defi_risks import DeFiRiskDetector
from ..detectors.rugpull import RugPullDetector
from ..detectors.upgradeability import UpgradeabilityDetector

logger = logging.getLogger(__name__)

@dataclass
class ScanTarget:
    target_type: str  # "address", "file", "github", "folder"
    path: str
    chain: str = "ethereum"
    contract_name: Optional[str] = None
    is_proxy: bool = False
    implementation_slot: Optional[str] = None

class SecurityOrchestrator:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.blockchain = BlockchainFetcher(config)
        self.source_fetcher = SourceFetcher()
        self.static_analyzer = StaticAnalyzer()
        self.bytecode_analyzer = BytecodeAnalyzer()
        
        # Specialized detectors
        self.defi_detector = DeFiRiskDetector()
        self.rugpull_detector = RugPullDetector()
        self.upgradeability_detector = UpgradeabilityDetector()
        
        self.findings: List[Dict] = []
        
    async def scan(self, target: ScanTarget, depth: str = "comprehensive") -> Dict:
        """Execute full security pipeline"""
        logger.info(f"Starting {depth} scan on {target.path}")
        start_time = time.time()
        
        # Phase 1: Acquisition
        contract_bundle = await self._acquire_contract(target)
        
        # Phase 2: Parallel Analysis
        tasks = [
            self._run_static_analysis(contract_bundle),
            self._run_bytecode_analysis(contract_bundle),
            self._run_heuristic_analysis(contract_bundle),
        ]
        
        if depth == "comprehensive":
            tasks.extend([
                self._run_dynamic_analysis(contract_bundle),
                self._run_defi_analysis(contract_bundle),
            ])
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Phase 3: Consolidation
        for result in results:
            if isinstance(result, list):
                self.findings.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Analysis task failed: {result}")
        
        # Phase 4: Post-processing
        self._deduplicate_findings()
        self._calculate_risk_score()
        
        return {
            "scan_metadata": {
                "target": target.path,
                "duration": time.time() - start_time,
                "timestamp": time.time(),
                "chain": target.chain
            },
            "contract_info": contract_bundle.get("metadata", {}),
            "findings": self.findings,
            "risk_score": self.risk_score,
            "summary": self._generate_summary()
        }
    
    async def _acquire_contract(self, target: ScanTarget) -> Dict:
        """Fetch source code or bytecode based on target type"""
        if target.target_type == "address":
            # Fetch from blockchain
            address = target.path
            code = await self.blockchain.get_code(address, target.chain)
            
            # Detect if proxy
            proxy_info = await self.upgradeability_detector.detect_proxy(address, target.chain)
            
            if proxy_info.get("is_proxy"):
                impl_address = proxy_info.get("implementation")
                source = await self.blockchain.get_contract_source(impl_address, target.chain)
            else:
                source = await self.blockchain.get_contract_source(address, target.chain)
                
            return {
                "type": "onchain",
                "address": address,
                "bytecode": code,
                "source": source,
                "proxy_info": proxy_info,
                "metadata": {
                    "compiler": await self.blockchain.get_compiler_version(address),
                    "balance": await self.blockchain.get_balance(address)
                }
            }
            
        elif target.target_type in ["file", "folder"]:
            return await self.source_fetcher.load_local(target.path)
            
        elif target.target_type == "github":
            return await self.source_fetcher.fetch_github(target.path)
            
        raise ValueError(f"Unknown target type: {target.target_type}")
    
    async def _run_static_analysis(self, bundle: Dict) -> List[Dict]:
        """Run Slither, Mythril, and Semgrep"""
        if not bundle.get("source"):
            return []
            
        findings = []
        
        # Slither Analysis
        slither_results = await self.static_analyzer.run_slither(bundle["source"])
        findings.extend(self._normalize_slither(slither_results))
        
        # Semgrep Custom Rules
        semgrep_results = await self.static_analyzer.run_semgrep(bundle["source"])
        findings.extend(self._normalize_semgrep(semgrep_results))
        
        # Mythril (for small contracts only, timeout handling)
        if len(bundle.get("bytecode", "")) < 10000:  # Limit to smaller contracts
            mythril_results = await self.static_analyzer.run_mythril(bundle["source"])
            findings.extend(self._normalize_mythril(mythril_results))
            
        return findings
    
    async def _run_bytecode_analysis(self, bundle: Dict) -> List[Dict]:
        """Analyze deployed bytecode for patterns"""
        if not bundle.get("bytecode"):
            return []
            
        findings = []
        
        # Check for suspicious patterns in bytecode
        findings.extend(await self.bytecode_analyzer.analyze(
            bundle["bytecode"], 
            bundle.get("source")
        ))
        
        # Check for selfdestruct capability
        if await self.bytecode_analyzer.has_selfdestruct(bundle["bytecode"]):
            findings.append({
                "severity": "High",
                "category": "AccessControl",
                "title": "Contract Contains SELFDESTRUCT",
                "description": "Contract can be destroyed via SELFDESTRUCT, potentially locking funds",
                "confidence": "High"
            })
            
        return findings
    
    async def _run_heuristic_analysis(self, bundle: Dict) -> List[Dict]:
        """AI-based pattern detection for rug pulls and scams"""
        findings = []
        
        # Rug pull detection
        if bundle.get("source"):
            rugpull_findings = await self.rugpull_detector.analyze(bundle)
            findings.extend(rugpull_findings)
            
        return findings
    
    async def _run_defi_analysis(self, bundle: Dict) -> List[Dict]:
        """DeFi-specific vulnerability detection"""
        if not bundle.get("source"):
            return []
            
        return await self.defi_detector.analyze(
            bundle["source"],
            bundle.get("metadata", {})
        )
    
    async def _run_dynamic_analysis(self, bundle: Dict) -> List[Dict]:
        """Fuzzing with Echidna (if available)"""
        # Placeholder for Echidna/Foundry integration
        return []
    
    def _deduplicate_findings(self):
        """Remove duplicate findings based on similarity"""
        seen = set()
        unique = []
        for finding in self.findings:
            key = f"{finding.get('title')}:{finding.get('line', 0)}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        self.findings = unique
    
    def _calculate_risk_score(self):
        """Calculate composite risk score"""
        weights = self.config.get_severity_weights()
        total = 0
        for finding in self.findings:
            total += weights.get(finding.get("severity", "Low"), 0)
        # Normalize to 0-100
        self.risk_score = min(100, total)
    
    def _generate_summary(self) -> Dict:
        """Generate executive summary"""
        severity_counts = {}
        for finding in self.findings:
            sev = finding.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "risk_rating": "Critical" if self.risk_score > 70 else "High" if self.risk_score > 40 else "Medium" if self.risk_score > 20 else "Low",
            "categories": list(set(f.get("category") for f in self.findings))
        }
    
    def _normalize_slither(self, results: List[Dict]) -> List[Dict]:
        """Convert Slither output to standard format"""
        normalized = []
        for item in results:
            normalized.append({
                "title": item.get("check"),
                "severity": item.get("impact", "Informational"),
                "confidence": item.get("confidence", "Medium"),
                "description": item.get("description"),
                "category": item.get("check"),
                "line": item.get("lines", [0])[0] if isinstance(item.get("lines"), list) else 0,
                "file": item.get("filename"),
                "tool": "Slither"
            })
        return normalized
    
    def _normalize_semgrep(self, results: List[Dict]) -> List[Dict]:
        """Convert Semgrep output to standard format"""
        # Implementation similar to above
        return []
    
    def _normalize_mythril(self, results: List[Dict]) -> List[Dict]:
        """Convert Mythril output to standard format"""
        # Implementation for symbolic execution results
        return []
