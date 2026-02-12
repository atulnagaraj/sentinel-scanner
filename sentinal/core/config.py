"""Production configuration management"""
import os
from dataclasses import dataclass
from typing import Dict, Optional
import yaml

@dataclass
class ChainConfig:
    name: str
    rpc_url: str
    explorer_api: str
    explorer_api_key: Optional[str]
    chain_id: int

class ConfigManager:
    CHAINS = {
        "ethereum": {"chain_id": 1, "explorer": "https://api.etherscan.io/api"},
        "bsc": {"chain_id": 56, "explorer": "https://api.bscscan.com/api"},
        "polygon": {"chain_id": 137, "explorer": "https://api.polygonscan.com/api"},
        "arbitrum": {"chain_id": 42161, "explorer": "https://api.arbiscan.io/api"},
        "optimism": {"chain_id": 10, "explorer": "https://api.optimistic.etherscan.io/api"},
        "avalanche": {"chain_id": 43114, "explorer": "https://api.snowtrace.io/api"},
        "fantom": {"chain_id": 250, "explorer": "https://api.ftmscan.com/api"},
    }
    
    def __init__(self):
        self.api_keys = {
            "etherscan": os.getenv("ETHERSCAN_API_KEY"),
            "bscscan": os.getenv("BSCSCAN_API_KEY"),
        }
        
    def get_chain_config(self, chain_name: str) -> ChainConfig:
        chain = self.CHAINS.get(chain_name.lower())
        if not chain:
            raise ValueError(f"Unsupported chain: {chain_name}")
            
        return ChainConfig(
            name=chain_name,
            rpc_url=os.getenv(f"{chain_name.upper()}_RPC", f"https://{chain_name}.infura.io/v3/{os.getenv('INFURA_KEY')}"),
            explorer_api=chain["explorer"],
            explorer_api_key=self.api_keys.get(f"{chain_name}scan"),
            chain_id=chain["chain_id"]
        )
    
    @staticmethod
    def get_severity_weights() -> Dict[str, int]:
        return {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 2,
            "Informational": 0
        }
