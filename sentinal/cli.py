"""Command Line Interface"""
import argparse
import asyncio
import sys
import os
from pathlib import Path

from .core.orchestrator import SecurityOrchestrator, ScanTarget
from .core.config import ConfigManager
from .reporters.html_reporter import HTMLReporter
from .reporters.json_reporter import JSONReporter  # Similar implementation

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel - Professional Smart Contract Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel -a 0x... --chain ethereum --output report.html
  sentinel -f ./contracts --depth comprehensive
  sentinel -g https://github.com/org/repo --branch main
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-a", "--address", help="Contract address to analyze")
    input_group.add_argument("-f", "--file", help="Solidity file or folder")
    input_group.add_argument("-g", "--github", help="GitHub repository URL")
    
    # Configuration
    parser.add_argument("--chain", default="ethereum", choices=["ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche", "fantom", "goerli", "sepolia"])
    parser.add_argument("--depth", default="standard", choices=["quick", "standard", "comprehensive"])
    parser.add_argument("-o", "--output", default="sentinel_report", help="Output file name (without extension)")
    parser.add_argument("--format", default="both", choices=["json", "html", "both"])
    parser.add_argument("--api-key", help="Etherscan API key (or set ETHERSCAN_API_KEY env var)")
    parser.add_argument("--rpc", help="Custom RPC endpoint")
    
    args = parser.parse_args()
    
    # Setup
    config = ConfigManager()
    if args.api_key:
        os.environ["ETHERSCAN_API_KEY"] = args.api_key
    
    # Determine target type
    target = None
    if args.address:
        target = ScanTarget(
            target_type="address",
            path=args.address,
            chain=args.chain
        )
    elif args.file:
        path = Path(args.file)
        target_type = "folder" if path.is_dir() else "file"
        target = ScanTarget(target_type=target_type, path=args.file)
    elif args.github:
        target = ScanTarget(target_type="github", path=args.github)
    
    # Execute
    try:
        orchestrator = SecurityOrchestrator(config)
        results = asyncio.run(orchestrator.scan(target, depth=args.depth))
        
        # Generate reports
        if args.format in ["json", "both"]:
            json_path = f"{args.output}.json"
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] JSON Report: {json_path}")
            
        if args.format in ["html", "both"]:
            html_path = f"{args.output}.html"
            reporter = HTMLReporter()
            reporter.generate(results, html_path)
            
        # Exit code based on severity
        critical_count = results["summary"]["severity_breakdown"].get("Critical", 0)
        high_count = results["summary"]["severity_breakdown"].get("High", 0)
        
        if critical_count > 0:
            print(f"\n[!] {critical_count} CRITICAL issues found!")
            sys.exit(2)
        elif high_count > 0:
            print(f"\n[!] {high_count} HIGH severity issues found")
            sys.exit(1)
        else:
            print("\n[✓] No critical or high severity issues found")
            sys.exit(0)
            
    except Exception as e:
        print(f"[X] Error: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
