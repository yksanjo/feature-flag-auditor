#!/usr/bin/env python3
"""
Feature Flag Auditor

Scans codebase and feature flag providers to identify unused, stale, or risky flags.
"""

import os
import re
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path
from abc import ABC, abstractmethod

try:
    from github import Github
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class FlagProvider(ABC):
    """Base class for feature flag providers."""
    
    @abstractmethod
    def get_flags(self) -> List[Dict]:
        """Fetch all flags from the provider."""
        pass
    
    @abstractmethod
    def get_flag_usage(self, flag_key: str) -> Dict:
        """Get usage statistics for a flag."""
        pass


class LaunchDarklyProvider(FlagProvider):
    """LaunchDarkly feature flag provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://app.launchdarkly.com/api/v2"
        self.headers = {
            "Authorization": api_key,
            "Content-Type": "application/json"
        }
    
    def get_flags(self) -> List[Dict]:
        """Fetch all flags from LaunchDarkly."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests package not installed")
        
        flags = []
        url = f"{self.base_url}/flags"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            for item in data.get("items", []):
                flags.append({
                    "key": item.get("key"),
                    "name": item.get("name"),
                    "description": item.get("description", ""),
                    "creation_date": item.get("creationDate"),
                    "tags": item.get("tags", []),
                    "temporary": item.get("temporary", False),
                    "archived": item.get("archived", False),
                    "environments": item.get("environments", {})
                })
        except Exception as e:
            print(f"Error fetching LaunchDarkly flags: {e}")
        
        return flags
    
    def get_flag_usage(self, flag_key: str) -> Dict:
        """Get usage statistics for a flag."""
        # LaunchDarkly usage API would go here
        # This is a simplified version
        return {
            "requests": 0,
            "evaluations": 0
        }


class FlagsmithProvider(FlagProvider):
    """Flagsmith feature flag provider."""
    
    def __init__(self, api_key: str, base_url: str = "https://api.flagsmith.com/api/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "X-Environment-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def get_flags(self) -> List[Dict]:
        """Fetch all flags from Flagsmith."""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests package not installed")
        
        flags = []
        url = f"{self.base_url}/flags"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            for item in data:
                flags.append({
                    "key": item.get("feature", {}).get("name"),
                    "name": item.get("feature", {}).get("name"),
                    "description": item.get("feature", {}).get("description", ""),
                    "creation_date": item.get("created_date"),
                    "tags": [],
                    "temporary": False,
                    "archived": item.get("archived", False),
                    "enabled": item.get("enabled", False)
                })
        except Exception as e:
            print(f"Error fetching Flagsmith flags: {e}")
        
        return flags
    
    def get_flag_usage(self, flag_key: str) -> Dict:
        """Get usage statistics for a flag."""
        # Flagsmith usage API would go here
        return {
            "requests": 0,
            "evaluations": 0
        }


def scan_codebase_for_flags(repo_name: str, github_token: str, flag_keys: List[str]) -> Dict[str, List[str]]:
    """Scan codebase for feature flag references."""
    if not GITHUB_AVAILABLE:
        raise ImportError("PyGithub not installed. Install with: pip install PyGithub")
    
    g = Github(github_token)
    repo = g.get_repo(repo_name)
    
    # Common file extensions to search
    extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs"]
    
    flag_references = {key: [] for key in flag_keys}
    
    try:
        # Search for each flag key in the codebase
        for flag_key in flag_keys:
            # Search for common patterns
            patterns = [
                f'"{flag_key}"',
                f"'{flag_key}'",
                f"`{flag_key}`",
                f"isFeatureEnabled.*{flag_key}",
                f"getFeatureFlag.*{flag_key}",
                f"featureFlags.*{flag_key}",
                f"flags.*{flag_key}",
            ]
            
            for pattern in patterns:
                try:
                    results = repo.search_code(pattern, language=None)
                    for result in results:
                        file_path = result.path
                        if any(file_path.endswith(ext) for ext in extensions):
                            if file_path not in flag_references[flag_key]:
                                flag_references[flag_key].append(file_path)
                except Exception as e:
                    # GitHub API rate limits or search limitations
                    continue
    except Exception as e:
        print(f"Warning: Error scanning codebase: {e}")
    
    return flag_references


def calculate_flag_age(creation_date: str) -> int:
    """Calculate age of flag in days."""
    try:
        # Try different date formats
        for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"]:
            try:
                created = datetime.strptime(creation_date, fmt)
                age = (datetime.now() - created.replace(tzinfo=None)).days
                return age
            except ValueError:
                continue
        return 0
    except:
        return 0


def audit_feature_flags(
    repo_name: str,
    provider: str,
    github_token: Optional[str] = None,
    provider_api_key: Optional[str] = None,
    age_threshold: int = 30,
    provider_base_url: Optional[str] = None
) -> Dict:
    """
    Audit feature flags in a repository.
    
    Args:
        repo_name: Repository in format "owner/repo"
        provider: "launchdarkly" or "flagsmith"
        github_token: GitHub personal access token
        provider_api_key: Feature flag provider API key
        age_threshold: Days threshold for flag age (default: 30)
        provider_base_url: Base URL for provider (for Flagsmith)
    
    Returns:
        Audit results dictionary
    """
    github_token = github_token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        raise ValueError("GITHUB_TOKEN not found in environment or provided")
    
    # Initialize provider
    if provider.lower() == "launchdarkly":
        provider_api_key = provider_api_key or os.getenv("LAUNCHDARKLY_API_KEY")
        if not provider_api_key:
            raise ValueError("LAUNCHDARKLY_API_KEY not found")
        flag_provider = LaunchDarklyProvider(provider_api_key)
    elif provider.lower() == "flagsmith":
        provider_api_key = provider_api_key or os.getenv("FLAGSMITH_API_KEY")
        if not provider_api_key:
            raise ValueError("FLAGSMITH_API_KEY not found")
        base_url = provider_base_url or os.getenv("FLAGSMITH_BASE_URL", "https://api.flagsmith.com/api/v1")
        flag_provider = FlagsmithProvider(provider_api_key, base_url)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
    
    # Fetch flags
    print(f"Fetching flags from {provider}...")
    flags = flag_provider.get_flags()
    print(f"Found {len(flags)} flags")
    
    # Get flag keys
    flag_keys = [flag["key"] for flag in flags if flag.get("key")]
    
    # Scan codebase
    print(f"Scanning codebase {repo_name} for flag references...")
    flag_references = scan_codebase_for_flags(repo_name, github_token, flag_keys)
    
    # Analyze flags
    results = {
        "repo": repo_name,
        "provider": provider,
        "audit_date": datetime.now().isoformat(),
        "total_flags": len(flags),
        "flags": []
    }
    
    for flag in flags:
        flag_key = flag.get("key")
        if not flag_key:
            continue
        
        age = calculate_flag_age(flag.get("creation_date", ""))
        references = flag_references.get(flag_key, [])
        has_references = len(references) > 0
        
        # Determine risk level
        risk_level = "low"
        issues = []
        
        if age > age_threshold:
            risk_level = "medium"
            issues.append(f"Flag is {age} days old (threshold: {age_threshold} days)")
        
        if not has_references:
            risk_level = "high"
            issues.append("No references found in codebase")
        
        if flag.get("archived", False):
            issues.append("Flag is archived")
        
        if flag.get("temporary", False) and age > age_threshold:
            risk_level = "high"
            issues.append("Temporary flag exceeded age threshold")
        
        # Check if enabled in production
        environments = flag.get("environments", {})
        enabled_in_prod = False
        if isinstance(environments, dict):
            for env_name, env_data in environments.items():
                if "production" in env_name.lower() or "prod" in env_name.lower():
                    if isinstance(env_data, dict) and env_data.get("on", False):
                        enabled_in_prod = True
                    elif isinstance(env_data, bool) and env_data:
                        enabled_in_prod = True
        
        if enabled_in_prod and not has_references:
            risk_level = "high"
            issues.append("Enabled in production but no code references")
        
        flag_result = {
            "key": flag_key,
            "name": flag.get("name", flag_key),
            "description": flag.get("description", ""),
            "age_days": age,
            "creation_date": flag.get("creation_date", ""),
            "archived": flag.get("archived", False),
            "temporary": flag.get("temporary", False),
            "enabled_in_prod": enabled_in_prod,
            "code_references": references,
            "reference_count": len(references),
            "risk_level": risk_level,
            "issues": issues,
            "recommendation": _get_recommendation(risk_level, issues, age, has_references)
        }
        
        results["flags"].append(flag_result)
    
    # Summary statistics
    results["summary"] = {
        "high_risk": sum(1 for f in results["flags"] if f["risk_level"] == "high"),
        "medium_risk": sum(1 for f in results["flags"] if f["risk_level"] == "medium"),
        "low_risk": sum(1 for f in results["flags"] if f["risk_level"] == "low"),
        "unused_flags": sum(1 for f in results["flags"] if f["reference_count"] == 0),
        "old_flags": sum(1 for f in results["flags"] if f["age_days"] > age_threshold),
        "prod_flags_no_refs": sum(1 for f in results["flags"] if f["enabled_in_prod"] and f["reference_count"] == 0)
    }
    
    return results


def _get_recommendation(risk_level: str, issues: List[str], age: int, has_references: bool) -> str:
    """Generate recommendation based on flag analysis."""
    if risk_level == "high":
        if not has_references:
            return "Consider removing this flag if it's no longer needed, or verify it's used in a way not detected by the scan"
        if age > 90:
            return "Flag is very old and unused - strong candidate for removal"
    elif risk_level == "medium":
        if age > 60:
            return "Review flag usage and consider cleanup if no longer needed"
    else:
        return "Flag appears healthy"
    
    return "Review flag status"


def save_report(results: Dict, output_path: str, format: str = "json"):
    """Save audit report to file."""
    output_path = Path(output_path)
    
    if format == "json":
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
    
    elif format == "csv":
        import pandas as pd
        df = pd.DataFrame(results["flags"])
        df.to_csv(output_path, index=False)
    
    elif format == "md":
        with open(output_path, "w") as f:
            f.write(f"# Feature Flag Audit Report\n\n")
            f.write(f"**Repository:** {results['repo']}\n")
            f.write(f"**Provider:** {results['provider']}\n")
            f.write(f"**Audit Date:** {results['audit_date']}\n")
            f.write(f"**Total Flags:** {results['total_flags']}\n\n")
            
            f.write("## Summary\n\n")
            summary = results["summary"]
            f.write(f"- **High Risk:** {summary['high_risk']}\n")
            f.write(f"- **Medium Risk:** {summary['medium_risk']}\n")
            f.write(f"- **Low Risk:** {summary['low_risk']}\n")
            f.write(f"- **Unused Flags:** {summary['unused_flags']}\n")
            f.write(f"- **Old Flags (>30 days):** {summary['old_flags']}\n")
            f.write(f"- **Prod Flags (No Refs):** {summary['prod_flags_no_refs']}\n\n")
            
            f.write("## Flag Details\n\n")
            f.write("| Key | Name | Age (days) | References | Risk | Issues |\n")
            f.write("|-----|------|------------|------------|------|--------|\n")
            
            for flag in sorted(results["flags"], key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["risk_level"]]):
                issues_str = "; ".join(flag["issues"][:2]) if flag["issues"] else "None"
                f.write(f"| {flag['key']} | {flag['name']} | {flag['age_days']} | "
                       f"{flag['reference_count']} | {flag['risk_level']} | {issues_str} |\n")
    
    print(f"Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Audit feature flags in a repository")
    parser.add_argument("repos", nargs="+", help="Repository/repositories in format 'owner/repo'")
    parser.add_argument("--provider", "-p", required=True, choices=["launchdarkly", "flagsmith"],
                       help="Feature flag provider")
    parser.add_argument("--age-threshold", "-a", type=int, default=30,
                       help="Age threshold in days (default: 30)")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format", "-f", default="json", choices=["json", "csv", "md"],
                       help="Output format (default: json)")
    parser.add_argument("--token", "-t", help="GitHub personal access token")
    parser.add_argument("--provider-key", help="Feature flag provider API key")
    parser.add_argument("--provider-url", help="Provider base URL (for Flagsmith)")
    
    args = parser.parse_args()
    
    try:
        all_results = []
        
        for repo in args.repos:
            print(f"\n{'='*60}")
            print(f"Auditing {repo}")
            print(f"{'='*60}\n")
            
            results = audit_feature_flags(
                repo_name=repo,
                provider=args.provider,
                github_token=args.token,
                provider_api_key=args.provider_key,
                age_threshold=args.age_threshold,
                provider_base_url=args.provider_url
            )
            
            all_results.append(results)
            
            # Print summary
            print(f"\nSummary for {repo}:")
            summary = results["summary"]
            print(f"  Total Flags: {results['total_flags']}")
            print(f"  High Risk: {summary['high_risk']}")
            print(f"  Medium Risk: {summary['medium_risk']}")
            print(f"  Low Risk: {summary['low_risk']}")
            print(f"  Unused Flags: {summary['unused_flags']}")
            print(f"  Old Flags: {summary['old_flags']}")
        
        # Save results
        if args.output:
            if len(all_results) == 1:
                save_report(all_results[0], args.output, args.format)
            else:
                # Save combined report
                combined = {
                    "audit_date": datetime.now().isoformat(),
                    "repositories": all_results
                }
                if args.format == "json":
                    with open(args.output, "w") as f:
                        json.dump(combined, f, indent=2)
                    print(f"\nCombined report saved to {args.output}")
        else:
            # Print JSON to stdout
            if len(all_results) == 1:
                print("\n" + json.dumps(all_results[0], indent=2))
            else:
                print("\n" + json.dumps({"repositories": all_results}, indent=2))
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
