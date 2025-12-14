# Feature Flag Auditor

Scans codebase and feature flag providers to identify unused, stale, or risky feature flags.

## Features

- Scans GitHub repositories for feature flag usage
- Integrates with LaunchDarkly and Flagsmith
- Identifies:
  - Flags older than specified days (default: 30)
  - Flags in production but with no usage
  - Flags tied to deprecated features
  - Flags with no references in codebase
- Generates audit reports (JSON, CSV, Markdown)
- Supports cron jobs for regular audits

## Installation

```bash
pip install -r requirements.txt
```

## Setup

1. Get a GitHub Personal Access Token with `repo` scope

2. Get API keys for your feature flag provider:
   - LaunchDarkly: API key from account settings
   - Flagsmith: API key from project settings

3. Create `.env` file:
```env
GITHUB_TOKEN=your_github_token
LAUNCHDARKLY_API_KEY=your_launchdarkly_key  # Optional
FLAGSMITH_API_KEY=your_flagsmith_key  # Optional
FLAGSMITH_BASE_URL=https://api.flagsmith.com/api/v1  # Optional
```

## Usage

### CLI Mode

```bash
# Audit flags in a repository
python audit_flags.py owner/repo --provider launchdarkly

# Check for flags older than 60 days
python audit_flags.py owner/repo --provider launchdarkly --age-threshold 60

# Output to CSV
python audit_flags.py owner/repo --provider launchdarkly --output report.csv --format csv

# Scan multiple repositories
python audit_flags.py owner/repo1 owner/repo2 --provider launchdarkly
```

### Python API

```python
from audit_flags import audit_feature_flags

results = audit_feature_flags(
    repo_name="owner/repo",
    provider="launchdarkly",
    age_threshold=30
)

print(results)
```

### Scheduled Audits (Cron)

Add to crontab for daily audits:
```bash
0 9 * * * cd /path/to/feature-flag-auditor && python audit_flags.py owner/repo --provider launchdarkly --output /tmp/flag-audit-$(date +\%Y\%m\%d).json
```

## Supported Providers

- **LaunchDarkly**: Full support
- **Flagsmith**: Full support
- **Custom**: Extend the base provider class

## Output Format

The audit report includes:
- Flag name and key
- Creation date and age
- Usage status (used/unused)
- Code references
- Risk level
- Recommendations

## License

MIT
