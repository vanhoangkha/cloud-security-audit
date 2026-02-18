# Cloud Security Audit Tools

Collection of cloud security audit tools for AWS, GCP, and Azure.

## Tools Included

### Multi-Cloud (Already installed via pip/apt)
| Tool | AWS | GCP | Azure | Command |
|------|-----|-----|-------|---------|
| Prowler | ✅ | ✅ | ✅ | `prowler aws/gcp/azure` |
| ScoutSuite | ✅ | ✅ | ✅ | `scout aws/gcp/azure` |
| CloudSploit | ✅ | ✅ | ✅ | `cloudsploit scan --cloud <provider>` |
| Checkov | ✅ | ✅ | ✅ | `checkov -d .` |
| Steampipe | ✅ | ✅ | ✅ | `steampipe query` |

### GCP Specific
- **gcp-audit/** - CIS Benchmark compliance scripts

### Azure Specific
- **azure-audit/** - Azure compliance audit scripts
- **AzureInspect/** - PowerShell audit with HTML reports
- **Stormspotter/** - Azure AD visualization

## Usage

### AWS
```bash
prowler aws
scout aws
```

### GCP
```bash
prowler gcp --project-id PROJECT_ID
scout gcp --user-account
cd gcp-audit/src && ./cis-1.1.1-project-iam-policy.sh
```

### Azure
```bash
prowler azure --subscription-id SUB_ID
scout azure --cli
pwsh AzureInspect/AzureInspect.ps1
```

## Prerequisites
- AWS: `aws configure`
- GCP: `gcloud auth login`
- Azure: `az login`
