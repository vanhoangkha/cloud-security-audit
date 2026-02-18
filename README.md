# Cloud Security Audit Tools Collection

Comprehensive collection of open-source cloud security tools for AWS, GCP, Azure, and Kubernetes.

## 📁 Structure

```
├── aws/                    # AWS-specific tools
├── azure/                  # Azure-specific tools
├── gcp/                    # GCP-specific tools
├── kubernetes/             # Kubernetes security tools
├── iac-security/           # Infrastructure as Code scanning
├── secrets-detection/      # Secret scanning tools
└── multi-cloud/            # Multi-cloud tools
```

## 🛠️ Tools Included

### Multi-Cloud (`multi-cloud/`)
| Tool | Description |
|------|-------------|
| **Prowler** | AWS/GCP/Azure security assessments, CIS benchmarks |
| **ScoutSuite** | Multi-cloud security auditing |
| **CloudSploit** | Cloud security configuration monitoring |
| **Cloud Custodian** | Rules engine for cloud resource management |

### AWS (`aws/`)
| Tool | Description |
|------|-------------|
| **Pacu** | AWS exploitation framework (pentesting) |
| **Cloudsplaining** | IAM policy analysis |
| **Arsenal AWS Security** | Curated list of AWS security tools |

### Azure (`azure/`)
| Tool | Description |
|------|-------------|
| **Azure-Audit** | Compliance audit scripts |
| **AzureInspect** | PowerShell audit with HTML reports |
| **Stormspotter** | Azure AD visualization |

### GCP (`gcp/`)
| Tool | Description |
|------|-------------|
| **GCP-Audit** | CIS Benchmark compliance scripts |

### Kubernetes (`kubernetes/`)
| Tool | Description |
|------|-------------|
| **Trivy** | Vulnerability scanner for containers/IaC |
| **Kube-bench** | CIS Kubernetes Benchmark checks |
| **Kubescape** | Kubernetes security platform |
| **Falco** | Runtime security monitoring |

### IaC Security (`iac-security/`)
| Tool | Description |
|------|-------------|
| **Checkov** | Static analysis for Terraform, CloudFormation, K8s |
| **KICS** | 2400+ queries for IaC security |
| **Terrascan** | Detect compliance violations in IaC |
| **tfsec** | Terraform static analysis |

### Secrets Detection (`secrets-detection/`)
| Tool | Description |
|------|-------------|
| **TruffleHog** | Find leaked credentials |
| **Gitleaks** | Git secret scanning |

## 🚀 Quick Start

### Install CLI Tools
```bash
# Multi-cloud
pip install prowler scoutsuite cloudsploit checkov

# Kubernetes
brew install trivy kubescape

# Secrets
brew install trufflehog gitleaks
```

### Run Scans
```bash
# AWS
prowler aws
scout aws

# GCP
prowler gcp --project-id PROJECT_ID
scout gcp --user-account

# Azure
prowler azure --subscription-id SUB_ID
scout azure --cli

# Kubernetes
trivy k8s --report summary cluster
kubescape scan framework nsa

# IaC
checkov -d ./terraform
tfsec ./terraform

# Secrets
trufflehog git file://./repo
gitleaks detect -s ./repo
```

## 📋 Prerequisites
- AWS: `aws configure`
- GCP: `gcloud auth login`
- Azure: `az login`
- Kubernetes: `kubectl` configured

## 📚 References
- [Prowler](https://github.com/prowler-cloud/prowler)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Checkov](https://github.com/bridgecrewio/checkov)

## 📄 License
Each tool maintains its original license. See individual tool directories.
