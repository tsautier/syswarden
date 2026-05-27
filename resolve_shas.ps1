# Enforce strict error handling
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Output "Resolving full commit SHAs for GitHub Actions pinning..."

# Retrieve and parse SHAs using git ls-remote and whitespace splitting
$SCORECARD_SHA = (-split (git ls-remote https://github.com/ossf/scorecard-action refs/tags/v2.4.3))[0]
$SHFMT_SHA     = (-split (git ls-remote https://github.com/mfinelli/setup-shfmt refs/tags/v4))[0]
$GITLEAKS_SHA  = (-split (git ls-remote https://github.com/gitleaks/gitleaks-action refs/tags/v2))[0]
$TRIVY_SHA     = (-split (git ls-remote https://github.com/aquasecurity/trivy-action refs/tags/v0.35.0))[0]

Write-Output "---"
Write-Output "SCORECARD_SHA: ${SCORECARD_SHA}"
Write-Output "SHFMT_SHA:     ${SHFMT_SHA}"
Write-Output "GITLEAKS_SHA:  ${GITLEAKS_SHA}"
Write-Output "TRIVY_SHA:     ${TRIVY_SHA}"
