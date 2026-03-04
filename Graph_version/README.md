# PS-Last_app_signin

A PowerShell script that audits Entra ID / Azure AD service principals for inactivity using the **Microsoft Graph API** exclusively — no Log Analytics workspace required. Exports a report identifying apps that are safe to disable.

## What It Does

- Fetches the full **service principal sign-in activity** dataset from Graph (`/beta/reports/servicePrincipalSignInActivities`)
- Fetches all **service principals** from Graph (`/v1.0/servicePrincipals`)
- For each service principal, checks:
  - Last sign-in across all activity vectors (delegated, app-only, rollup)
  - App role assignments (granted API permissions)
  - OAuth2 permission grants (as client and as resource)
  - Whether the app registration has active credentials (secrets or certificates)
- Flags each app as **SafeToDisable** or explains **why not** via reason tags
- Optionally exports a full CSV report

## Prerequisites

- **PowerShell 5.1+** or **PowerShell 7+**
- Microsoft Graph PowerShell SDK (authentication module):

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

- An account with admin consent for the following Graph scopes:
  - `AuditLog.Read.All`
  - `Directory.Read.All`
  - `Application.Read.All`
  - `AppRoleAssignment.ReadWrite.All`
  - `DelegatedPermissionGrant.Read.All`

## Usage

```powershell
# Basic run — apps inactive for 180+ days, excluding never-used apps
.\Get-App_last_used.ps1

# Custom inactivity threshold
.\Get-App_last_used.ps1 -UnusedDays 90

# Include apps that have never had any sign-in activity
.\Get-App_last_used.ps1 -IncludeNeverUsed

# Export to CSV
.\Get-App_last_used.ps1 -OutCsv .\report.csv

# Combine options
.\Get-App_last_used.ps1 -UnusedDays 90 -IncludeNeverUsed -OutCsv .\report.csv
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-UnusedDays` | int | `180` | Number of days of inactivity before an app is considered unused |
| `-IncludeNeverUsed` | switch | off | Include service principals with no recorded sign-in activity at all |
| `-OutCsv` | string | `""` | Path to export a CSV report; if empty, no file is written |

## Output Columns

| Column | Description |
|---|---|
| `DisplayName` | Service principal display name |
| `AppId` | Application (client) ID |
| `AppRegistrationObjectId` | Object ID of the backing app registration (null for external/managed SPs) |
| `ServicePrincipalId` | Object ID of the service principal |
| `ServicePrincipalType` | Application / ManagedIdentity / Legacy / etc. |
| `AccountEnabled` | Whether the service principal is enabled |
| `LastUsedUtc` | Most recent sign-in across all activity vectors |
| `DelegatedClientUtc` | Last delegated sign-in where this app acted as client |
| `DelegatedResourceUtc` | Last delegated sign-in where this app acted as resource (API) |
| `AppAuthClientUtc` | Last app-only sign-in where this app acted as client |
| `AppAuthResourceUtc` | Last app-only sign-in where this app acted as resource (API) |
| `RoleAssignments` | Number of app role assignments granted to this SP |
| `OAuthClientGrants` | Number of OAuth2 permission grants where this SP is the client |
| `OAuthResourceGrants` | Number of OAuth2 permission grants where this SP is the resource |
| `HasCredentials` | Whether the app registration has active secrets or certificates |
| `SafeToDisable` | `True` if the app has no recent activity and no dependency signals |
| `WhyNotSafe` | Semicolon-separated list of reasons the app was not flagged safe |

## Why Not Safe — Reason Tags

| Tag | Meaning |
|---|---|
| `RecentActivity` | Sign-in activity within the `-UnusedDays` window |
| `UsedAsAPI` | Has delegated resource sign-in activity (another app calls it as an API) |
| `UsedAsAPIAppOnly` | Has app-only resource sign-in activity |
| `AppRoleAssignments` | Has one or more app role assignments |
| `OAuthClientGrants` | Has OAuth2 permission grants as client |
| `OAuthResourceGrants` | Has OAuth2 permission grants as resource |
| `CredentialsPresent` | App registration has active secrets or certificates |

## Notes

- Sign-in activity data is sourced from the Graph beta endpoint `servicePrincipalSignInActivities`, which retains data for up to **30 days** for most tenants (P1/P2 licence required).
- The script pages through **all** service principals and activity records — there is no cap on result counts.
- The script is **read-only** — it makes no changes to your tenant.

## License

MIT
