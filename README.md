# PS-Last_app_signin

A PowerShell script that audits Azure AD app registrations for inactivity and unused credentials using the Microsoft Graph API. Exports a risk-classified CSV report.

## What It Does

- Fetches all **app registrations** and their **service principals** from your tenant
- Pulls **sign-in activity** from the Graph beta endpoint (delegated, app-only, and managed identity)
- Evaluates each app against a 180-day inactivity window
- Classifies each app with a **risk level** (High / Medium / Low / Active / Ignore)
- Exports a full CSV report and prints a summary + high-risk list to the console

## Prerequisites

- **PowerShell 5.1+** or **PowerShell 7+**
- **Microsoft.Graph** PowerShell module

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

- An account (or service principal) with the following Graph permissions:
  - `Application.Read.All`
  - `AuditLog.Read.All`
  - `Directory.Read.All`

> These permissions require **admin consent** in your tenant.

## Usage

```powershell
.\last_signin.ps1
```

The script will prompt you to authenticate via `Connect-MgGraph`. After it runs, a CSV file named `UnusedApps_YYYYMMDD.csv` is written to the current directory.

## Output Columns

| Column | Description |
|---|---|
| `DisplayName` | App registration display name |
| `AppId` | Application (client) ID |
| `ObjectId` | App registration object ID |
| `SignInAudience` | Target audience (single tenant, multi, etc.) |
| `CreatedDaysAgo` | How many days ago the app was created |
| `HasServicePrincipal` | Whether a service principal exists |
| `SPEnabled` | Whether the service principal is enabled |
| `SPType` | Service principal type |
| `LastDelegatedSignIn` | Most recent delegated sign-in timestamp |
| `LastAppOnlySignIn` | Most recent app-only sign-in timestamp |
| `LastOverallActivity` | Most recent sign-in across all vectors |
| `DaysSinceActivity` | Days since last sign-in |
| `HasSecrets` | Whether client secrets exist |
| `SecretExpiry` | Expiry of the most recent secret |
| `SecretsExpired` | Whether all secrets are expired |
| `HasCerts` | Whether certificates exist |
| `CertExpiry` | Expiry of the most recent certificate |
| `CertsExpired` | Whether all certificates are expired |
| `PermissionCount` | Number of required resource access entries |
| `UnusedReason` | Why the app was flagged (if applicable) |
| `RiskLevel` | Active / High / Medium / Low / Ignore |
| `Notes` | App registration notes field |

## Risk Classification

| Risk Level | Criteria |
|---|---|
| **High** | Never used or inactive >180 days **and** has active credentials |
| **Medium** | Never used or inactive >180 days, no credentials |
| **Low** | No service principal, SP disabled, or all credentials expired |
| **Active** | Recently used (within 180 days) |
| **Ignore** | App created less than 30 days ago (insufficient data) |

## Notes

- Sign-in activity data comes from the **beta** Graph endpoint (`/reports/servicePrincipalSignInActivities`) and may not reflect real-time data.
- The 180-day cutoff is set at the top of the script and can be adjusted by changing the `$cutoffDate` variable.
- The script is **read-only** — it makes no changes to your tenant.

## License

MIT
