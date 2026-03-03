# PS-Last_app_signin

A PowerShell script that audits Azure AD / Entra ID app registrations for inactivity and unused credentials. Uses **Log Analytics / Microsoft Sentinel** for interactive + service principal sign-ins, and the **Entra audit log API** for non-interactive sign-ins. Exports a risk-classified CSV report.

## What It Does

- Queries **Log Analytics** via KQL for 180 days of interactive and service principal sign-in activity
  - Uses `SigninLogs` and `AADServicePrincipalSignInLogs`
- Queries the **Entra audit log API** (`/beta/auditLogs/signIns`) for the last 30 days of non-interactive user sign-ins
- Fetches all **app registrations** and **service principals** from Microsoft Graph
- Combines all sources for the most complete activity picture per app
- Classifies each app with a **risk level** (High / Medium / Low / Active / Ignore)
- Exports a full CSV report and prints a summary + high-risk list to the console

## Prerequisites

- **PowerShell 5.1+** or **PowerShell 7+**
- Required modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Applications    -Scope CurrentUser
Install-Module Az.OperationalInsights          -Scope CurrentUser
```

- A **Log Analytics workspace** with `SigninLogs` and `AADServicePrincipalSignInLogs` connected.
- An account with the following permissions:
  - **Microsoft Graph**: `Application.Read.All`, `Directory.Read.All` *(requires admin consent)*
  - **Azure**: read access to the Log Analytics workspace (e.g. `Log Analytics Reader`)

## Configuration

Before running, set your workspace ID at the top of the script:

```powershell
$WorkspaceId = "<your-log-analytics-workspace-id>"
```

The script validates this value and exits if the placeholder is still present.

## Usage

```powershell
.\last_signin.ps1
```

The script will prompt you to authenticate via `Connect-MgGraph` and `Connect-AzAccount`. After it runs, a CSV file named `UnusedApps_YYYYMMDD.csv` is written to the current directory.

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
| `LastInteractiveSignIn` | Most recent interactive user sign-in (from Log Analytics) |
| `LastNonInteractiveSignIn` | Most recent non-interactive sign-in (from Entra audit logs, 30-day window) |
| `LastSPSignIn` | Most recent service principal sign-in (from Log Analytics) |
| `LastActivityOverall` | Most recent sign-in across all vectors |
| `DaysSinceActivity` | Days since last sign-in |
| `TotalSignIns180d` | Total sign-in count over the last 180 days |
| `HasSecrets` | Whether client secrets exist |
| `SecretExpiry` | Expiry of the most recent secret |
| `SecretsExpired` | Whether all secrets are expired |
| `HasCerts` | Whether certificates exist |
| `CertExpiry` | Expiry of the most recent certificate |
| `CertsExpired` | Whether all certificates are expired |
| `HasLiveCredentials` | Whether any non-expired credential exists |
| `PermissionCount` | Number of required resource access entries |
| `UnusedReason` | Why the app was flagged (if applicable) |
| `RiskLevel` | Active / High / Medium / Low / Ignore |
| `Notes` | App registration notes field |

## Risk Classification

| Risk Level | Criteria |
|---|---|
| **High** | Never used or inactive >180 days **and** has at least one live (non-expired) credential |
| **Medium** | Never used or inactive >180 days, no live credentials |
| **Low** | No service principal, SP disabled, or all credentials expired |
| **Active** | Has sign-in activity within the last 180 days |
| **Ignore** | App created less than 30 days ago (insufficient data) |

## Notes

- Sign-in data requires Entra diagnostic logs to be routed to a Log Analytics workspace. At minimum, connect `SigninLogs` and `AADServicePrincipalSignInLogs`.
- The Entra audit log API retains non-interactive sign-ins for **30 days**. `LastNonInteractiveSignIn` is therefore based on a 30-day window.
- If no data at all is found in Log Analytics for a given app, the SP `signInActivity` field from Graph is used as a final fallback.
- The 180-day window is baked into the KQL query and can be adjusted there.
- The script is **read-only** — it makes no changes to your tenant.

## License

MIT
