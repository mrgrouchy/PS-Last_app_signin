# PS-Last_app_signin

PowerShell scripts for auditing Entra ID / Azure AD service principal and app registration activity, to identify unused apps that are safe to disable.

---

## Scripts

### `Get-AppUsageReport.ps1` — Recommended

The primary, merged script. Combines **Graph SP sign-in activity (180d)** with optional **Log Analytics user sign-ins** for the widest possible activity picture. No LA workspace required to run.

### `Get-App_last_used.ps1` — Graph only

Lightweight Graph-only script focused on service principal activity and dependency signals. Useful for a quick run without any Azure prerequisites.

### `last_signin.ps1` — Log Analytics only

Original script. Requires a Log Analytics workspace with Entra sign-in tables connected. Reports on app registrations rather than service principals.

---

## Get-AppUsageReport.ps1

### What It Does

- Fetches **SP sign-in activity** from Graph (`/beta/reports/servicePrincipalSignInActivities`) — up to **180 days**, Microsoft-managed retention independent of your LA workspace
- Optionally queries **Log Analytics** for interactive and non-interactive **user** sign-ins (`isfuzzy=true` — missing tables are silently skipped)
- Pre-fetches all **app registrations** in bulk for credential and age analysis
- For each service principal, checks:
  - Last sign-in across all vectors (delegated, app-only, interactive user, non-interactive user)
  - App role assignments and OAuth permission grants (structural dependency signals)
  - Credential liveness (secrets and certificates, with expiry dates)
- Classifies each app with a **risk level** and **SafeToDisable** flag
- Prints a colour-coded summary and exports a full CSV report

### Prerequisites

- **PowerShell 5.1+** or **PowerShell 7+**
- Modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Only needed if using -WorkspaceId (Log Analytics)
Install-Module Az.OperationalInsights -Scope CurrentUser
```

- Graph scopes (admin consent required):
  `AuditLog.Read.All`, `Directory.Read.All`, `Application.Read.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.Read.All`
- If using `-WorkspaceId`: Azure read access to the LA workspace (e.g. `Log Analytics Reader`)

### Usage

```powershell
# Graph only — 180d SP activity, no LA required
.\Get-AppUsageReport.ps1 -OutCsv .\report.csv

# Graph + Log Analytics — adds 90d interactive/non-interactive user sign-ins
.\Get-AppUsageReport.ps1 -WorkspaceId "<guid>" -OutCsv .\report.csv

# Custom inactivity threshold, include apps that have never signed in
.\Get-AppUsageReport.ps1 -WorkspaceId "<guid>" -UnusedDays 90 -LookbackDays 90 -IncludeNeverUsed -OutCsv .\report.csv
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-UnusedDays` | `180` | Days of inactivity before an app is considered unused |
| `-WorkspaceId` | _(empty)_ | Log Analytics workspace ID. Omit to run Graph-only |
| `-LookbackDays` | `90` | LA query window — should not exceed your workspace retention |
| `-IncludeNeverUsed` | off | Include SPs with no recorded sign-in activity |
| `-OutCsv` | _(empty)_ | Path to export CSV. No file written if omitted |

### Sign-in Data Sources

| Source | Data | Retention |
|---|---|---|
| Graph `servicePrincipalSignInActivities` | SP delegated + app-only sign-ins | Up to 180 days |
| LA `SigninLogs` | Interactive user sign-ins | Your workspace retention |
| LA `AADNonInteractiveUserSignInLogs` | Non-interactive user sign-ins | Your workspace retention |

`TrueLastActivity` in the report is the maximum date across all six activity vectors.

### Output Columns

| Column | Description |
|---|---|
| `DisplayName` | Service principal display name |
| `AppId` | Application (client) ID |
| `AppRegistrationObjectId` | Object ID of the backing app registration (null for external SPs) |
| `ServicePrincipalId` | Object ID of the service principal |
| `ServicePrincipalType` | Application / ManagedIdentity / Legacy / etc. |
| `AccountEnabled` | Whether the service principal is enabled |
| `CreatedDaysAgo` | Age of the app registration in days |
| `TrueLastActivity` | Most recent sign-in across all vectors |
| `DaysSinceActivity` | Days since `TrueLastActivity` |
| `LastInteractiveSignIn` | Last interactive user sign-in (from LA) |
| `LastNonInteractiveSignIn` | Last non-interactive user sign-in (from LA) |
| `DelegatedClientUtc` | Last delegated sign-in where this app was the client (Graph) |
| `DelegatedResourceUtc` | Last delegated sign-in where this app was the resource/API (Graph) |
| `AppAuthClientUtc` | Last app-only sign-in where this app was the client (Graph) |
| `AppAuthResourceUtc` | Last app-only sign-in where this app was the resource/API (Graph) |
| `RoleAssignments` | Number of app role assignments granted to this SP |
| `OAuthClientGrants` | Number of OAuth2 grants where this SP is the client |
| `OAuthResourceGrants` | Number of OAuth2 grants where this SP is the resource |
| `HasSecrets` | Whether client secrets exist |
| `SecretExpiry` | Expiry of the most recent secret |
| `SecretsExpired` | Whether all secrets are expired |
| `HasCerts` | Whether certificates exist |
| `CertExpiry` | Expiry of the most recent certificate |
| `CertsExpired` | Whether all certificates are expired |
| `HasLiveCredentials` | Whether any non-expired credential exists |
| `RiskLevel` | Active / High / Medium / Low / Ignore |
| `SafeToDisable` | `True` if Low/Medium risk AND no dependency signals |
| `DependencySignals` | Semicolon-separated structural reasons the app may still be needed |

### Sign-in Field Reference

| Field | Source | Who is acting | User involved | This app is... |
|---|---|---|---|---|
| `LastInteractiveSignIn` | LA `SigninLogs` | Human user | Yes | Being logged into |
| `LastNonInteractiveSignIn` | LA `AADNonInteractiveUserSignInLogs` | Token refresh | Yes (silently) | Maintaining a user session |
| `DelegatedClientUtc` | Graph | This app | Yes | Calling another API on behalf of a user |
| `DelegatedResourceUtc` | Graph | Another app | Yes | Being called as an API on behalf of a user |
| `AppAuthClientUtc` | Graph | This app | No | Calling another API autonomously |
| `AppAuthResourceUtc` | Graph | Another app | No | Being called as an API autonomously |

- **`LastInteractiveSignIn`** â€” A user was prompted to sign in. MFA challenges happen here. The classic "user logged into the app" event.
- **`LastNonInteractiveSignIn`** â€” A token was silently refreshed on behalf of a user with no prompt shown. High-volume, low-visibility signal that an app is actively in use.
- **`DelegatedClientUtc`** â€” This app called another API on behalf of a signed-in user (e.g. a web app calling Graph with the user's identity). Confirms the app is making outbound API calls.
- **`DelegatedResourceUtc`** â€” Another app called this app's API on behalf of a user. Strong signal this app is still needed as a dependency. Surfaces as `UsedAsAPI` in `DependencySignals`.
- **`AppAuthClientUtc`** â€” This app authenticated to another API using its own identity (client credentials / app-only). Daemon services, background jobs, and automation pipelines appear here.
- **`AppAuthResourceUtc`** â€” Another app authenticated to this app's API using app-only flow. Confirms this app is being consumed service-to-service. Surfaces as `UsedAsAPIAppOnly` in `DependencySignals`.
### Risk Classification

| Risk Level | Criteria |
|---|---|
| **Active** | Sign-in activity within `-UnusedDays` |
| **High** | Inactive or never used **and** has live (non-expired) credentials |
| **Medium** | Inactive or never used, no live credentials |
| **Low** | SP disabled, or all credentials expired |
| **Ignore** | App created less than 30 days ago (insufficient data) |

### Dependency Signals

These are independent of `RiskLevel` — an app can be `Medium` risk but still have active dependents.

| Signal | Meaning |
|---|---|
| `UsedAsAPI` | Has delegated resource sign-in activity (another app calls it as an API) |
| `UsedAsAPIAppOnly` | Has app-only resource sign-in activity |
| `AppRoleAssignments` | Has one or more app role assignments |
| `OAuthClientGrants` | Has OAuth2 permission grants as client |
| `OAuthResourceGrants` | Has OAuth2 permission grants as resource |

---

## Get-App_last_used.ps1

Graph-only, no Azure prerequisites. Iterates all service principals, checks Graph SP activity, dependency signals, and whether the app registration has credentials. Outputs `SafeToDisable` and `WhyNotSafe` tags.

```powershell
.\Get-App_last_used.ps1 [-UnusedDays 180] [-IncludeNeverUsed] [-OutCsv .\report.csv]
```

---

## last_signin.ps1

Requires a Log Analytics workspace with `SigninLogs` and `AADServicePrincipalSignInLogs` connected. Reports on **app registrations** (not service principals). Useful if you want to cross-reference with interactive user sign-in volume.

```powershell
# Set WorkspaceId at the top of the script, then:
.\last_signin.ps1
```

---

## Notes

- All scripts are **read-only** — no changes are made to your tenant.
- Graph `servicePrincipalSignInActivities` requires an Entra ID P1 or P2 licence.
- LA retention is configurable in your workspace settings (default 90 days, up to 2 years).

## License

MIT
