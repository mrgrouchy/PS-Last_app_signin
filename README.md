# PS-Entra-App-Last-Use-Report

PowerShell scripts for auditing Entra ID / Azure AD service principal and app registration activity, to identify unused apps that are safe to disable.

---

## Scripts

### `Get-AppUsageReport.ps1`

Combines **Graph SP sign-in activity (180d)** with optional **Log Analytics user and workload sign-ins** for the widest possible activity picture. No LA workspace required to run.

---

## Get-AppUsageReport.ps1

### What It Does

- Fetches **SP sign-in activity** from Graph (`/beta/reports/servicePrincipalSignInActivities`) — up to **180 days**, Microsoft-managed retention independent of your LA workspace
- Optionally queries **Log Analytics** for interactive user, service principal, and managed identity sign-ins (`isfuzzy=true` — missing tables are silently skipped)
- Pre-fetches all **app registrations** in bulk for credential and age analysis
- For each service principal, checks:
  - Last sign-in across all vectors (delegated, app-only, interactive user, SP, managed identity)
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

# Graph + Log Analytics — adds 90d interactive user and workload sign-ins
.\Get-AppUsageReport.ps1 -WorkspaceId "<guid>" -OutCsv .\report.csv

# Custom inactivity threshold, include apps that have never signed in
.\Get-AppUsageReport.ps1 -WorkspaceId "<guid>" -UnusedDays 90 -LookbackDays 90 -IncludeNeverUsed -OutCsv .\report.csv

# Scope the run to a specific list of service principals from a CSV
.\Get-AppUsageReport.ps1 -InputCsv .\targets.csv -OutCsv .\report.csv
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-UnusedDays` | `180` | Days of inactivity before an app is considered unused |
| `-WorkspaceId` | _(empty)_ | Log Analytics workspace ID. Omit to run Graph-only |
| `-LookbackDays` | `90` | LA query window — should not exceed your workspace retention |
| `-IncludeNeverUsed` | off | Include SPs with no recorded sign-in activity |
| `-InputCsv` | _(empty)_ | Path to a CSV of SP/app IDs to query. See [InputCsv filtering](#inputcsv-filtering) below |
| `-OutCsv` | _(empty)_ | Path to export CSV. No file written if omitted |

### InputCsv Filtering

Pass `-InputCsv` with a CSV file to restrict the report to a specific set of service principals instead of scanning the whole tenant. The script detects the ID column automatically using these common names (first match wins):

| Priority | Column names checked |
|---|---|
| SP Object ID | `ServicePrincipalObjectId`, `ServicePrincipalObjectID`, `ServicePrincipalId`, `SPObjectId`, `SPId`, `SP_Id`, `ObjectId`, `Id` |
| App ID (fallback) | `AppId`, `ApplicationId` |

When SP object ID columns are present, AppId matching is disabled — SP IDs take full precedence. If no recognised column is found, the first column in the CSV is used as SP object ID with a warning. The output CSV from a previous run can be fed directly back in as input (it contains both `ServicePrincipalId` and `AppId`).

### Sign-in Data Sources

| Source | Data | Retention |
|---|---|---|
| Graph `servicePrincipalSignInActivities` | SP delegated + app-only sign-ins | Up to 180 days |
| LA `SigninLogs` | Interactive user sign-ins | Your workspace retention |
| LA `AADServicePrincipalSignInLogs` | Service principal sign-ins | Your workspace retention |
| LA `AADManagedIdentitySignInLogs` | Managed identity sign-ins | Your workspace retention |

`TrueLastActivity` in the report is the maximum date across all seven activity vectors.

### Output Columns

| Column | Description |
|---|---|
| `DisplayName` | Service principal display name |
| `AppId` | Application (client) ID |
| `AppRegistrationObjectId` | Object ID of the backing app registration (null for external SPs) |
| `ServicePrincipalId` | Object ID of the service principal |
| `ServicePrincipalType` | Application / ManagedIdentity / Legacy / etc. |
| `AccountEnabled` | Combined enabled state (SP + app registration). `False` if either is disabled |
| `ServicePrincipalActivation` | Whether the service principal itself is enabled (independent of the app registration) |
| `CreatedDaysAgo` | Age of the app registration in days |
| `TrueLastActivity` | Most recent sign-in across all vectors |
| `DaysSinceActivity` | Days since `TrueLastActivity` |
| `LastInteractiveSignIn` | Last interactive user sign-in (from LA `SigninLogs`) |
| `LastServicePrincipalSignIn` | Last service principal sign-in (from LA `AADServicePrincipalSignInLogs`) |
| `LastManagedIdentitySignIn` | Last managed identity sign-in (from LA `AADManagedIdentitySignInLogs`) |
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
| `LastServicePrincipalSignIn` | LA `AADServicePrincipalSignInLogs` | Service principal | No | Authenticating as a workload identity |
| `LastManagedIdentitySignIn` | LA `AADManagedIdentitySignInLogs` | Managed identity | No | Authenticating via managed identity |
| `DelegatedClientUtc` | Graph | This app | Yes | Calling another API on behalf of a user |
| `DelegatedResourceUtc` | Graph | Another app | Yes | Being called as an API on behalf of a user |
| `AppAuthClientUtc` | Graph | This app | No | Calling another API autonomously |
| `AppAuthResourceUtc` | Graph | Another app | No | Being called as an API autonomously |

- **`LastInteractiveSignIn`** — A user was prompted to sign in. MFA challenges happen here. The classic “user logged into the app” event.
- **`LastServicePrincipalSignIn`** — The app authenticated as a service principal (e.g. via client secret or certificate). Captured in LA `AADServicePrincipalSignInLogs`. Complements the Graph activity timestamps with workspace-retention-based visibility.
- **`LastManagedIdentitySignIn`** — The app authenticated via a managed identity. Captured in LA `AADManagedIdentitySignInLogs`. Useful for Azure-hosted workloads that rely on system- or user-assigned managed identities rather than explicit credentials.
- **`DelegatedClientUtc`** — This app called another API on behalf of a signed-in user (e.g. a web app calling Graph with the user's identity). Confirms the app is making outbound API calls.
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
| `UsedAsAPI` | `DelegatedResourceUtc` is non-null — another app has called this app's API on behalf of a signed-in user. This app is acting as a resource server in a delegated flow. Disabling it would break the calling app for all affected users. |
| `UsedAsAPIAppOnly` | `AppAuthResourceUtc` is non-null — another app has authenticated to this app's API using its own identity (client credentials / app-only). This is a service-to-service dependency with no user involved. Disabling it would silently break background jobs or automation pipelines that depend on this app. |
| `AppRoleAssignments` | One or more principals (users, groups, or other service principals) have been granted an app role defined by this SP (`appRoleAssignedTo`). These grants are structural — they exist in the directory regardless of whether any sign-in has occurred — and imply that other apps or access policies are built around this app's role definitions. |
| `OAuthClientGrants` | This SP has been granted delegated OAuth2 permissions to call other APIs on behalf of users (`oauth2PermissionGrants` where `clientId` = this SP). The grants themselves don't confirm active use, but removing the SP would revoke its ability to act on behalf of users and could break flows that rely on those consented scopes. |
| `OAuthResourceGrants` | Other SPs have been granted delegated OAuth2 permissions to call **this** app's API on behalf of users (`oauth2PermissionGrants` where `resourceId` = this SP). This app is the resource/API being consented to. Disabling it would break every client app that holds one of these grants. |

### Dependency Signal Detail

#### `UsedAsAPI` — Delegated API dependency (inbound, user-delegated)

**What it means:** The `DelegatedResourceUtc` timestamp in Graph's SP sign-in activity is non-null. Some other application has recently called this app's API on behalf of a signed-in user using a delegated token (OAuth2 authorization code or on-behalf-of flow).

**Where to check:**

- **Entra portal — Enterprise applications > [this app] > Sign-in logs**
  Filter by "Resource" to see which client apps have called this SP. The `AppId` of the caller appears in the `clientAppUsed` / `resourceDisplayName` columns.
- **Graph API:**
  ```
  GET /beta/reports/servicePrincipalSignInActivities/{id}
  ```
  `delegatedResourceSignInActivity.lastSignInDateTime` is the timestamp surfaced as `DelegatedResourceUtc`.
- **Entra portal — Enterprise applications > [this app] > Permissions > Users and groups**
  Confirms which users have consented and would be affected.

**Resolution steps:**

1. Identify the calling application from sign-in logs (filter `resourceId` = this SP's object ID).
2. Contact the owner of the calling app to confirm whether the integration is still active.
3. If the calling app is also inactive, both can potentially be decommissioned together.
4. If the integration is confirmed live: keep this app enabled. Document the dependency and re-evaluate when the calling app is decommissioned.
5. If activity is historic only (old `DelegatedResourceUtc`, no recent sign-ins), re-run after 30–60 days to confirm inactivity before disabling.

---

#### `UsedAsAPIAppOnly` — App-only API dependency (inbound, service-to-service)

**What it means:** The `AppAuthResourceUtc` timestamp is non-null. Another application has authenticated to this app's API using client credentials (app-only / no user). This is a machine-to-machine dependency — a daemon, background job, or automation pipeline is calling this app.

**Where to check:**

- **Entra portal — Enterprise applications > [this app] > Sign-in logs**
  Filter `Sign-in type = Application` and `Resource = [this app]`. The `Application` column shows the client SP that is calling in.
- **Graph API:**
  ```
  GET /beta/reports/servicePrincipalSignInActivities/{id}
  ```
  `applicationAuthenticationResourceSignInActivity.lastSignInDateTime` = `AppAuthResourceUtc`.
- **Entra portal — App registrations > [this app] > Expose an API**
  Lists the scopes/roles this app exposes. Knowing the role name helps trace which client apps hold that role.

**Resolution steps:**

1. From sign-in logs, note the `AppId` of every client that has called this resource.
2. For each client, check its own `AppAuthClientUtc` — if the client is also stale, the dependency chain may be fully abandoned.
3. Check with the platform/ops team that owns the background job or pipeline.
4. If the calling service is decommissioned or the job no longer runs, it is safe to remove the app role from the calling SP first, then disable this app.
5. If uncertain: disable the resource app in a non-production environment and monitor for failures before touching production.

---

#### `AppRoleAssignments` — Structural role grants (inbound, directory-level)

**What it means:** One or more users, groups, or other service principals have been granted an app role that is defined by this SP (`appRoleAssignedTo`). These grants exist in the directory independently of any sign-in event. They may control access to data, enforce least-privilege boundaries, or gate functionality in another application that reads this app's roles from the token.

**Where to check:**

- **Entra portal — Enterprise applications > [this app] > Users and groups**
  Lists every principal (user/group/SP) that holds a role assignment to this app, and which role they hold.
- **Graph API:**
  ```
  GET /v1.0/servicePrincipals/{id}/appRoleAssignedTo
  ```
  Returns `principalId`, `principalType`, `appRoleId`, and `createdDateTime` for each grant.
- **App registrations > [this app] > App roles**
  Lists the role definitions (display name, value, allowed member types) so you can understand what each role grants.

**Resolution steps:**

1. Export the full `appRoleAssignedTo` list and count how many active users/groups hold each role.
2. For SP-to-SP assignments, identify the client SP and check whether it is itself active.
3. Determine whether the role assignment is enforcing access control in another system (e.g. the calling app checks `roles` claims in the JWT). If so, revoking will silently deny access to those users.
4. Communicate with role holders (or their managers) before revoking. Remove role assignments before disabling the SP to make the change visible and auditable.
5. If all role holders are from decommissioned accounts or groups with no members, it is safe to remove grants and then disable the app.

---

#### `OAuthClientGrants` — Delegated permissions granted to this app (outbound)

**What it means:** This SP holds one or more `oauth2PermissionGrants` where it is the `clientId`. It has been granted delegated (user-context) permission to call other APIs — for example, `User.Read` on Microsoft Graph, or custom scopes on another internal API. The grants represent consented access, not confirmed recent use.

**Where to check:**

- **Entra portal — Enterprise applications > [this app] > Permissions > Delegated permissions**
  Lists every API and scope this app has been granted permission to call on behalf of users.
- **Graph API:**
  ```
  GET /v1.0/oauth2PermissionGrants?$filter=clientId eq '{servicePrincipalId}'
  ```
  Returns `resourceId`, `scope`, `consentType` (AllPrincipals vs Principal), and `principalId`.
- Cross-reference with `DelegatedClientUtc` (from the report) — if this is null or old, the app is not actually exercising these grants.

**Resolution steps:**

1. If `DelegatedClientUtc` is null or beyond the inactivity threshold, the app holds permissions it is not using — the grants are likely stale.
2. Review each grant's `consentType`: `AllPrincipals` (admin-consented, broad) vs `Principal` (user-consented, per-user).
3. If the app will be disabled and not decommissioned immediately, the grants will stop being exercised automatically. No immediate cleanup is required, but they should be revoked before permanent deletion.
4. To revoke a specific grant: **Entra portal — Enterprise applications > [this app] > Permissions > [grant] > Revoke**, or via Graph:
   ```
   DELETE /v1.0/oauth2PermissionGrants/{id}
   ```
5. This signal alone is not a strong blocker — treat it as a hygiene item rather than evidence of active use.

---

#### `OAuthResourceGrants` — Delegated permissions granted to other apps to call this app (inbound)

**What it means:** One or more other SPs hold `oauth2PermissionGrants` where this SP is the `resourceId`. Those client apps have been granted (and possibly consented to) delegated permission to call this app's API on behalf of users. Disabling this SP will break the consent grant and prevent those client apps from obtaining delegated tokens for this resource.

**Where to check:**

- **Entra portal — Enterprise applications > [this app] > Permissions > Other applications**
  Shows which apps have been granted permission to call this app, and under which scopes.
- **Graph API:**
  ```
  GET /v1.0/oauth2PermissionGrants?$filter=resourceId eq '{servicePrincipalId}'
  ```
  Returns `clientId` (the app that holds the grant), `scope`, and `consentType` for each grant.
- **App registrations > [this app] > Expose an API > Authorized client applications**
  Lists pre-authorized clients (these bypass the user consent prompt entirely).
- Cross-reference `DelegatedResourceUtc` — if that is non-null, this app is actively being called (overlaps with `UsedAsAPI`).

**Resolution steps:**

1. For each client SP in the grant list, check whether that client is itself active (look it up in the report).
2. If all client SPs are stale/disabled and `DelegatedResourceUtc` is null, the grants are effectively orphaned and disabling this app has no live impact.
3. If any client is active, identify the integration owner and confirm whether the client actually calls this API in production.
4. Before disabling: notify the owners of each client SP. Revoke the grants from the client side first (removes consent from the client app's perspective), then disable this resource SP.
5. To revoke: **Enterprise applications > [client app] > Permissions > Revoke consent for [this resource]**, or:
   ```
   DELETE /v1.0/oauth2PermissionGrants/{id}
   ```

---

## Notes

- All scripts are **read-only** — no changes are made to your tenant.
- Graph `servicePrincipalSignInActivities` requires an Entra ID P1 or P2 licence.
- LA retention is configurable in your workspace settings (default 90 days, up to 2 years).

## License

MIT
