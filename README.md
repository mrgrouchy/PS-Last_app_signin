# PS-Entra-App-Last-Use-Report

PowerShell scripts for auditing Entra ID service principals and app registrations for inactivity, ownership, and dependency signals during application cleanup reviews.

## Read-Only — No Automated Actions

This toolset is **tenant read-only**. It issues only `GET` requests against Microsoft Graph and read-only Log Analytics queries. It does not call any write, patch, delete, or revoke endpoints. No tenant object is modified, disabled, or deleted by running these scripts. Every action column in the output (`RecommendedAction`, `CandidateForDisableReview`) is a signal for human decision-making — it is never executed automatically.

## Scripts

### `Get-AppUsageReport.ps1`

Builds a tenant-wide or targeted report that combines sign-in activity, credential state, ownership classification, and structural dependency checks. The output is intended to identify candidates for manual disable review, not automatic deletion.

## `Get-AppUsageReport.ps1`

### What It Does

- Fetches service principal sign-in activity from Graph `beta/reports/servicePrincipalSignInActivities`
- Optionally queries Log Analytics for interactive user, service principal, and managed identity sign-ins
- Loads all service principals and app registrations in bulk
- Supports input CSV scoping by service principal object ID, app ID, or app registration object ID fallback
- Checks app role assignments and OAuth delegated grants
- Checks synchronization jobs to catch provisioning-based enterprise apps
- Checks federated identity credentials on tenant-owned app registrations
- Sub-classifies non-tenant-owned service principals into `MicrosoftFirstParty` and `ConsentedExternalApp`
- Exempts Microsoft infrastructure SPs from cleanup workflows automatically
- Produces a conservative `CandidateForDisableReview` flag and a staged `RecommendedAction` instead of a direct disable recommendation

### Prerequisites

- PowerShell 5.1+ or PowerShell 7+
- Modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Only needed if using -WorkspaceId
Install-Module Az.OperationalInsights -Scope CurrentUser
```

- Graph access sufficient to read:
  - service principals
  - applications
  - sign-in activity
  - app role assignments
  - OAuth permission grants
  - synchronization jobs
  - federated identity credentials

### Usage

```powershell
# Graph only
.\Get-AppUsageReport.ps1 -OutCsv .\report.csv

# Graph + Log Analytics
.\Get-AppUsageReport.ps1 -WorkspaceId "<guid>" -OutCsv .\report.csv

# Include objects with no observed activity
.\Get-AppUsageReport.ps1 -IncludeNeverUsed -OutCsv .\report.csv

# Restrict to a target list
.\Get-AppUsageReport.ps1 -InputCsv .\targets.csv -OutCsv .\report.csv
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-UnusedDays` | `180` | Days of inactivity before an app is treated as inactive |
| `-WorkspaceId` | empty | Optional Log Analytics workspace ID |
| `-LookbackDays` | `90` | Log Analytics query window |
| `-Top` | `0` | Limit the number of service principals processed after filtering |
| `-IncludeNeverUsed` | off | Keep rows with no recorded activity in the final report |
| `-OutCsv` | empty | Export path for the CSV report |
| `-InputCsv` | empty | Optional CSV used to scope the run |

### Input CSV Filtering

The script detects common input columns automatically.

| Match type | Column names |
|---|---|
| Service principal object ID | `ServicePrincipalObjectId`, `ServicePrincipalObjectID`, `ServicePrincipalId`, `SPObjectId`, `SPId`, `SP_Id`, `ObjectId`, `Id` |
| App ID | `AppId`, `ApplicationId` |

Behavior:

- If service principal IDs are present, they take precedence over app IDs.
- If no service principals match, the script attempts to resolve the supplied IDs as app registration object IDs and then maps those back to service principals by `AppId`.
- If no recognized column exists, the first CSV column is treated as a service principal ID with a warning.

### Sign-in Data Sources

| Source | Data |
|---|---|
| Graph `servicePrincipalSignInActivities` | Delegated and app-only service principal activity |
| Log Analytics `SigninLogs` | Interactive user sign-ins |
| Log Analytics `AADServicePrincipalSignInLogs` | Service principal sign-ins |
| Log Analytics `AADManagedIdentitySignInLogs` | Managed identity sign-ins |

`TrueLastActivity` is the most recent timestamp across all available activity vectors.

### Output Columns

| Column | Description |
|---|---|
| `DisplayName` | Service principal display name |
| `AppId` | Application client ID |
| `AppRegistrationObjectId` | Backing app registration object ID when present |
| `ServicePrincipalId` | Service principal object ID |
| `ServicePrincipalType` | Graph service principal type |
| `OwnershipClass` | `TenantOwned` when a local app registration exists, otherwise `NonTenantOwned` |
| `SpSubClass` | `TenantOwned`, `MicrosoftFirstParty`, or `ConsentedExternalApp` — see below |
| `PublisherName` | Publisher name from the service principal object |
| `AccountEnabled` | Combined effective enabled state |
| `ServicePrincipalActivation` | Service principal enabled state only |
| `CreatedDaysAgo` | Age of the backing app registration |
| `TrueLastActivity` | Latest observed activity |
| `DaysSinceActivity` | Days since latest observed activity |
| `LastInteractiveSignIn` | Last interactive user sign-in |
| `LastServicePrincipalSignIn` | Last service principal sign-in |
| `LastManagedIdentitySignIn` | Last managed identity sign-in |
| `DelegatedClientUtc` | Last delegated client activity |
| `DelegatedResourceUtc` | Last delegated resource/API activity |
| `AppAuthClientUtc` | Last app-only client activity |
| `AppAuthResourceUtc` | Last app-only resource/API activity |
| `RoleAssignments` | Count of app role assignments |
| `OAuthClientGrants` | Count of delegated grants where this SP is the client |
| `OAuthResourceGrants` | Count of delegated grants where this SP is the resource |
| `ProvisioningJobCount` | Count of synchronization jobs on the service principal |
| `ActiveProvisioningJobs` | Count of synchronization jobs in an active/running state |
| `ProvisioningCheckStatus` | `Ok` or `Unavailable` |
| `HasSecrets` | Whether password credentials exist |
| `SecretExpiry` | Latest secret expiry |
| `SecretsExpired` | Whether secrets are effectively expired |
| `HasCerts` | Whether key credentials exist |
| `CertExpiry` | Latest certificate expiry |
| `CertsExpired` | Whether certificates are effectively expired |
| `HasLiveCredentials` | Whether any non-expired secret or cert exists |
| `FederatedCredentialCount` | Count of federated identity credentials on the app registration |
| `FederatedCredentialCheckStatus` | `Ok`, `NotApplicable`, or `Unavailable` |
| `RiskLevel` | `Active`, `High`, `Medium`, `Low`, `Ignore`, `Review`, or `Exempt` — see below |
| `CandidateForDisableReview` | Conservative review signal for tenant-owned or consented-external inactive apps with no detected dependency signals |
| `RecommendedAction` | Staged action guidance — see below |
| `DependencySignals` | Semicolon-separated dependency or caution markers |

### SP Sub-Classification

`SpSubClass` refines `OwnershipClass` for non-tenant-owned service principals:

| SpSubClass | Meaning |
|---|---|
| `TenantOwned` | Has a local app registration in this tenant |
| `MicrosoftFirstParty` | No local app reg; publisher matches Microsoft Services, Microsoft Corporation, Windows Azure, or Microsoft Azure |
| `ConsentedExternalApp` | No local app reg; publisher is non-Microsoft or absent — a consented ISV or external app |

### Risk Classification

| RiskLevel | Meaning |
|---|---|
| `Active` | Activity exists within `-UnusedDays` |
| `High` | Inactive but still has live credentials |
| `Medium` | Inactive with no live secrets or certificates detected |
| `Low` | Disabled, or credentials are fully expired |
| `Ignore` | App registration is newer than 30 days |
| `Review` | `ConsentedExternalApp` — keep separate from tenant-owned cleanup flow |
| `Exempt` | `MicrosoftFirstParty` — Microsoft infrastructure; never process through a disable workflow |

### Recommended Action

| RecommendedAction | Meaning |
|---|---|
| `Exempt` | Microsoft infrastructure SP — do not take any action |
| `NoAction` | SP is active or too new — no action warranted |
| `RevokeGrants` | Consented external app with no dependencies — revoke OAuth grants and app role assignments as Stage 1 |
| `DisableSP` | Tenant-owned SP with no dependencies — disable via `accountEnabled = false` |
| `ReviewDependencies` | Dependencies detected — manual review required before any action |
| `Review` | Catch-all for unclassified cases |

For `RevokeGrants` (`ConsentedExternalApp` with no dependencies), the recommended staged sequence is:

1. **Revoke delegated grants** — remove all `oauth2PermissionGrants` where `clientId` equals the SP object ID
2. **Remove app role assignments** — remove all `appRoleAssignedTo` entries on the SP
3. **Disable the SP** — set `accountEnabled = false` on the service principal object
4. **Delete after observation window** — confirm no service impact, then delete the SP after a suitable hold period (recommended: 30–90 days)

For `DisableSP` (`TenantOwned` with no dependencies), skip steps 1–2 and begin at step 3, then proceed to step 4.

### Dependency Signals

| Signal | Meaning |
|---|---|
| `UsedAsAPI` | Delegated inbound API activity exists |
| `UsedAsAPIAppOnly` | App-only inbound API activity exists |
| `AppRoleAssignments` | Principals hold app roles on this service principal |
| `OAuthClientGrants` | This service principal has delegated grants to other APIs |
| `OAuthResourceGrants` | Other service principals have delegated grants to this API |
| `ProvisioningJobs` | Synchronization jobs exist on the service principal |
| `ProvisioningCheckUnavailable` | Sync job check could not be completed |
| `FederatedCredentials` | Federated identity credentials exist on the app registration |
| `FederatedCredentialCheckUnavailable` | Federated credential check could not be completed |
| `NonTenantOwned` | No local app registration was found for the service principal |

### Architectural Decision — Microsoft First-Party SPs

Microsoft First-Party SPs (`SpSubClass = MicrosoftFirstParty`) are service principals provisioned directly by Microsoft into every tenant to support platform infrastructure — identity extensions, Office 365 workloads, Azure RBAC backends, and similar services. They are identified by publisher name matching `Microsoft Services`, `Microsoft Corporation`, `Windows Azure`, `Microsoft Azure`, or `Microsoft`.

**Decision: First-party SPs must never be fed into any disable, revoke, or delete workflow, regardless of observed activity.**

Rationale:

- Zero sign-in activity in the reporting window is **expected and normal** for many first-party SPs. Absence of sign-in telemetry does not mean the SP is unused — many are invoked out-of-band by platform operations not surfaced in `servicePrincipalSignInActivities`.
- Microsoft re-provisions removed first-party SPs automatically. Disabling or deleting them can break tenant services before re-provisioning completes, creating an incident window with no net reduction in attack surface.
- These SPs are not owned by the tenant. The tenant cannot control their lifecycle beyond consent scope — the correct action for unwanted permissions is consent revocation, not SP disablement.

The script enforces this by assigning `RiskLevel = Exempt`, `RecommendedAction = Exempt`, and excluding all `MicrosoftFirstParty` SPs from `CandidateForDisableReview`. Filter on `SpSubClass != MicrosoftFirstParty` before passing output to any remediation pipeline.

### Cleanup Interpretation

- `CandidateForDisableReview = True` means the object is a candidate for human review, not that it is automatically safe to disable or delete.
- `Exempt` objects are Microsoft infrastructure. Do not feed them into any disable or delete workflow.
- `Review` objects (`ConsentedExternalApp`) should be handled separately from tenant-owned app cleanup using the `RevokeGrants` staged sequence.
- `RecommendedAction` is a starting point for human decision-making, not an automation trigger.
- Apps with no observed sign-in data can still be live through provisioning, infrequent use, break-glass scenarios, federation, or other out-of-band dependencies.

## Notes

- Graph `servicePrincipalSignInActivities` is still the main non-LA signal for service principal activity.

## License

MIT
