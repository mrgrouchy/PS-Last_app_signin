# PS-Entra-App-Last-Use-Report

PowerShell scripts for auditing Entra ID service principals and app registrations for inactivity, ownership, and dependency signals during application cleanup reviews.

## Scripts

### `Get-AppUsageReport.ps1`

Builds a tenant-wide or targeted report that combines sign-in activity, credential state, ownership classification, and structural dependency checks. The output is intended to identify candidates for manual disable review, not automatic deletion.

### `Tools/Match_Id_to_displayname.ps1`

Validates an input CSV by confirming that a `DisplayName` matches either an app registration `AppId` or a service principal `ServicePrincipalId`, and reports successful matches to the console.

### `Tools/Backup-JsonFiles.ps1`

Backs up top-level `.json` files in a directory into a `Json_Backup` folder before bulk changes.

## `Get-AppUsageReport.ps1`

### What It Does

- Fetches service principal sign-in activity from Graph `beta/reports/servicePrincipalSignInActivities`
- Optionally queries Log Analytics for interactive user, service principal, and managed identity sign-ins
- Loads all service principals and app registrations in bulk
- Supports input CSV scoping by service principal object ID, app ID, or app registration object ID fallback
- Checks app role assignments and OAuth delegated grants
- Checks synchronization jobs to catch provisioning-based enterprise apps
- Checks federated identity credentials on tenant-owned app registrations
- Separates tenant-owned and non-tenant-owned service principals
- Produces a conservative `CandidateForDisableReview` flag instead of a direct disable recommendation

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
| `RiskLevel` | `Active`, `High`, `Medium`, `Low`, `Ignore`, or `Review` |
| `CandidateForDisableReview` | Conservative review signal for tenant-owned, inactive apps with no detected dependency signals |
| `DependencySignals` | Semicolon-separated dependency or caution markers |

### Risk Classification

| RiskLevel | Meaning |
|---|---|
| `Active` | Activity exists within `-UnusedDays` |
| `High` | Inactive but still has live credentials |
| `Medium` | Inactive with no live secrets or certificates detected |
| `Low` | Disabled, or credentials are fully expired |
| `Ignore` | App registration is newer than 30 days |
| `Review` | Non-tenant-owned service principal; keep out of normal cleanup flow |

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

### Cleanup Interpretation

- `CandidateForDisableReview = True` means the object is a candidate for human review, not that it is automatically safe to disable or delete.
- `Review` objects should be handled separately from tenant-owned app cleanup.
- Apps with no observed sign-in data can still be live through provisioning, infrequent use, break-glass scenarios, federation, or other out-of-band dependencies.

## `Tools/Match_Id_to_displayname.ps1`

### Usage

```powershell
.\Tools\Match_Id_to_displayname.ps1 -CsvPath .\input.csv
```

Accepted CSV columns:

- `DisplayName` or `Displayname`
- App registration identifiers: `AppId`, `ApplicationId`, `ClientId`
- Service principal identifiers: `ServicePrincipalId`, `ServicePrincipalObjectId`, `ObjectId`, `Id`

Behavior:

- Each row must contain `DisplayName` and exactly one identifier type.
- App IDs are checked against app registrations.
- Service principal IDs are checked against service principals.
- Confirmed matches are printed to screen and summarized at the end.

## `Tools/Backup-JsonFiles.ps1`

### Usage

```powershell
.\Tools\Backup-JsonFiles.ps1
.\Tools\Backup-JsonFiles.ps1 -SourceDir "C:\path\to\jsons"
```

Behavior:

- Copies top-level `.json` files into `Json_Backup`
- Rotates an existing backup copy by timestamp before overwriting it
- Does not recurse into subfolders

## Notes

- These scripts are reporting and helper utilities. They do not directly remove or disable tenant objects.
- Graph `servicePrincipalSignInActivities` is still the main non-LA signal for service principal activity.

## License

MIT
