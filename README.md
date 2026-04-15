# PS-Entra-App-Last-Use-Report

PowerShell scripts for reviewing Entra ID applications and service principals during cleanup work. The repo currently contains:

- `Get-AppUsageReport-Local.ps1`: the same report with resumable local checkpointing
- `Report-DisabledAppReg.ps1`: disabled app-registration tracker with optional Log Analytics enrichment and HTML reporting
- `Export-DisabledEntraApplicationsArchive.ps1`: JSON-first archive of disabled applications for later reference or partial recreation

## What These Scripts Do

The reporting scripts combine several signals to help identify inactive or review-worthy enterprise applications:

- Graph `servicePrincipalSignInActivities`
- optional Log Analytics sign-in data
- app registration presence and disabled state
- secret and certificate metadata
- app role assignments
- OAuth delegated grants
- synchronization jobs
- federated identity credentials

The output is designed for human review. It is not an automated remediation tool.

The archive script exports disabled applications and related service principals into per-app JSON files plus manifest files for lookup.

## Read-Only Scope

These scripts are intended to be read-only against Entra ID and Log Analytics:

- Microsoft Graph calls are `GET` requests
- Log Analytics usage is query-only
- the scripts write only local files such as CSV, JSON, and run-state checkpoints

They do not disable, delete, revoke, or modify tenant objects.

## Scripts

### `Get-AppUsageReport-Local.ps1`

This is the local/resumable variant of the same report. It is intended for operator-driven local execution.

Local-only behavior:

- writes a run-state JSON file while processing
- lets you control how often the checkpoint file is updated with `-CheckpointInterval`
- writes checkpoints through a temp-file replace flow with retries to reduce OneDrive/file-lock issues during long local runs
- if `-OutCsv` is omitted, writes `.\Get-AppUsageReport-<yyyy-MM-dd>.csv`
- on same-day reruns, prompts to reuse or delete the existing checkpoint (default behavior)
- automatically deletes prior-day checkpoints and starts a fresh iteration
- resumes when the same scope and key parameters are detected
- supports explicit checkpoint path control
- supports non-interactive same-day action selection (`Prompt`, `Reuse`, `Delete`)
- reduces local run overhead by throttling progress updates and avoiding repeated array-copy growth during report construction
- derives `ProvisioningLastRunUtc` from synchronization jobs and only treats provisioning as a dependency signal when exactly one job exists and the latest run is within 90 days
- forces `RiskLevel=Active` when that recent provisioning dependency rule is met

Typical usage:

```powershell
.\Get-AppUsageReport-Local.ps1
.\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv
.\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -RunStatePath .\report.runstate.json
.\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -NoResume
.\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -SameDayRunStateAction Reuse
```

Additional parameters:

| Parameter | Default | Notes |
|---|---|---|
| `-RunStatePath` | derived automatically | Checkpoint JSON path; when `-OutCsv` is set it defaults to the same folder and base name (for example `report.csv` -> `report.runstate.json`) |
| `-NoResume` | off | Ignore existing checkpoint |
| `-CheckpointInterval` | `25` | Save the run-state file every N processed service principals |
| `-SameDayRunStateAction` | `Prompt` | Same-day checkpoint behavior: `Prompt`, `Reuse`, or `Delete` |
| `-KeepRunState` | off | Deprecated compatibility switch (no longer required) |

### `Export-DisabledEntraApplicationsArchive.ps1`

Exports disabled applications into an archive that preserves nested Graph data more safely than CSV would.

Key behavior:

- archives apps where the app registration is disabled
- optionally includes apps with disabled related service principals
- exports one `archive.json` per application
- writes `manifest.json` and `manifest.csv` at the archive root
- reuses an existing Graph session when available
- falls back to interactive Graph sign-in if no existing session or app certificate settings are present
- stamps `Metadata.DeletedDateUtc` on previously archived apps that are no longer found in Graph on a later run

Typical usage:

```powershell
.\Export-DisabledEntraApplicationsArchive.ps1
.\Export-DisabledEntraApplicationsArchive.ps1 -OutDir .\archives\2026-03-22
.\Export-DisabledEntraApplicationsArchive.ps1 -IncludeServicePrincipalDisabled
```

Parameters:

| Parameter | Default | Notes |
|---|---|---|
| `-OutDir` | `.\disabled-app-archive` | Archive root |
| `-IncludeServicePrincipalDisabled` | off | Also include apps with disabled related service principals |

### `Report-DisabledAppReg.ps1`

Tracks disabled app registrations over time in a local JSON file and can optionally enrich the tracker with attempted sign-in data from Log Analytics.

Key behavior:

- fetches disabled applications from Microsoft Graph beta (`applications?$filter=isDisabled eq true`) with paging
- records `firstSeen` the first time a disabled app is observed
- refreshes `lastSeen` on later runs without overwriting `firstSeen`
- writes newly discovered disabled apps to the tracker before any optional Log Analytics lookup so first-run attempted sign-in checks start from the recorded `firstSeen`
- optionally queries Log Analytics for attempted interactive, non-interactive, and service principal sign-ins
- tracks `attemptedSignInHitCount` and recent `latestCorrelationIds` per app when Log Analytics is enabled
- can export the tracker to CSV
- always ensures a dated HTML report exists for the current day under `.\reports\<yyyyMMdd>\` (and `-HtmlReport` forces an additional timestamped report)

Typical usage:

```powershell
.\Report-DisabledAppReg.ps1
.\Report-DisabledAppReg.ps1 -OutCsv .\disabled-apps.csv
.\Report-DisabledAppReg.ps1 -HtmlReport
.\Report-DisabledAppReg.ps1 -UseLA
```

Parameters:

| Parameter | Default | Notes |
|---|---|---|
| `-JsonPath` | `.\disabled-apps-tracker.json` | Tracker JSON path |
| `-UseLA` | off | Enables Log Analytics enrichment |
| `-LookbackDays` | `90` | Fallback window only for apps without `firstSeen` |
| `-OutCsv` | empty | Optional CSV export |
| `-HtmlReport` | off | Force-write an HTML report under `.\reports\<yyyyMMdd>\` even if one already exists for today |

## Input CSV Support

Both reporting scripts support CSV scoping and detect common ID columns automatically.

Recognized service principal columns:

- `ServicePrincipalObjectId`
- `ServicePrincipalObjectID`
- `ServicePrincipalId`
- `SPObjectId`
- `SPId`
- `SP_Id`
- `ObjectId`
- `Id`

Recognized app ID columns:

- `AppId`
- `ApplicationId`

Behavior:

- service principal ID matching takes precedence
- if no service principals match, the scripts try resolving supplied IDs as app registration object IDs and then map back to `AppId`
- if no standard column exists, the first CSV column is treated as a service principal ID

## Report Output

The report scripts emit objects with fields including:

- `DisplayName`
- `AppId`
- `AppRegistrationObjectId`
- `ServicePrincipalId`
- `OwnershipClass`
- `SpSubClass`
- `AccountEnabled`
- `TrueLastActivity`
- `DaysSinceActivity`
- `RoleAssignments`
- `OAuthClientGrants`
- `OAuthResourceGrants`
- `ProvisioningJobCount`
- `ProvisioningLastRunUtc`
- `HasLiveCredentials`
- `FederatedCredentialCount`
- `RiskLevel`
- `CandidateForDisableReview`
- `RecommendedAction`
- `RecommendedActionReason`
- `DependencySignals`

Important classification behavior:

- `MicrosoftFirstParty` is treated as `Exempt`
- `ConsentedExternalApp` is kept separate from tenant-owned cleanup decisions
- `CandidateForDisableReview` is conservative and meant for review, not direct action

`RecommendedAction` is a staged next-step hint for reviewers. It is not an automated remediation instruction and should be read together with `RiskLevel` and `DependencySignals`.

`RecommendedActionReason` is a short human-readable explanation of why that action was chosen for the row.

Both reporting scripts now try to batch dependency checks per service principal through Microsoft Graph for better large-tenant performance. If a batch request fails, they fall back to the older individual-request path for the rest of the run.

For `Get-AppUsageReport-Local.ps1`, provisioning dependency now uses a recency rule:

- if exactly one provisioning job exists and its latest run is within 90 days, `DependencySignals` includes `ProvisioningJobs`
- in that same case, `RiskLevel` is forced to `Active`
- otherwise, provisioning does not count as an active dependency signal (unless the provisioning check itself is unavailable)

| `RecommendedAction` | Meaning in practice |
|---|---|
| `Exempt` | Microsoft first-party service principal. Exclude from ordinary cleanup review driven by this report. |
| `NoAction` | The app is still active or too new to treat as unused. Keep monitoring rather than making changes. |
| `RevokeGrants` | External app with actual OAuth or app-role grant signals. Review tenant consent and remove those grants before considering broader disable actions. |
| `DisableSPReview` | No grant or dependency signals were found that justify a grant-focused path. Use the normal enterprise application disable review flow instead. |
| `DisableSP` | Tenant-owned app with no dependency signals. Strong cleanup candidate for staged disable review, but still not a direct delete recommendation. |
| `ReviewDependencies` | Signals such as API usage, assignments, grants, provisioning jobs, or federated credentials exist. Review those dependencies before changing the app. |

## Archive Output

The archive script writes a structure like this:

```text
disabled-app-archive/
  manifest.csv
  manifest.json
  <DisplayName>__<AppId>/
    archive.json
```

Each `archive.json` contains:

- archive metadata
- application summary and full application object
- application owners
- federated identity credentials
- related service principals
- service principal owners
- app role assignments
- OAuth delegated grants
- synchronization jobs

If an app was archived previously but is no longer returned by Graph on a later run, the script stamps:

```json
"DeletedDateUtc": "..."
```

This is the detection time recorded by the archive process, not an authoritative Entra deletion timestamp.

## Authentication Notes

This repository is sanitized. Values such as tenant ID, client ID, certificate thumbprint, and workspace ID placeholders are intentionally non-production in source.

Current behavior:

- `Get-AppUsageReport-Local.ps1` first checks for a working existing Graph session, then tries app-certificate auth when configured, and otherwise falls back to interactive sign-in for testing
- `Report-DisabledAppReg.ps1` currently uses interactive `Connect-MgGraph -Scopes "Application.Read.All"` and its hardcoded `WorkspaceId` is intentionally redacted in the shared repo
- `Export-DisabledEntraApplicationsArchive.ps1` first checks `Get-MgContext`; if Graph is already connected it reuses that session, otherwise it falls back to interactive sign-in when no app certificate values are set

There is also an important current quirk in both reporting scripts:

```powershell
# Hardcoded Log Analytics workspace
$WorkspaceId = ""
```

That line overwrites any `-WorkspaceId` value passed on the command line unless you remove or change it in your private copy. Set it to your real workspace ID for Log Analytics mode, or blank it for Graph-only mode.

`Report-DisabledAppReg.ps1` behaves similarly for Log Analytics: its shared copy intentionally sets the hardcoded `WorkspaceId` to an empty redacted value, so `-UseLA` requires you to populate that privately first.

## Prerequisites

PowerShell:

- Windows PowerShell 5.1+ or PowerShell 7+

Modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Needed only when you use Log Analytics with the reporting scripts
Install-Module Az.OperationalInsights -Scope CurrentUser
```

Typical Graph read permissions needed across the scripts include:

- application read
- directory read
- app role assignment read
- delegated permission grant read
- synchronization read
- access to service principal sign-in activity

Exact consent requirements depend on how you authenticate in your private environment.

## Notes And Limitations

- Graph `servicePrincipalSignInActivities` is useful but not a full replacement for Log Analytics when you need a strict 90-day interactive sign-in view
- client secret values and certificate private keys cannot be recovered from Microsoft Graph; the archive preserves metadata only
- first-party Microsoft service principals should not be fed into disable or delete workflows just because they appear inactive

## License

MIT
