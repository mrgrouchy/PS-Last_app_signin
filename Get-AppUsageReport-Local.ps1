<#
.SYNOPSIS
  Builds a local-only, resumable app-usage and dependency report for Entra ID service principals.

.DESCRIPTION
  Collects service principal activity and dependency signals, then outputs a
  risk-classified report for cleanup review workflows. Data sources include
  Graph servicePrincipalSignInActivities and, when configured, Log Analytics
  sign-in tables (SigninLogs, AADServicePrincipalSignInLogs,
  AADManagedIdentitySignInLogs).

  Designed for local execution. The script supports resumable processing by
  writing a run-state checkpoint file and reusing it on the next run when the
  processing scope and key parameters match. For authentication, the script
  first reuses an existing working Microsoft Graph session when present, then
  tries app-certificate auth when configured, and otherwise falls back to
  interactive Graph sign-in for local testing.

  Note: this repository is sanitized for sharing. Authentication and workspace
  values are redacted and should be supplied in your private environment.

.PARAMETER UnusedDays
  Days of inactivity before an app is considered unused. Default: 180.

.PARAMETER WorkspaceId
  Log Analytics workspace ID.
  When enabled in your local/private copy, queries SigninLogs,
  AADServicePrincipalSignInLogs, and AADManagedIdentitySignInLogs
  (isfuzzy=true, missing tables skipped). Omit for Graph-only operation.
  In this sanitized shared script, the in-code workspace value is intentionally
  reset unless you customize that section locally, so passing -WorkspaceId
  alone is not sufficient in the shared copy.

.PARAMETER LookbackDays
  How far back to query Log Analytics. Should not exceed your workspace
  retention. Default: 90.

.PARAMETER Top
  Limits the number of service principals processed after filtering.
  Default: 0 (no limit).

.PARAMETER IncludeNeverUsed
  Include service principals with no recorded sign-in activity at all.
  Default: enabled. Use -IncludeNeverUsed:$false to exclude never-used apps.

.PARAMETER OutCsv
  Path to export a CSV report.
  If omitted, defaults to ".\Get-AppUsageReport-<yyyy-MM-dd>.csv".

.PARAMETER InputCsv
  Optional path to an input CSV used to scope processing.
  Supports SP object ID and AppId columns (for example ServicePrincipalObjectId,
  ServicePrincipalId, SPId, ObjectId, Id, AppId, ApplicationId).
  If no standard column exists, the first column is treated as a service
  principal ID.
  If direct SP matching returns no results, the script also attempts fallback
  resolution from app registration object IDs to AppId.

.PARAMETER RunStatePath
  Optional path to a checkpoint JSON file used for resume-on-failure behavior.
  If omitted, defaults to:
  - "<OutCsvDirectory>\<OutCsvBaseName>.runstate.json" when OutCsv is set
  - "Get-AppUsageReport.runstate.json" in the current directory otherwise

.PARAMETER NoResume
  Disables loading an existing run-state file. Processing starts fresh, but the
  script still writes a new run-state checkpoint during the current run.

.PARAMETER KeepRunState
  Deprecated compatibility switch. Run-state is retained for same-day reruns
  and rotated automatically when a new local day starts.

.PARAMETER SameDayRunStateAction
  Behavior when a run-state file from the same local day is found:
  - Prompt (default): ask whether to reuse or delete it
  - Reuse: automatically reuse it when fingerprint matches
  - Delete: automatically remove it and start fresh
  Run-state files from previous days are automatically removed.

.EXAMPLE
  # Graph only — uses dated default CSV name in current directory
  .\Get-AppUsageReport-Local.ps1

.EXAMPLE
  # Graph + Log Analytics (after local private configuration / script customization)
  .\Get-AppUsageReport-Local.ps1 -WorkspaceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutCsv .\report.csv

.EXAMPLE
  # Custom thresholds, include never-used apps (after local private configuration / script customization)
  .\Get-AppUsageReport-Local.ps1 -WorkspaceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -UnusedDays 90 -LookbackDays 90 -IncludeNeverUsed -OutCsv .\report.csv

.EXAMPLE
  # Filter by specific SP IDs from input CSV
  .\Get-AppUsageReport-Local.ps1 -InputCsv .\input.csv -OutCsv .\report.csv

.EXAMPLE
  # Process only the first 200 filtered service principals
  .\Get-AppUsageReport-Local.ps1 -Top 200 -OutCsv .\report.csv

.EXAMPLE
  # Resume-capable run using explicit checkpoint file
  .\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -RunStatePath .\report.runstate.json

.EXAMPLE
  # Force fresh run and ignore any previous checkpoint
  .\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -NoResume

.EXAMPLE
  # Non-interactive same-day handling
  .\Get-AppUsageReport-Local.ps1 -OutCsv .\report.csv -SameDayRunStateAction Reuse
#>
param(
  [int]$UnusedDays    = 180,
  [string]$WorkspaceId = "",
  [int]$LookbackDays  = 90,
  [int]$Top           = 0,
  [switch]$IncludeNeverUsed = $true,
  [string]$OutCsv     = "",
  [string]$InputCsv   = "",
  [string]$RunStatePath = "",
  [switch]$NoResume,
  [switch]$KeepRunState,
  [ValidateSet('Prompt','Reuse','Delete')]
  [string]$SameDayRunStateAction = 'Prompt'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($KeepRunState) {
  Write-Warning "-KeepRunState is deprecated and no longer required; run-state is retained for same-day reruns automatically."
}

# Hardcoded Log Analytics workspace
$WorkspaceId = ""

# ------------------------------------------------------------
# Load input CSV filter (if provided)
# ------------------------------------------------------------

$filterSpObjectIds = @{}
$filterAppIds = @{}
$hasInputFilter = -not [string]::IsNullOrWhiteSpace($InputCsv)

if ($hasInputFilter) {
  if (!(Test-Path $InputCsv)) {
    Write-Error "Input CSV file not found: $InputCsv"
    exit 1
  }

  Write-Host "Loading input CSV filter from: $InputCsv" -ForegroundColor Cyan
  $inputData = Import-Csv $InputCsv

  if (@($inputData).Count -eq 0) {
    Write-Warning "Input CSV is empty."
  }

  # Prefer explicit SP object ID columns, but also accept AppId columns
  $spIdColumns = @(
    "ServicePrincipalObjectId",
    "ServicePrincipalObjectID",
    "ServicePrincipalId",
    "SPObjectId",
    "SPId",
    "SP_Id",
    "ObjectId",
    "Id"
  )
  $appIdColumns = @("AppId", "ApplicationId")

  $firstRow = @($inputData | Select-Object -First 1)
  $rowProps = if ($firstRow.Count -gt 0) { @($firstRow[0].PSObject.Properties.Name) } else { @() }

  $matchedSpColumns = @($spIdColumns | Where-Object { $rowProps -contains $_ })
  $matchedAppColumns = @($appIdColumns | Where-Object { $rowProps -contains $_ })

  if ($matchedSpColumns.Count -eq 0 -and $matchedAppColumns.Count -eq 0) {
    $fallbackColumn = $rowProps | Select-Object -First 1
    if ($fallbackColumn) {
      Write-Warning "No standard ID column found. Using first column as ServicePrincipalId: $fallbackColumn"
      $matchedSpColumns = @($fallbackColumn)
    }
  }

  if ($matchedSpColumns.Count -gt 0) {
    Write-Host "  SP ID columns: $($matchedSpColumns -join ', ')" -ForegroundColor Gray
  }
  if ($matchedAppColumns.Count -gt 0) {
    Write-Host "  App ID columns: $($matchedAppColumns -join ', ')" -ForegroundColor Gray
  }

  foreach ($row in $inputData) {
    foreach ($col in $matchedSpColumns) {
      $id = $row.$col
      if ($id -and $id.Trim()) {
        $filterSpObjectIds[$id.Trim()] = $true
      }
    }
    foreach ($col in $matchedAppColumns) {
      $id = $row.$col
      if ($id -and $id.Trim()) {
        $filterAppIds[$id.Trim()] = $true
      }
    }
  }

  Write-Host "  Loaded $($filterSpObjectIds.Count) SP object ID(s) and $($filterAppIds.Count) App ID(s) for filtering" -ForegroundColor Gray
}
else {
  Write-Host "No input CSV provided — processing full tenant service principals." -ForegroundColor Cyan
}

# ------------------------------------------------------------
# Graph connection
# ------------------------------------------------------------

$TenantId  = ""
$ClientId  = ""
$Thumbprint = ""   # cert must exist in CurrentUser\My or LocalMachine\My

function Test-GraphConnectivity {
  try {
    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=1&`$select=id" -Method GET -ErrorAction Stop | Out-Null
    return $true
  }
  catch {
    return $false
  }
}

$usingExistingGraph = $false
try {
  $ctx = Get-MgContext -ErrorAction Stop
  if ($ctx -and $ctx.Account -and (Test-GraphConnectivity)) {
    $usingExistingGraph = $true
    Write-Host "Using existing Microsoft Graph session: $($ctx.Account) ($($ctx.TenantId))" -ForegroundColor DarkGray
  }
}
catch {
  $usingExistingGraph = $false
}

if (-not $usingExistingGraph) {
  $hasAppAuthConfig = (-not [string]::IsNullOrWhiteSpace($TenantId)) -and
                      (-not [string]::IsNullOrWhiteSpace($ClientId)) -and
                      (-not [string]::IsNullOrWhiteSpace($Thumbprint))

  if ($hasAppAuthConfig) {
    Write-Host "No active Graph session found. Connecting with app certificate auth..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $Thumbprint -NoWelcome
  }
  else {
    Write-Host "No active Graph session found and app auth values are empty. Using interactive Graph sign-in for testing..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","AuditLog.Read.All" -NoWelcome
  }
}



# ------------------------------------------------------------
# Az connection (only when WorkspaceId supplied)
# ------------------------------------------------------------

$useLA = ($WorkspaceId -ne "")

if ($useLA) {
  Write-Host "Log Analytics configured — will query interactive user + workload sign-in data ($LookbackDays days)." -ForegroundColor Cyan
  Connect-AzAccount | Out-Null
}

# ------------------------------------------------------------
# Paging helper
# ------------------------------------------------------------

function Get-AllGraphPages {
  param([string]$Uri)

  $results = @()

  do {
    $resp = Invoke-MgGraphRequest -Uri $Uri -Method GET
    if ($null -ne $resp.value) { $results += $resp.value }

    if ($resp -is [System.Collections.IDictionary]) {
      $Uri = $resp['@odata.nextLink']
    } else {
      $next = $resp.PSObject.Properties['@odata.nextLink']
      $Uri = if ($next) { $next.Value } else { $null }
    }

  } while ($Uri)

  return $results
}

# ------------------------------------------------------------
# Safe property read from either Hashtable or PSObject
# ------------------------------------------------------------

function Get-Prop {
  param($obj, [string]$key)
  if ($null -eq $obj) { return $null }
  if ($obj -is [System.Collections.IDictionary]) { return $obj[$key] }
  $p = $obj.PSObject.Properties[$key]
  if ($p) { return $p.Value } else { return $null }
}

# ------------------------------------------------------------
# Dictionary-safe nested property navigation
# ------------------------------------------------------------

function Get-ValueByPath {
  param($obj, $path)

  $cur = $obj
  foreach ($p in $path.Split(".")) {
    if ($null -eq $cur) { return $null }
    if ($cur -is [System.Collections.IDictionary]) {
      if (!$cur.Contains($p)) { return $null }
      $cur = $cur[$p]
    } else {
      $prop = $cur.PSObject.Properties[$p]
      if (!$prop) { return $null }
      $cur = $prop.Value
    }
  }
  return $cur
}

# ------------------------------------------------------------
# Extract Graph SP activity timestamps
# ------------------------------------------------------------

function Get-GraphActivityTimes {
  param($activity)

  $dcli = Get-ValueByPath $activity "delegatedClientSignInActivity.lastSignInDateTime"
  $dres = Get-ValueByPath $activity "delegatedResourceSignInActivity.lastSignInDateTime"
  $acli = Get-ValueByPath $activity "applicationAuthenticationClientSignInActivity.lastSignInDateTime"
  $ares = Get-ValueByPath $activity "applicationAuthenticationResourceSignInActivity.lastSignInDateTime"

  [pscustomobject]@{
    DelegatedClientUtc   = if ($dcli) { [datetime]$dcli } else { $null }
    DelegatedResourceUtc = if ($dres) { [datetime]$dres } else { $null }
    AppAuthClientUtc     = if ($acli) { [datetime]$acli } else { $null }
    AppAuthResourceUtc   = if ($ares) { [datetime]$ares } else { $null }
  }
}

# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

function Get-AppRoleAssignments {
  param($spId)
  $items = @(Get-AllGraphPages "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo?`$top=999")
  return $items.Count
}

function Get-OAuthGrantsClient {
  param($spId)
  $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId'" -Method GET
  return @($resp.value).Count
}

function Get-OAuthGrantsResource {
  param($spId)
  $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=resourceId eq '$spId'" -Method GET
  return @($resp.value).Count
}

function Get-SynchronizationJobInfo {
  param($spId)

  try {
    $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/synchronization/jobs" -Method GET
    $jobs = @($resp.value)
    $activeStates = @('Active', 'InProgress', 'Running')
    $activeCount = @(
      $jobs | Where-Object {
        $state = Get-ValueByPath $_ 'status.code'
        $state -and ($activeStates -contains $state)
      }
    ).Count

    return [pscustomobject]@{
      JobCount    = $jobs.Count
      ActiveCount = $activeCount
      CheckStatus = 'Ok'
    }
  }
  catch {
    return [pscustomobject]@{
      JobCount    = $null
      ActiveCount = $null
      CheckStatus = 'Unavailable'
    }
  }
}

function Get-FederatedCredentialInfo {
  param($appRegObjectId)

  if ([string]::IsNullOrWhiteSpace($appRegObjectId)) {
    return [pscustomobject]@{
      Count       = 0
      CheckStatus = 'NotApplicable'
    }
  }

  try {
    $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/applications/$appRegObjectId/federatedIdentityCredentials" -Method GET
    return [pscustomobject]@{
      Count       = @($resp.value).Count
      CheckStatus = 'Ok'
    }
  }
  catch {
    return [pscustomobject]@{
      Count       = $null
      CheckStatus = 'Unavailable'
    }
  }
}

# ------------------------------------------------------------
# Resume helpers
# ------------------------------------------------------------

function Get-RunFingerprint {
  param(
    [array]$ServicePrincipals,
    [int]$UnusedDays,
    [int]$LookbackDays,
    [int]$Top,
    [bool]$IncludeNeverUsed,
    [bool]$UseLA
  )

  $ids = @(
    $ServicePrincipals |
      ForEach-Object { Get-Prop $_ "id" } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      Sort-Object
  )

  $signature = [pscustomobject]@{
    ServicePrincipalIds = $ids
    UnusedDays          = $UnusedDays
    LookbackDays        = $LookbackDays
    Top                 = $Top
    IncludeNeverUsed    = $IncludeNeverUsed
    UseLA               = $UseLA
  } | ConvertTo-Json -Depth 6 -Compress

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($signature)
    $hashBytes = $sha.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hashBytes) -replace "-", "").ToLowerInvariant()
  }
  finally {
    $sha.Dispose()
  }
}

function Save-RunCheckpoint {
  param(
    [string]$Path,
    [string]$Fingerprint,
    [int]$Total,
    [hashtable]$ProcessedMap,
    [array]$Rows
  )

  $state = [pscustomobject]@{
    Version                = 1
    SavedAtUtc             = (Get-Date).ToUniversalTime().ToString("o")
    SavedOnLocalDate       = (Get-Date).ToString("yyyy-MM-dd")
    Fingerprint            = $Fingerprint
    TotalServicePrincipals = $Total
    ProcessedServicePrincipalIds = @($ProcessedMap.Keys | Sort-Object)
    ReportRows             = @($Rows)
  }

  $json    = $state | ConvertTo-Json -Depth 12
  $tmpPath = "$Path.tmp"

  # Write to a temp file first so OneDrive never locks the live checkpoint during the write.
  Set-Content -Path $tmpPath -Value $json -Encoding UTF8

  # Rename over the real file with exponential-backoff retries (handles brief OneDrive sync locks).
  $maxRetries = 6
  $delayMs    = 500
  for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
    try {
      Move-Item -LiteralPath $tmpPath -Destination $Path -Force -ErrorAction Stop
      return
    }
    catch {
      if ($attempt -lt $maxRetries) {
        Write-Verbose "Checkpoint rename attempt $attempt failed – retrying in ${delayMs} ms..."
        Start-Sleep -Milliseconds $delayMs
        $delayMs *= 2
      } else {
        Write-Warning "Could not save checkpoint after $maxRetries attempts: $_"
        Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

# ============================================================
# DATA COLLECTION
# ============================================================

# ------------------------------------------------------------
# Graph: SP sign-in activity (up to 180d, Microsoft-managed)
# ------------------------------------------------------------

Write-Host "Fetching SP sign-in activity from Graph (up to 180d)..." -ForegroundColor Cyan
$graphActivity = Get-AllGraphPages "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$top=1000"
Write-Host "  Activity rows: $($graphActivity.Count)"

$activityByAppId = @{}
foreach ($a in $graphActivity) {
  $id = Get-Prop $a "appId"
  if ($id) { $activityByAppId[$id] = $a }
}

# ------------------------------------------------------------
# Log Analytics: interactive user + workload sign-ins
# ------------------------------------------------------------

$laByAppId = @{}

if ($useLA) {
  Write-Host "Querying Log Analytics for interactive user + workload sign-ins (last $LookbackDays days)..." -ForegroundColor Cyan

  $kql = @"
union isfuzzy=true
    (SigninLogs                      | where TimeGenerated > ago(${LookbackDays}d) | extend T = "i"),
    (AADServicePrincipalSignInLogs   | where TimeGenerated > ago(${LookbackDays}d) | extend T = "sp"),
    (AADManagedIdentitySignInLogs    | where TimeGenerated > ago(${LookbackDays}d) | extend T = "mi")
| summarize
    LastInteractive    = maxif(TimeGenerated, T == "i"),
    LastServicePrincipal = maxif(TimeGenerated, T == "sp"),
    LastManagedIdentity  = maxif(TimeGenerated, T == "mi")
  by AppId
"@

  try {
    $laResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan (New-TimeSpan -Days $LookbackDays)
    foreach ($row in $laResults.Results) {
      $laByAppId[$row.AppId] = $row
    }
    Write-Host "  LA returned activity for $($laByAppId.Count) apps" -ForegroundColor Gray
  }
  catch {
    Write-Warning "Log Analytics query failed: $_`nContinuing with Graph-only data."
    $useLA = $false
  }
}

# ------------------------------------------------------------
# Graph: all service principals
# ------------------------------------------------------------

Write-Host "Fetching service principals..." -ForegroundColor Cyan
$servicePrincipals = Get-AllGraphPages "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType,isDisabled,publisherName&`$top=999"
Write-Host "  Service principals: $($servicePrincipals.Count)"

$allServicePrincipals = @($servicePrincipals)

# Apply input CSV filter if provided
# IMPORTANT: if SP object IDs are provided, only match on SP object ID.
# AppId matching is a fallback only when SP object IDs are not available.
if ($hasInputFilter -and ($filterSpObjectIds.Count -gt 0 -or $filterAppIds.Count -gt 0)) {
  Write-Host "Applying input CSV filter..." -ForegroundColor Cyan
  $useSpIdOnly = $filterSpObjectIds.Count -gt 0
  if ($useSpIdOnly) {
    Write-Host "  Using SP Object ID matching (AppId fallback disabled because SP IDs are present)" -ForegroundColor Gray
  }

  $servicePrincipals = @($servicePrincipals | Where-Object {
    $spId = Get-Prop $_ "id"
    $appId = Get-Prop $_ "appId"

    # Match by SP object ID; only use AppId when no SP IDs were supplied in CSV
    $spMatch = $filterSpObjectIds.Count -gt 0 -and $filterSpObjectIds.ContainsKey($spId)
    $appMatch = (-not $useSpIdOnly) -and $filterAppIds.Count -gt 0 -and $filterAppIds.ContainsKey($appId)

    $spMatch -or $appMatch
  })
  Write-Host "  Filtered to $($servicePrincipals.Count) service principals" -ForegroundColor Gray
}

# Apply top limit if provided
if ($Top -gt 0) {
  $servicePrincipals = @($servicePrincipals | Select-Object -First $Top)
  Write-Host "  Applying -Top $Top => processing $($servicePrincipals.Count) service principal(s)" -ForegroundColor Gray
}

# ------------------------------------------------------------
# Graph: all app registrations (bulk fetch — avoids per-SP calls)
# ------------------------------------------------------------

Write-Host "Fetching app registrations..." -ForegroundColor Cyan
$appRegs = Get-AllGraphPages "https://graph.microsoft.com/beta/applications?`$select=id,appId,isDisabled,createdDateTime,passwordCredentials,keyCredentials&`$top=999"
Write-Host "  App registrations: $($appRegs.Count)"

$appRegByAppId = @{}
$appRegByObjectId = @{}
foreach ($app in $appRegs) {
  $objId = Get-Prop $app "id"
  $id = Get-Prop $app "appId"
  if ($id) { $appRegByAppId[$id] = $app }
  if ($objId) { $appRegByObjectId[$objId] = $app }
}

# Fallback input resolution:
# If no SPs matched, input IDs may actually be app registration object IDs.
if ($hasInputFilter -and $servicePrincipals.Count -eq 0 -and ($filterSpObjectIds.Count -gt 0 -or $filterAppIds.Count -gt 0)) {
  Write-Warning "No service principals matched initial filter. Attempting fallback by resolving input IDs as app registration object IDs..."

  $resolvedAppIds = @{}
  $candidateIds = @($filterSpObjectIds.Keys + $filterAppIds.Keys) | Select-Object -Unique

  foreach ($candidateId in $candidateIds) {
    if ($appRegByObjectId.ContainsKey($candidateId)) {
      $resolvedAppId = Get-Prop $appRegByObjectId[$candidateId] "appId"
      if ($resolvedAppId) {
        $resolvedAppIds[$resolvedAppId] = $true
      }
    }
  }

  if ($resolvedAppIds.Count -gt 0) {
    $servicePrincipals = @($allServicePrincipals | Where-Object {
      $spAppId = Get-Prop $_ "appId"
      $resolvedAppIds.ContainsKey($spAppId)
    })

    Write-Host "  Fallback resolved $($resolvedAppIds.Count) app registration object ID(s) to AppId(s)." -ForegroundColor Gray
    Write-Host "  Fallback filtered to $($servicePrincipals.Count) service principal(s)." -ForegroundColor Gray

    if ($Top -gt 0) {
      $servicePrincipals = @($servicePrincipals | Select-Object -First $Top)
      Write-Host "  Re-applying -Top $Top after fallback => processing $($servicePrincipals.Count) service principal(s)" -ForegroundColor Gray
    }
  }
  else {
    Write-Warning "Fallback could not resolve any input IDs to app registration object IDs."
  }
}

# ============================================================
# BUILD REPORT
# ============================================================

$now    = Get-Date
$nowUtc = $now.ToUniversalTime()

if ([string]::IsNullOrWhiteSpace($OutCsv)) {
  $defaultCsvName = "Get-AppUsageReport-{0}.csv" -f $now.ToString("yyyy-MM-dd")
  $OutCsv = Join-Path -Path $PWD -ChildPath $defaultCsvName
  Write-Host "No -OutCsv supplied. Using dated default output: $OutCsv" -ForegroundColor DarkGray
}

$defaultStateName = "Get-AppUsageReport.runstate.json"
if ([string]::IsNullOrWhiteSpace($RunStatePath)) {
  if ($OutCsv) {
    $outCsvFullPath = [System.IO.Path]::GetFullPath($OutCsv)
    $outCsvDir = [System.IO.Path]::GetDirectoryName($outCsvFullPath)
    $outCsvBaseName = [System.IO.Path]::GetFileNameWithoutExtension($outCsvFullPath)
    $RunStatePath = Join-Path -Path $outCsvDir -ChildPath ("{0}.runstate.json" -f $outCsvBaseName)
  } else {
    $RunStatePath = Join-Path -Path $PWD -ChildPath $defaultStateName
  }
}

$runFingerprint = Get-RunFingerprint -ServicePrincipals @($servicePrincipals) -UnusedDays $UnusedDays -LookbackDays $LookbackDays -Top $Top -IncludeNeverUsed ([bool]$IncludeNeverUsed) -UseLA ([bool]$useLA)
$processedIds = @{}
$reportRows = @()

if (-not $NoResume -and (Test-Path -LiteralPath $RunStatePath)) {
  try {
    # Open with FileShare.ReadWrite so we can read even while OneDrive holds the file open.
    $existingState = $null
    $readRetries   = 4
    $readDelayMs   = 750
    for ($rAttempt = 1; $rAttempt -le $readRetries; $rAttempt++) {
      try {
        $fs     = [System.IO.File]::Open($RunStatePath,
                      [System.IO.FileMode]::Open,
                      [System.IO.FileAccess]::Read,
                      [System.IO.FileShare]::ReadWrite)
        $reader = [System.IO.StreamReader]::new($fs, [System.Text.Encoding]::UTF8)
        $raw    = $reader.ReadToEnd()
        $reader.Dispose(); $fs.Dispose()
        $existingState = $raw | ConvertFrom-Json
        break
      }
      catch {
        if ($rAttempt -lt $readRetries) {
          Write-Verbose "Checkpoint read attempt $rAttempt failed – retrying in ${readDelayMs} ms..."
          Start-Sleep -Milliseconds $readDelayMs
          $readDelayMs *= 2
        } else {
          throw
        }
      }
    }
    $todayLocal = (Get-Date).ToString("yyyy-MM-dd")
    $stateLocalDate = $null

    if ($existingState -and $existingState.SavedOnLocalDate) {
      $stateLocalDate = [string]$existingState.SavedOnLocalDate
    } elseif ($existingState -and $existingState.SavedAtUtc) {
      try {
        $stateLocalDate = ([datetime]$existingState.SavedAtUtc).ToLocalTime().ToString("yyyy-MM-dd")
      }
      catch {
        $stateLocalDate = $null
      }
    }

    if ($stateLocalDate -and $stateLocalDate -ne $todayLocal) {
      Remove-Item -LiteralPath $RunStatePath -Force -ErrorAction SilentlyContinue
      Write-Host "Run-state is from $stateLocalDate (today: $todayLocal). Removed old checkpoint and starting fresh." -ForegroundColor Yellow
    }
    else {
      $reuseSameDay = $true
      if ($SameDayRunStateAction -eq 'Delete') {
        $reuseSameDay = $false
      }
      elseif ($SameDayRunStateAction -eq 'Prompt') {
        $answer = Read-Host "Same-day run-state found at '$RunStatePath'. Reuse it? (R)euse/(D)elete [R]"
        if ($answer -and $answer.Trim().ToUpperInvariant().StartsWith("D")) {
          $reuseSameDay = $false
        }
      }

      if ($reuseSameDay) {
        if ($existingState -and $existingState.Fingerprint -eq $runFingerprint) {
          foreach ($id in @($existingState.ProcessedServicePrincipalIds)) {
            if ($id) { $processedIds[[string]$id] = $true }
          }
          $reportRows = @($existingState.ReportRows)
          Write-Host "Resuming from run-state: $RunStatePath ($($processedIds.Count)/$($servicePrincipals.Count) already processed)" -ForegroundColor Yellow
        }
        else {
          Write-Warning "Existing run-state file does not match current scope/parameters. Starting a fresh run."
        }
      }
      else {
        Remove-Item -LiteralPath $RunStatePath -Force -ErrorAction SilentlyContinue
        Write-Host "Deleted same-day checkpoint. Starting a fresh run." -ForegroundColor Yellow
      }
    }
  }
  catch {
    Write-Warning "Could not load run-state file '$RunStatePath': $_`nStarting a fresh run."
  }
}
elseif (-not $NoResume) {
  Write-Host "Run-state enabled: $RunStatePath" -ForegroundColor DarkGray
}

$i = 0
$saveEvery = 1
foreach ($sp in $servicePrincipals) {

  $i++
  $spName = Get-Prop $sp "displayName"
  Write-Progress -Activity "Building report" -Status "$i / $($servicePrincipals.Count): $spName" -PercentComplete (($i / $servicePrincipals.Count) * 100)

  $spAppId        = Get-Prop $sp "appId"
  $spId           = Get-Prop $sp "id"
  if ($spId -and $processedIds.ContainsKey($spId)) {
    continue
  }
  $spType         = Get-Prop $sp "servicePrincipalType"
  $spIsDisabledRaw = Get-Prop $sp "isDisabled"
  $spIsDisabled    = $null
  if ($null -ne $spIsDisabledRaw) {
    if ($spIsDisabledRaw -is [bool]) {
      $spIsDisabled = $spIsDisabledRaw
    }
    else {
      try {
        $spIsDisabled = [System.Convert]::ToBoolean($spIsDisabledRaw)
      }
      catch {
        $spIsDisabled = $false
      }
    }
  }

  # Some first-party/external SPs may not surface this value consistently.
  # Treat missing isDisabled as active to avoid false disabled classification.
  if ($null -eq $spIsDisabled) {
    $spIsDisabled = $false
  }

  $servicePrincipalActivation = (-not $spIsDisabled)

  # --- Graph SP activity ---
  $times = Get-GraphActivityTimes $activityByAppId[$spAppId]

  # --- Log Analytics sign-ins ---
  $lastInteractive    = $null
  $lastServicePrincipal = $null
  $lastManagedIdentity  = $null
  $la = $laByAppId[$spAppId]
  if ($la) {
    $li = Get-Prop $la "LastInteractive"
    $lsp = Get-Prop $la "LastServicePrincipal"
    $lmi = Get-Prop $la "LastManagedIdentity"
    $epoch = "0001-01-01"
    if ($li -and -not $li.StartsWith($epoch)) { $lastInteractive    = [datetime]$li }
    if ($lsp -and -not $lsp.StartsWith($epoch)) { $lastServicePrincipal = [datetime]$lsp }
    if ($lmi -and -not $lmi.StartsWith($epoch)) { $lastManagedIdentity = [datetime]$lmi }
  }

  # --- True last activity: max across ALL vectors ---
  $allDates = @(
    $times.DelegatedClientUtc,
    $times.DelegatedResourceUtc,
    $times.AppAuthClientUtc,
    $times.AppAuthResourceUtc,
    $lastInteractive,
    $lastServicePrincipal,
    $lastManagedIdentity
  ) | Where-Object { $null -ne $_ }

  $trueLastActivity = if ($allDates) { ($allDates | Sort-Object -Descending | Select-Object -First 1) } else { $null }
  $daysSince        = if ($trueLastActivity) { [int]($nowUtc - $trueLastActivity.ToUniversalTime()).TotalDays } else { $null }

  # --- App registration: created date + credentials ---
  $appReg         = $appRegByAppId[$spAppId]
  $appRegObjectId = $null
  $appRegDisabled = $false
  $createdDaysAgo = $null
  $hasSecrets     = $false
  $hasCerts       = $false
  $secretExpiry   = $null
  $certExpiry     = $null
  $secretExpired  = $false
  $certExpired    = $false

  if ($appReg) {
    $appRegObjectId = Get-Prop $appReg "id"
    $appRegDisabledRaw = Get-Prop $appReg "isDisabled"
    if ($null -ne $appRegDisabledRaw) {
      if ($appRegDisabledRaw -is [bool]) {
        $appRegDisabled = $appRegDisabledRaw
      }
      else {
        try {
          $appRegDisabled = [System.Convert]::ToBoolean($appRegDisabledRaw)
        }
        catch {
          $appRegDisabled = $false
        }
      }
    }

    $createdDt      = Get-Prop $appReg "createdDateTime"
    $pwCreds        = @(Get-Prop $appReg "passwordCredentials")
    $keyCreds       = @(Get-Prop $appReg "keyCredentials")

    if ($createdDt) { $createdDaysAgo = [int]($now - [datetime]$createdDt).TotalDays }

    $hasSecrets = $pwCreds.Count -gt 0
    $hasCerts   = $keyCreds.Count -gt 0

    if ($hasSecrets) {
      $latest       = $pwCreds | Sort-Object { [datetime](Get-Prop $_ "endDateTime") } -Descending | Select-Object -First 1
      $secretExpiry = Get-Prop $latest "endDateTime"
      $secretExpired = $secretExpiry -and ([datetime]$secretExpiry -lt $now)
    }
    if ($hasCerts) {
      $latest     = $keyCreds | Sort-Object { [datetime](Get-Prop $_ "endDateTime") } -Descending | Select-Object -First 1
      $certExpiry = Get-Prop $latest "endDateTime"
      $certExpired = $certExpiry -and ([datetime]$certExpiry -lt $now)
    }
  }

  $hasLiveCreds = ($hasSecrets -and -not $secretExpired) -or ($hasCerts -and -not $certExpired)

  $ownershipClass = if ($appReg) { 'TenantOwned' } else { 'NonTenantOwned' }

  # Sub-classify NonTenantOwned SPs to distinguish Microsoft infrastructure from consented external apps
  $publisherName = Get-Prop $sp "publisherName"
  $msPublishers = @('Microsoft Services', 'Microsoft Corporation', 'Windows Azure', 'Microsoft Azure', 'Microsoft')
  $spSubClass = if ($ownershipClass -eq 'TenantOwned') {
    'TenantOwned'
  } elseif ($publisherName -and ($msPublishers | Where-Object { $publisherName -like "*$_*" })) {
    'MicrosoftFirstParty'
  } else {
    'ConsentedExternalApp'
  }

  # Effective enabled state:
  # - If local app registration exists, combine SP activation + appReg disabled state
  # - If no local app registration (e.g., first-party/external SP), use SP activation only
  if ($null -eq $appReg) {
    $effectiveAccountEnabled = $servicePrincipalActivation
  }
  else {
    $effectiveAccountEnabled = $servicePrincipalActivation -and (-not $appRegDisabled)
  }

  # --- Dependency checks ---
  $roleAssignments = Get-AppRoleAssignments $spId
  $oauthClient     = Get-OAuthGrantsClient $spId
  $oauthResource   = Get-OAuthGrantsResource $spId
  $syncInfo        = Get-SynchronizationJobInfo $spId
  $fedCredInfo     = Get-FederatedCredentialInfo $appRegObjectId

  # --- Risk level (activity + credential liveness) ---
  $tooNew = $null -ne $createdDaysAgo -and $createdDaysAgo -lt 30
  $isActiveByUsage = $null -ne $daysSince -and $daysSince -lt $UnusedDays

  $riskLevel = if ($isActiveByUsage) {
    "Active"
  } elseif ($spSubClass -eq 'MicrosoftFirstParty') {
    "Exempt"
  } elseif ($spSubClass -eq 'ConsentedExternalApp') {
    "Review"
  } elseif ($tooNew) {
    "Ignore"
  } elseif ($false -eq $effectiveAccountEnabled) {
    "Low"
  } elseif (($hasSecrets -and $secretExpired -and -not $hasCerts) -or
            ($hasSecrets -and $secretExpired -and $hasCerts -and $certExpired)) {
    "Low"
  } elseif ($hasLiveCreds) {
    "High"
  } else {
    "Medium"
  }

  # --- Dependency signals (independent of risk level) ---
  $depReasons = @()
  if ($times.DelegatedResourceUtc) { $depReasons += "UsedAsAPI" }
  if ($times.AppAuthResourceUtc)   { $depReasons += "UsedAsAPIAppOnly" }
  if ($roleAssignments -gt 0)      { $depReasons += "AppRoleAssignments" }
  if ($oauthClient -gt 0)          { $depReasons += "OAuthClientGrants" }
  if ($oauthResource -gt 0)        { $depReasons += "OAuthResourceGrants" }
  if ($syncInfo.JobCount -gt 0)    { $depReasons += "ProvisioningJobs" }
  if ($syncInfo.CheckStatus -eq 'Unavailable') { $depReasons += "ProvisioningCheckUnavailable" }
  if ($fedCredInfo.Count -gt 0)    { $depReasons += "FederatedCredentials" }
  if ($fedCredInfo.CheckStatus -eq 'Unavailable') { $depReasons += "FederatedCredentialCheckUnavailable" }
  if ($ownershipClass -eq 'NonTenantOwned') { $depReasons += "NonTenantOwned" }

  # CandidateForDisableReview is intentionally conservative. It is a review signal, not a delete recommendation.
  $candidateForDisableReview = (
    (
      $spSubClass -eq 'TenantOwned' -and
      $riskLevel -in @("Low", "Medium") -and
      $depReasons.Count -eq 0
    ) -or (
      $spSubClass -eq 'ConsentedExternalApp' -and
      $depReasons.Count -eq 0 -and
      $riskLevel -notin @("Active", "Exempt", "Ignore")
    )
  )

  # RecommendedAction is a review workflow hint, not an automated remediation command.
  # Read it together with RiskLevel and DependencySignals:
  # - Exempt: Microsoft first-party SP; do not target for cleanup from this report.
  # - NoAction: still active or too new; keep monitoring instead of changing anything.
  # - RevokeGrants: external app with actual OAuth/app-role grant signals; review/removing
  #   those grants is a better first step than disabling the enterprise app blindly.
  # - DisableSPReview: no dependency signals that require a grant-focused path; use normal
  #   enterprise app disable review, especially for external apps that have no real grants.
  # - DisableSP: tenant-owned app with no dependency signals; strongest cleanup candidate,
  #   but still intended for staged disable review rather than direct deletion.
  # - ReviewDependencies: one or more dependency signals exist; inspect what relies on the
  #   service principal before disabling it or revoking grants.
  $recommendedAction = if ($spSubClass -eq 'MicrosoftFirstParty') {
    'Exempt'
  } elseif ($riskLevel -in @("Active", "Ignore")) {
    'NoAction'
  } elseif ($spSubClass -eq 'ConsentedExternalApp') {
    $hasGrantSignals = ($oauthClient -gt 0) -or ($oauthResource -gt 0) -or ($roleAssignments -gt 0)
    $hasNonGrantDependencySignals = $depReasons | Where-Object {
      $_ -notin @('NonTenantOwned', 'OAuthClientGrants', 'OAuthResourceGrants', 'AppRoleAssignments')
    }

    if ($hasNonGrantDependencySignals) {
      'ReviewDependencies'
    } elseif ($hasGrantSignals) {
      'RevokeGrants'
    } else {
      'DisableSPReview'
    }
  } elseif ($spSubClass -eq 'TenantOwned') {
    if ($depReasons.Count -eq 0) {
      'DisableSP'
    } else {
      'ReviewDependencies'
    }
  } else {
    'Review'
  }

  $recommendedActionReason = switch ($recommendedAction) {
    'Exempt' { 'Microsoft first-party service principal.' }
    'NoAction' { 'Still active or too new for unused-app review.' }
    'RevokeGrants' { 'External app has OAuth or app-role grant signals.' }
    'DisableSPReview' { 'No grant or other dependency signals found for this external app.' }
    'DisableSP' { 'Tenant-owned app has no dependency signals.' }
    'ReviewDependencies' { 'Dependency signals were found and should be reviewed first.' }
    default { 'Manual review required.' }
  }

  $row = [pscustomobject]@{
    DisplayName              = $spName
    AppId                    = $spAppId
    AppRegistrationObjectId  = $appRegObjectId
    ServicePrincipalId       = $spId
    ServicePrincipalType     = $spType
    OwnershipClass           = $ownershipClass
    SpSubClass               = $spSubClass
    PublisherName            = $publisherName
    AccountEnabled           = $effectiveAccountEnabled
    ServicePrincipalActivation = $servicePrincipalActivation
    CreatedDaysAgo           = $createdDaysAgo

    TrueLastActivity         = $trueLastActivity
    DaysSinceActivity        = $daysSince
    LastInteractiveSignIn    = $lastInteractive
    LastServicePrincipalSignIn = $lastServicePrincipal
    LastManagedIdentitySignIn  = $lastManagedIdentity
    DelegatedClientUtc       = $times.DelegatedClientUtc
    DelegatedResourceUtc     = $times.DelegatedResourceUtc
    AppAuthClientUtc         = $times.AppAuthClientUtc
    AppAuthResourceUtc       = $times.AppAuthResourceUtc

    RoleAssignments          = $roleAssignments
    OAuthClientGrants        = $oauthClient
    OAuthResourceGrants      = $oauthResource
    ProvisioningJobCount     = $syncInfo.JobCount
    ActiveProvisioningJobs   = $syncInfo.ActiveCount
    ProvisioningCheckStatus  = $syncInfo.CheckStatus

    HasSecrets               = $hasSecrets
    SecretExpiry             = $secretExpiry
    SecretsExpired           = $secretExpired
    HasCerts                 = $hasCerts
    CertExpiry               = $certExpiry
    CertsExpired             = $certExpired
    HasLiveCredentials       = $hasLiveCreds
    FederatedCredentialCount = $fedCredInfo.Count
    FederatedCredentialCheckStatus = $fedCredInfo.CheckStatus

    RiskLevel                = $riskLevel
    CandidateForDisableReview = $candidateForDisableReview
    RecommendedAction        = $recommendedAction
    RecommendedActionReason  = $recommendedActionReason
    DependencySignals        = ($depReasons -join ";")
  }

  $reportRows += $row
  if ($spId) {
    $processedIds[$spId] = $true
  }

  if (($processedIds.Count % $saveEvery) -eq 0 -or $processedIds.Count -eq $servicePrincipals.Count) {
    Save-RunCheckpoint -Path $RunStatePath -Fingerprint $runFingerprint -Total $servicePrincipals.Count -ProcessedMap $processedIds -Rows $reportRows
  }
}

Write-Progress -Activity "Building report" -Completed

$report = @($reportRows)
if (Test-Path -LiteralPath $RunStatePath) {
  Write-Host "Run-state retained for same-day reruns: $RunStatePath" -ForegroundColor DarkGray
}

# ------------------------------------------------------------
# Filter + sort
# ------------------------------------------------------------

if (!$IncludeNeverUsed) {
  $report = $report | Where-Object { $_.TrueLastActivity }
}

$report = $report | Sort-Object TrueLastActivity

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
Write-Host "Total service principals : $($report.Count)"
Write-Host "Sign-in sources          : Graph servicePrincipalSignInActivities (180d)$(if ($useLA) { ", Log Analytics interactive user + workload sign-ins ($LookbackDays`d)" })"

$report | Group-Object RiskLevel | Sort-Object Name | ForEach-Object {
  $colour = switch ($_.Name) {
    "High"   { "Red" }
    "Medium" { "Yellow" }
    "Low"    { "Gray" }
    "Active" { "Green" }
    "Review" { "Magenta" }
    default  { "DarkGray" }
  }
  Write-Host ("  {0,-10} : {1}" -f $_.Name, $_.Count) -ForegroundColor $colour
}

Write-Host ""
  $report | Format-Table DisplayName, OwnershipClass, TrueLastActivity, DaysSinceActivity, RiskLevel, CandidateForDisableReview, DependencySignals -AutoSize

if ($OutCsv) {
  $report | Export-Csv $OutCsv -NoTypeInformation
  Write-Host "CSV exported to $OutCsv" -ForegroundColor Green
}
