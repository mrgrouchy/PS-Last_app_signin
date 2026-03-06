<#
.SYNOPSIS
  Audits Entra ID service principals for inactivity and structural dependencies.

.DESCRIPTION
  Combines Graph SP sign-in activity (180d) with optional Log Analytics user
  sign-ins (interactive + non-interactive) to produce the widest possible
  activity picture per app. Outputs a risk-classified report.

.PARAMETER UnusedDays
  Days of inactivity before an app is considered unused. Default: 180.

.PARAMETER WorkspaceId
  Log Analytics workspace ID. When supplied, also queries SigninLogs and
  AADNonInteractiveUserSignInLogs (isfuzzy=true — missing tables are skipped).
  Omit to run Graph-only.

.PARAMETER LookbackDays
  How far back to query Log Analytics. Should not exceed your workspace
  retention. Default: 90.

.PARAMETER IncludeNeverUsed
  Include service principals with no recorded sign-in activity at all.

.PARAMETER InputCsv
  Path to a CSV file containing service principal IDs or app IDs to query.
  Only those service principals will be included in the report.
  Recognised column names (first match wins):
    SP Object ID : ServicePrincipalId, id, ObjectId, SpObjectId, SpId, ServicePrincipalObjectId
    App ID       : AppId, ApplicationId, ClientId

.PARAMETER OutCsv
  Path to export a CSV report. If omitted, no file is written.

.EXAMPLE
  # Graph only — 180d SP activity, no LA required
  .\Get-AppUsageReport.ps1 -OutCsv .\report.csv

.EXAMPLE
  # Graph + Log Analytics — adds 90d interactive/non-interactive user sign-ins
  .\Get-AppUsageReport.ps1 -WorkspaceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutCsv .\report.csv

.EXAMPLE
  # Custom thresholds, include never-used apps
  .\Get-AppUsageReport.ps1 -WorkspaceId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -UnusedDays 90 -LookbackDays 90 -IncludeNeverUsed -OutCsv .\report.csv
#>
param(
  [int]$UnusedDays    = 180,
  [string]$WorkspaceId = "",
  [int]$LookbackDays  = 90,
  [switch]$IncludeNeverUsed,
  [string]$InputCsv   = "",
  [string]$OutCsv     = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Graph connection
# ------------------------------------------------------------

$scopes = @(
  "AuditLog.Read.All",
  "Directory.Read.All",
  "Application.Read.All",
  "AppRoleAssignment.ReadWrite.All",
  "DelegatedPermissionGrant.Read.All"
)

Connect-MgGraph -Scopes $scopes | Out-Null

# ------------------------------------------------------------
# Az connection (only when WorkspaceId supplied)
# ------------------------------------------------------------

$useLA = ($WorkspaceId -ne "")

if ($useLA) {
  Write-Host "Log Analytics configured — will query user sign-in data ($LookbackDays days)." -ForegroundColor Cyan
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
  return if ($p) { $p.Value } else { $null }
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
# Log Analytics: user sign-ins (interactive + non-interactive)
# ------------------------------------------------------------

$laByAppId = @{}

if ($useLA) {
  Write-Host "Querying Log Analytics for user sign-ins (last $LookbackDays days)..." -ForegroundColor Cyan

  $kql = @"
union isfuzzy=true
    (SigninLogs                      | where TimeGenerated > ago(${LookbackDays}d) | extend T = "i"),
    (AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(${LookbackDays}d) | extend T = "n")
| summarize
    LastInteractive    = maxif(TimeGenerated, T == "i"),
    LastNonInteractive = maxif(TimeGenerated, T == "n")
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
$servicePrincipals = Get-AllGraphPages "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType,accountEnabled&`$top=999"
Write-Host "  Service principals: $($servicePrincipals.Count)"

# ------------------------------------------------------------
# InputCsv filter — restrict to specific SPs if supplied
# ------------------------------------------------------------

if ($InputCsv) {
  Write-Host "Filtering to service principals from '$InputCsv'..." -ForegroundColor Cyan

  $csvRows = Import-Csv $InputCsv
  if ($csvRows.Count -eq 0) {
    Write-Warning "InputCsv '$InputCsv' is empty — no filter applied."
  } else {
    $colNames = $csvRows[0].PSObject.Properties.Name

    $spIdColCandidates  = @("ServicePrincipalId","id","ObjectId","SpObjectId","SpId","ServicePrincipalObjectId")
    $appIdColCandidates = @("AppId","ApplicationId","ClientId")

    $spIdCol  = $spIdColCandidates  | Where-Object { $colNames -contains $_ } | Select-Object -First 1
    $appIdCol = $appIdColCandidates | Where-Object { $colNames -contains $_ } | Select-Object -First 1

    if (-not $spIdCol -and -not $appIdCol) {
      Write-Warning ("InputCsv: no recognised ID column found.`n" +
        "  Expected one of: $($spIdColCandidates + $appIdColCandidates -join ', ')`n" +
        "  Columns in file : $($colNames -join ', ')`nNo filter applied.")
    } else {
      $filterIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

      if ($spIdCol) {
        $csvRows | ForEach-Object { if ($_.$spIdCol)  { [void]$filterIds.Add($_.$spIdCol)  } }
        $servicePrincipals = @($servicePrincipals | Where-Object { $filterIds.Contains((Get-Prop $_ "id")) })
        Write-Host "  Matched $($servicePrincipals.Count) SP(s) by column '$spIdCol'" -ForegroundColor Gray
      } else {
        $csvRows | ForEach-Object { if ($_.$appIdCol) { [void]$filterIds.Add($_.$appIdCol) } }
        $servicePrincipals = @($servicePrincipals | Where-Object { $filterIds.Contains((Get-Prop $_ "appId")) })
        Write-Host "  Matched $($servicePrincipals.Count) SP(s) by column '$appIdCol'" -ForegroundColor Gray
      }
    }
  }
}

# ------------------------------------------------------------
# Graph: all app registrations (bulk fetch — avoids per-SP calls)
# ------------------------------------------------------------

Write-Host "Fetching app registrations..." -ForegroundColor Cyan
$appRegs = Get-AllGraphPages "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,createdDateTime,passwordCredentials,keyCredentials&`$top=999"
Write-Host "  App registrations: $($appRegs.Count)"

$appRegByAppId = @{}
foreach ($app in $appRegs) {
  $id = Get-Prop $app "appId"
  if ($id) { $appRegByAppId[$id] = $app }
}

# ============================================================
# BUILD REPORT
# ============================================================

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$UnusedDays)
$now    = Get-Date

$i = 0
$report = foreach ($sp in $servicePrincipals) {

  $i++
  $spName = Get-Prop $sp "displayName"
  Write-Progress -Activity "Building report" -Status "$i / $($servicePrincipals.Count): $spName" -PercentComplete (($i / $servicePrincipals.Count) * 100)

  $spAppId   = Get-Prop $sp "appId"
  $spId      = Get-Prop $sp "id"
  $spType    = Get-Prop $sp "servicePrincipalType"
  $spEnabled = Get-Prop $sp "accountEnabled"

  # --- Graph SP activity ---
  $times = Get-GraphActivityTimes $activityByAppId[$spAppId]

  # --- Log Analytics user sign-ins ---
  $lastInteractive    = $null
  $lastNonInteractive = $null
  $la = $laByAppId[$spAppId]
  if ($la) {
    $li = Get-Prop $la "LastInteractive"
    $ln = Get-Prop $la "LastNonInteractive"
    $epoch = "0001-01-01"
    if ($li -and -not $li.StartsWith($epoch)) { $lastInteractive    = [datetime]$li }
    if ($ln -and -not $ln.StartsWith($epoch)) { $lastNonInteractive = [datetime]$ln }
  }

  # --- True last activity: max across ALL vectors ---
  $allDates = @(
    $times.DelegatedClientUtc,
    $times.DelegatedResourceUtc,
    $times.AppAuthClientUtc,
    $times.AppAuthResourceUtc,
    $lastInteractive,
    $lastNonInteractive
  ) | Where-Object { $null -ne $_ }

  $trueLastActivity = if ($allDates) { ($allDates | Sort-Object -Descending | Select-Object -First 1) } else { $null }
  $daysSince        = if ($trueLastActivity) { [int]($now - $trueLastActivity).TotalDays } else { $null }

  # --- App registration: created date + credentials ---
  $appReg         = $appRegByAppId[$spAppId]
  $appRegObjectId = $null
  $createdDaysAgo = $null
  $hasSecrets     = $false
  $hasCerts       = $false
  $secretExpiry   = $null
  $certExpiry     = $null
  $secretExpired  = $false
  $certExpired    = $false

  if ($appReg) {
    $appRegObjectId = Get-Prop $appReg "id"
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

  # --- Dependency checks ---
  $roleAssignments = Get-AppRoleAssignments $spId
  $oauthClient     = Get-OAuthGrantsClient $spId
  $oauthResource   = Get-OAuthGrantsResource $spId

  # --- Risk level (activity + credential liveness) ---
  $tooNew = $createdDaysAgo -ne $null -and $createdDaysAgo -lt 30

  $riskLevel = if ($tooNew) {
    "Ignore"
  } elseif ($trueLastActivity -and $trueLastActivity -ge $cutoff) {
    "Active"
  } elseif (-not $spEnabled) {
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

  # SafeToDisable: inactive (Low/Medium risk) AND no structural dependencies
  $safeToDisable = $riskLevel -in @("Low", "Medium") -and $depReasons.Count -eq 0

  [pscustomobject]@{
    DisplayName              = $spName
    AppId                    = $spAppId
    AppRegistrationObjectId  = $appRegObjectId
    ServicePrincipalId       = $spId
    ServicePrincipalType     = $spType
    AccountEnabled           = $spEnabled
    CreatedDaysAgo           = $createdDaysAgo

    TrueLastActivity         = $trueLastActivity
    DaysSinceActivity        = $daysSince
    LastInteractiveSignIn    = $lastInteractive
    LastNonInteractiveSignIn = $lastNonInteractive
    DelegatedClientUtc       = $times.DelegatedClientUtc
    DelegatedResourceUtc     = $times.DelegatedResourceUtc
    AppAuthClientUtc         = $times.AppAuthClientUtc
    AppAuthResourceUtc       = $times.AppAuthResourceUtc

    RoleAssignments          = $roleAssignments
    OAuthClientGrants        = $oauthClient
    OAuthResourceGrants      = $oauthResource

    HasSecrets               = $hasSecrets
    SecretExpiry             = $secretExpiry
    SecretsExpired           = $secretExpired
    HasCerts                 = $hasCerts
    CertExpiry               = $certExpiry
    CertsExpired             = $certExpired
    HasLiveCredentials       = $hasLiveCreds

    RiskLevel                = $riskLevel
    SafeToDisable            = $safeToDisable
    DependencySignals        = ($depReasons -join ";")
  }
}

Write-Progress -Activity "Building report" -Completed

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
Write-Host "Sign-in sources          : Graph servicePrincipalSignInActivities (180d)$(if ($useLA) { ", Log Analytics user sign-ins ($LookbackDays`d)" })"

$report | Group-Object RiskLevel | Sort-Object Name | ForEach-Object {
  $colour = switch ($_.Name) {
    "High"   { "Red" }
    "Medium" { "Yellow" }
    "Low"    { "Gray" }
    "Active" { "Green" }
    default  { "DarkGray" }
  }
  Write-Host ("  {0,-10} : {1}" -f $_.Name, $_.Count) -ForegroundColor $colour
}

Write-Host ""
$report | Format-Table DisplayName, TrueLastActivity, DaysSinceActivity, RiskLevel, SafeToDisable, DependencySignals -AutoSize

if ($OutCsv) {
  $report | Export-Csv $OutCsv -NoTypeInformation
  Write-Host "CSV exported to $OutCsv" -ForegroundColor Green
}
