<#
.SYNOPSIS
  Pull Service Principal last sign-in activity (beta reports dataset), paginate past 1000,
  pull all service principals (v1.0), then join locally and compute a "LastUsed" timestamp
  as the max of all available activity timestamps.

.REQUIREMENTS
  - Microsoft.Graph PowerShell module
  - Graph permissions (delegated): AuditLog.Read.All + Directory.Read.All (or equivalent)
    Note: Your tenant may also require directory roles like Reports Reader / Security Reader.

.NOTES
  - /beta/reports/servicePrincipalSignInActivities returns max 1000 per page; use @odata.nextLink.
  - The reports dataset returns only service principals with activity; join fills null for never-used.
#>

param(
  [int]$UnusedDays = 180,
  [switch]$IncludeNeverUsed,
  [string]$OutCsv = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-AllGraphPages {
  param(
    [Parameter(Mandatory)] [string] $Uri
  )

  $all = New-Object System.Collections.Generic.List[object]

  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri

    if ($resp.value) { $resp.value | ForEach-Object { $all.Add($_) } }

    # StrictMode-safe: only read the property if it exists
    $nextProp = $resp.PSObject.Properties['@odata.nextLink']
    $Uri = if ($null -ne $nextProp) { [string]$nextProp.Value } else { $null }

  } while ($Uri)

  return $all
}

function Get-MaxLastUsed {
  param([object]$Activity)

  if (-not $Activity) { return $null }

  $paths = @(
    'lastSignInActivity.lastSignInDateTime'
    'delegatedClientSignInActivity.lastSignInDateTime'
    'delegatedResourceSignInActivity.lastSignInDateTime'
    'applicationAuthenticationClientSignInActivity.lastSignInDateTime'
    'applicationAuthenticationResourceSignInActivity.lastSignInDateTime'
  )

  function Get-ValueByPath {
    param([object]$Obj, [string]$Path)

    $cur = $Obj
    foreach ($seg in $Path.Split('.')) {
      if ($null -eq $cur) { return $null }

      if ($cur -is [System.Collections.IDictionary]) {
        if (-not $cur.Contains($seg)) { return $null }
        $cur = $cur[$seg]
      } else {
        $p = $cur.PSObject.Properties[$seg]
        if (-not $p) { return $null }
        $cur = $p.Value
      }
    }
    return $cur
  }

  $dates = foreach ($p in $paths) {
    $v = Get-ValueByPath -Obj $Activity -Path $p
    if ($v) {
      try { [datetime]$v } catch { $null }
    }
  }

  $dates = $dates | Where-Object { $_ -is [datetime] }
  if (-not $dates) { return $null }
  ($dates | Sort-Object -Descending | Select-Object -First 1)
}

# --- Connect (interactive delegated) ---
# If you're already connected, this is fine; it won't hurt.
$scopes = @("AuditLog.Read.All","Directory.Read.All")
Connect-MgGraph -Scopes $scopes | Out-Null

Write-Host "Pulling /beta/reports/servicePrincipalSignInActivities (paged)..." -ForegroundColor Cyan
$activityUri = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$top=1000"
$activity = Get-AllGraphPages -Uri $activityUri
Write-Host ("  Activity rows: {0}" -f $activity.Count) -ForegroundColor DarkCyan

# Build lookup by appId (GUID) - reliable
$activityByAppId = @{}
foreach ($a in $activity) {

  # Works for hashtables/dictionaries
  $appId = $null
  if ($a -is [System.Collections.IDictionary]) {
    $appId = $a['appId']
  } else {
    $appIdProp = $a.PSObject.Properties['appId']
    if ($appIdProp) { $appId = $appIdProp.Value }
  }

  if ($appId) {
    $activityByAppId[[string]$appId] = $a
  }
}

Write-Host "Pulling /v1.0/servicePrincipals (paged)..." -ForegroundColor Cyan
$spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled&`$top=999"
$servicePrincipals = Get-AllGraphPages -Uri $spUri
Write-Host ("  Service principals: {0}" -f $servicePrincipals.Count) -ForegroundColor DarkCyan

$cutoff = (Get-Date).ToUniversalTime().AddDays(-[double]$UnusedDays)

Write-Host "Joining and calculating LastUsed (max of all activity timestamps)..." -ForegroundColor Cyan
$report = foreach ($sp in $servicePrincipals) {
  $act = $null
if ($sp.appId) {
  $act = $activityByAppId[[string]$sp.appId]
}
  $lastUsed = Get-MaxLastUsed -Activity $act

  # If user didn't request never-used, optionally exclude later
  [pscustomobject]@{
    DisplayName         = $sp.displayName
    AppId               = $sp.appId
    ServicePrincipalId  = $sp.id
    ServicePrincipalType= $sp.servicePrincipalType
    AccountEnabled      = $sp.accountEnabled
    LastUsedUtc         = $lastUsed
    Status              = if (-not $lastUsed) { "NeverUsed" }
                          elseif ($lastUsed -lt $cutoff) { "Stale>$UnusedDays" }
                          else { "Active" }
  }
}

if (-not $IncludeNeverUsed) {
  $report = $report | Where-Object { $_.LastUsedUtc }
}

# Sort: never used at bottom unless included; then oldest first for cleanup views
$report = $report | Sort-Object -Property @{Expression="LastUsedUtc";Descending=$false}, DisplayName

$matched = @($report | Where-Object { $_.LastUsedUtc }).Count
$never   = @($report | Where-Object { -not $_.LastUsedUtc }).Count
Write-Host "Matched with activity: $matched | No activity matched: $never" -ForegroundColor Yellow

Write-Host ("Done. Rows: {0}" -f ($report | Measure-Object).Count) -ForegroundColor Green

# Output to screen
$report | Select-Object DisplayName, AppId, ServicePrincipalId, ServicePrincipalType, AccountEnabled, LastUsedUtc, Status

# Optional CSV
if ($OutCsv) {
  $report | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
  Write-Host "Wrote CSV: $OutCsv" -ForegroundColor Green
}
