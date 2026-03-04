param(
  [int]$UnusedDays = 180,
  [switch]$IncludeNeverUsed,
  [string]$OutCsv = ""
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
# Dictionary-safe property navigation
# ------------------------------------------------------------

function Get-ValueByPath {
  param($obj, $path)

  $cur = $obj
  foreach ($p in $path.Split(".")) {

    if ($null -eq $cur) { return $null }

    if ($cur -is [System.Collections.IDictionary]) {
      if (!$cur.Contains($p)) { return $null }
      $cur = $cur[$p]
    }
    else {
      $prop = $cur.PSObject.Properties[$p]
      if (!$prop) { return $null }
      $cur = $prop.Value
    }
  }

  return $cur
}

# ------------------------------------------------------------
# Extract all activity timestamps
# ------------------------------------------------------------

function Get-ActivityTimes {

  param($activity)

  if (!$activity) {
    return [pscustomobject]@{
      LastUsedUtc = $null
      DelegatedClientUtc = $null
      DelegatedResourceUtc = $null
      AppAuthClientUtc = $null
      AppAuthResourceUtc = $null
    }
  }

  $roll = Get-ValueByPath $activity "lastSignInActivity.lastSignInDateTime"
  $dcli = Get-ValueByPath $activity "delegatedClientSignInActivity.lastSignInDateTime"
  $dres = Get-ValueByPath $activity "delegatedResourceSignInActivity.lastSignInDateTime"
  $acli = Get-ValueByPath $activity "applicationAuthenticationClientSignInActivity.lastSignInDateTime"
  $ares = Get-ValueByPath $activity "applicationAuthenticationResourceSignInActivity.lastSignInDateTime"

  $dates = @()

  foreach ($d in @($roll,$dcli,$dres,$acli,$ares)) {
    if ($d) { $dates += [datetime]$d }
  }

  $last = if ($dates) { ($dates | Sort-Object -Descending | Select-Object -First 1) } else { $null }

  [pscustomobject]@{
    LastUsedUtc = $last
    DelegatedClientUtc = $dcli
    DelegatedResourceUtc = $dres
    AppAuthClientUtc = $acli
    AppAuthResourceUtc = $ares
  }

}

# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

function Get-AppRoleAssignments {

  param($spId)

  $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo?`$top=999"

  $items = @(Get-AllGraphPages $uri)

  return $items.Count
}

function Get-OAuthGrantsClient {

  param($spId)

  $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId'"

  $resp = Invoke-MgGraphRequest -Uri $uri -Method GET

  return @($resp.value).Count
}

function Get-OAuthGrantsResource {

  param($spId)

  $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=resourceId eq '$spId'"

  $resp = Invoke-MgGraphRequest -Uri $uri -Method GET

  return @($resp.value).Count
}

function Get-AppInfo {

  param($appId)

  $uri = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$appId'&`$select=id,passwordCredentials,keyCredentials"

  $resp = Invoke-MgGraphRequest -Uri $uri -Method GET

  $app = $resp.value | Select-Object -First 1

  if (!$app) {
    return [pscustomobject]@{ ObjectId = $null; HasCredentials = $false }
  }

  $hasCreds = ($app.passwordCredentials.Count -gt 0) -or ($app.keyCredentials.Count -gt 0)

  return [pscustomobject]@{
    ObjectId       = $app.id
    HasCredentials = $hasCreds
  }
}

# ------------------------------------------------------------
# Pull activity dataset
# ------------------------------------------------------------

Write-Host "Fetching activity dataset..." -ForegroundColor Cyan

$activity = Get-AllGraphPages "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?`$top=1000"

Write-Host "Activity rows: $($activity.Count)"

# Build lookup by appId

$activityByAppId = @{}

foreach ($a in $activity) {

  if ($a -is [System.Collections.IDictionary]) {
    $appId = $a["appId"]
  }
  else {
    $appId = $a.appId
  }

  if ($appId) {
    $activityByAppId[$appId] = $a
  }

}

# ------------------------------------------------------------
# Pull service principals
# ------------------------------------------------------------

Write-Host "Fetching service principals..." -ForegroundColor Cyan

$servicePrincipals = Get-AllGraphPages "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType,accountEnabled&`$top=999"

Write-Host "Service Principals: $($servicePrincipals.Count)"

# ------------------------------------------------------------
# Build report
# ------------------------------------------------------------

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$UnusedDays)

$report = foreach ($sp in $servicePrincipals) {

  $act = $activityByAppId[$sp.appId]

  $times = Get-ActivityTimes $act

  $roleAssignments = Get-AppRoleAssignments $sp.id
  $oauthClient = Get-OAuthGrantsClient $sp.id
  $oauthResource = Get-OAuthGrantsResource $sp.id
  $appInfo = Get-AppInfo $sp.appId
  $hasCreds = $appInfo.HasCredentials

  $reasons = @()

  if ($times.LastUsedUtc -ge $cutoff) { $reasons += "RecentActivity" }

  if ($times.DelegatedResourceUtc) { $reasons += "UsedAsAPI" }

  if ($times.AppAuthResourceUtc) { $reasons += "UsedAsAPIAppOnly" }

  if ($roleAssignments -gt 0) { $reasons += "AppRoleAssignments" }

  if ($oauthClient -gt 0) { $reasons += "OAuthClientGrants" }

  if ($oauthResource -gt 0) { $reasons += "OAuthResourceGrants" }

  if ($hasCreds) { $reasons += "CredentialsPresent" }

  $safe = $false

  if (!$reasons -and (!$times.LastUsedUtc -or $times.LastUsedUtc -lt $cutoff)) {
    $safe = $true
  }

  [pscustomobject]@{

    DisplayName = $sp.displayName
    AppId = $sp.appId
    AppRegistrationObjectId = $appInfo.ObjectId
    ServicePrincipalId = $sp.id
    ServicePrincipalType = $sp.servicePrincipalType
    AccountEnabled = $sp.accountEnabled

    LastUsedUtc = $times.LastUsedUtc
    DelegatedClientUtc = $times.DelegatedClientUtc
    DelegatedResourceUtc = $times.DelegatedResourceUtc
    AppAuthClientUtc = $times.AppAuthClientUtc
    AppAuthResourceUtc = $times.AppAuthResourceUtc

    RoleAssignments = $roleAssignments
    OAuthClientGrants = $oauthClient
    OAuthResourceGrants = $oauthResource
    HasCredentials = $hasCreds

    SafeToDisable = $safe
    WhyNotSafe = ($reasons -join ";")
  }

}

if (!$IncludeNeverUsed) {
  $report = $report | Where-Object { $_.LastUsedUtc }
}

$report = $report | Sort-Object LastUsedUtc

Write-Host "Report rows: $($report.Count)" -ForegroundColor Green

$report | Format-Table DisplayName,LastUsedUtc,SafeToDisable,WhyNotSafe -AutoSize

if ($OutCsv) {

  $report | Export-Csv $OutCsv -NoTypeInformation

  Write-Host "CSV exported to $OutCsv"

}
