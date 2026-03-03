#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Az.OperationalInsights

Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All"
Connect-AzAccount  # or use existing session

#region --- CONFIG ---
$WorkspaceId = "<your-log-analytics-workspace-id>"
$ExportPath  = "UnusedApps_$(Get-Date -Format 'yyyyMMdd').csv"
#endregion

if (-not $WorkspaceId -or $WorkspaceId -eq "<your-log-analytics-workspace-id>") {
    throw "Set a valid Log Analytics WorkspaceId before running."
}

#region --- LOG ANALYTICS: Sign-in activity (all types, 180 days) ---
Write-Host "Querying Log Analytics for sign-in activity..." -ForegroundColor Cyan

$kqlQuery = @"
union isfuzzy=true
    (SigninLogs                    | where TimeGenerated > ago(180d) | extend SignInType = "Interactive"),
    (AADServicePrincipalSignInLogs | where TimeGenerated > ago(180d) | extend SignInType = "ServicePrincipal")
| summarize
    LastInteractive      = maxif(TimeGenerated, SignInType == "Interactive"),
    LastServicePrincipal = maxif(TimeGenerated, SignInType == "ServicePrincipal"),
    TotalSignIns         = count(),
    LastActivity         = max(TimeGenerated)
  by AppId, AppDisplayName
| extend DaysSinceActivity = datetime_diff('day', now(), LastActivity)
"@

$laResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $kqlQuery -Timespan (New-TimeSpan -Days 180)
$laRows    = $laResults.Results

# Build lookup by AppId
$laLookup = @{}
$laRows | ForEach-Object { $laLookup[$_.AppId] = $_ }

Write-Host "  LA returned activity for $($laRows.Count) apps" -ForegroundColor Gray

#endregion

#region --- GRAPH FALLBACK: Non-interactive sign-ins (30 days) ---
Write-Host "Fetching non-interactive sign-ins from Graph audit logs (last 30d)..." -ForegroundColor Cyan
$cutoff = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $cutoff and signInEventTypes/any(t:t eq 'nonInteractiveUser')&`$select=appId,createdDateTime&`$top=1000"

$niLookup = @{}
while ($uri) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($row in $resp.value) {
        if (-not $row.appId) { continue }
        $dt = [datetime]$row.createdDateTime
        if (-not $niLookup.ContainsKey($row.appId) -or $dt -gt $niLookup[$row.appId]) {
            $niLookup[$row.appId] = $dt
        }
    }
    $uri = $resp.'@odata.nextLink'
}
Write-Host "  Graph returned non-interactive activity for $($niLookup.Count) apps" -ForegroundColor Gray
#endregion

#region --- GRAPH: App registrations + Service principals ---
Write-Host "Fetching app registrations from Graph..." -ForegroundColor Cyan
$allApps = Get-MgApplication -All -Property "id,appId,displayName,createdDateTime,signInAudience,requiredResourceAccess,passwordCredentials,keyCredentials,notes,owners"

Write-Host "Fetching service principals from Graph..." -ForegroundColor Cyan
$allSPs = Get-MgServicePrincipal -All -Property "id,appId,displayName,signInActivity,servicePrincipalType,tags,accountEnabled"

$spLookup = @{}
$allSPs | ForEach-Object { $spLookup[$_.AppId] = $_ }

#endregion

#region --- BUILD REPORT ---
Write-Host "Building report for $($allApps.Count) app registrations..." -ForegroundColor Cyan
$now = Get-Date

$report = foreach ($app in $allApps) {

    $sp  = $spLookup[$app.AppId]
    $la  = $laLookup[$app.AppId]

    # --- Sign-in dates from LA ---
    $lastInteractive      = if ($la.LastInteractive      -and $la.LastInteractive      -ne "0001-01-01T00:00:00") { [datetime]$la.LastInteractive }      else { $null }
    $lastNonInteractive   = if ($niLookup.ContainsKey($app.AppId)) { $niLookup[$app.AppId] } else { $null }
    $lastServicePrincipal = if ($la.LastServicePrincipal -and $la.LastServicePrincipal -ne "0001-01-01T00:00:00") { [datetime]$la.LastServicePrincipal } else { $null }
    $lastOverall          = if ($la.LastActivity         -and $la.LastActivity         -ne "0001-01-01T00:00:00") { [datetime]$la.LastActivity }         else { $null }

    # SP signInActivity as a final safety net (Graph-side, ~180d)
    $spFallback = if ($sp.SignInActivity.LastSignInDateTime) { [datetime]$sp.SignInActivity.LastSignInDateTime } else { $null }

    # True last activity across all vectors
    $allDates = @($lastInteractive, $lastNonInteractive, $lastServicePrincipal, $lastOverall, $spFallback) |
                Where-Object { $_ } | Sort-Object -Descending
    $trueLastActivity = $allDates | Select-Object -First 1

    # --- App age ---
    $appAgeDays        = if ($app.CreatedDateTime) { ($now - [datetime]$app.CreatedDateTime).Days } else { $null }
    $daysSinceActivity = if ($trueLastActivity)    { ($now - $trueLastActivity).Days }              else { $null }

    # --- Credential analysis ---
    $hasSecrets    = $app.PasswordCredentials.Count -gt 0
    $hasCerts      = $app.KeyCredentials.Count -gt 0
    $secretExpiry  = ($app.PasswordCredentials | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
    $certExpiry    = ($app.KeyCredentials      | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
    $secretExpired = $hasSecrets -and $secretExpiry -and ([datetime]$secretExpiry -lt $now)
    $certExpired   = $hasCerts   -and $certExpiry   -and ([datetime]$certExpiry   -lt $now)
    $hasLiveCreds  = ($hasSecrets -and -not $secretExpired) -or ($hasCerts -and -not $certExpired)

    # --- Classification ---
    $tooNew = $appAgeDays -ne $null -and $appAgeDays -lt 30

    $unusedReason = switch ($true) {
        $tooNew                                          { "Too New (<30d)" }
        (-not $sp)                                       { "No Service Principal" }
        (-not $sp.AccountEnabled)                        { "SP Disabled" }
        ($hasSecrets -and $secretExpired -and
         $hasCerts   -and $certExpired)                  { "All Creds Expired" }
        ($hasSecrets -and $secretExpired -and -not $hasCerts) { "All Creds Expired" }
        (-not $hasSecrets -and $hasCerts -and $certExpired)    { "All Creds Expired" }
        (-not $trueLastActivity -and $appAgeDays -ge 30) { "Never Used" }
        ($daysSinceActivity -gt 180)                     { "Inactive >180d" }
        default                                          { $null }
    }

    $riskLevel = switch ($unusedReason) {
        "Never Used"           { if ($hasLiveCreds) { "High" }   else { "Medium" } }
        "Inactive >180d"       { if ($hasLiveCreds) { "High" }   else { "Medium" } }
        "No Service Principal" { "Low" }
        "All Creds Expired"    { "Low" }
        "SP Disabled"          { "Low" }
        "Too New (<30d)"       { "Ignore" }
        default                { "Active" }
    }

    [PSCustomObject]@{
        DisplayName               = $app.DisplayName
        AppId                     = $app.AppId
        ObjectId                  = $app.Id
        SignInAudience            = $app.SignInAudience
        CreatedDaysAgo            = $appAgeDays
        HasServicePrincipal       = ($null -ne $sp)
        SPEnabled                 = $sp.AccountEnabled
        SPType                    = $sp.ServicePrincipalType
        # Sign-in breakdown
        LastInteractiveSignIn     = $lastInteractive
        LastNonInteractiveSignIn  = $lastNonInteractive
        LastSPSignIn              = $lastServicePrincipal
        LastActivityOverall       = $trueLastActivity
        DaysSinceActivity         = $daysSinceActivity
        TotalSignIns180d          = $la.TotalSignIns
        # Credentials
        HasSecrets                = $hasSecrets
        SecretExpiry              = $secretExpiry
        SecretsExpired            = $secretExpired
        HasCerts                  = $hasCerts
        CertExpiry                = $certExpiry
        CertsExpired              = $certExpired
        HasLiveCredentials        = $hasLiveCreds
        # Risk
        PermissionCount           = $app.RequiredResourceAccess.Count
        UnusedReason              = $unusedReason
        RiskLevel                 = $riskLevel
        Notes                     = $app.Notes
    }
}

#endregion

#region --- OUTPUT ---
$summary = $report | Group-Object RiskLevel | Sort-Object Name
Write-Host "`n=== Summary ===" -ForegroundColor Yellow
Write-Host "Total app registrations : $($report.Count)"
$summary | ForEach-Object {
    $colour = switch ($_.Name) {
        "High"   { "Red" }    "Medium" { "Yellow" }
        "Low"    { "Gray" }   "Active" { "Green" }
        default  { "DarkGray" }
    }
    Write-Host ("  {0,-10} : {1}" -f $_.Name, $_.Count) -ForegroundColor $colour
}

$report | Export-Csv $ExportPath -NoTypeInformation
Write-Host "`nFull report: $ExportPath" -ForegroundColor Green

# High risk to console
$highRisk = $report | Where-Object { $_.RiskLevel -eq "High" }
if ($highRisk.Count -gt 0) {
    Write-Host "`n--- High Risk Apps ---" -ForegroundColor Red
    $highRisk | Select-Object DisplayName, AppId, DaysSinceActivity, UnusedReason, SecretExpiry, HasLiveCredentials |
        Format-Table -AutoSize
}
#endregion
