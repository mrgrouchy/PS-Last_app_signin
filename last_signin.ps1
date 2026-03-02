Connect-MgGraph -Scopes "Application.Read.All", "AuditLog.Read.All", "Directory.Read.All"

$cutoffDate = (Get-Date).AddDays(-180)
$exportPath = "UnusedApps_$(Get-Date -Format 'yyyyMMdd').csv"

#region --- Collect Data ---

# All app registrations
Write-Host "Fetching app registrations..." -ForegroundColor Cyan
$allApps = Get-MgApplication -All -Property "id,appId,displayName,createdDateTime,signInAudience,requiredResourceAccess,passwordCredentials,keyCredentials,notes"

# All service principals (needed for sign-in activity cross-ref)
Write-Host "Fetching service principals..." -ForegroundColor Cyan
$allSPs = Get-MgServicePrincipal -All -Property "id,appId,displayName,signInActivity,servicePrincipalType,tags,accountEnabled"

# SP sign-in activity from beta endpoint (180 days, breaks out delegated vs app-only)
Write-Host "Fetching SP sign-in activities..." -ForegroundColor Cyan
$activities = [System.Collections.Generic.List[object]]::new()
$uri = "https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities"
do {
    $result = Invoke-MgGraphRequest -Method GET -Uri $uri
    $result.value | ForEach-Object { $activities.Add($_) }
    $uri = $result.'@odata.nextLink'
} while ($uri)

# Build lookup hashtables for performance
$activityLookup = @{}
$activities | ForEach-Object { $activityLookup[$_.appId] = $_ }

$spLookup = @{}
$allSPs | ForEach-Object { $spLookup[$_.AppId] = $_ }

#endregion

#region --- Build Report ---

Write-Host "Building report..." -ForegroundColor Cyan
$report = foreach ($app in $allApps) {

    $sp       = $spLookup[$app.AppId]
    $activity = $activityLookup[$app.AppId]

    # --- Credential status ---
    $now = Get-Date
    $secretExpiry  = ($app.PasswordCredentials | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
    $certExpiry    = ($app.KeyCredentials      | Sort-Object EndDateTime -Descending | Select-Object -First 1).EndDateTime
    $hasSecrets    = $app.PasswordCredentials.Count -gt 0
    $hasCerts      = $app.KeyCredentials.Count -gt 0
    $secretExpired = $hasSecrets -and $secretExpiry -and ($secretExpiry -lt $now)
    $certExpired   = $hasCerts   -and $certExpiry   -and ($certExpiry   -lt $now)
    $allCredsExpired = ($hasSecrets -or $hasCerts) -and $secretExpired -and (-not $hasCerts -or $certExpired)

    # --- Sign-in dates (all vectors) ---
    $lastDelegated  = $activity.delegatedClientSignInActivity.lastSignInDateTime
    $lastAppOnly    = $activity.applicationAuthenticationClientSignInActivity.lastSignInDateTime
    $lastManagedId  = $activity.msiSignInActivity.lastSignInDateTime  # Managed identity variant
    $spSignIn       = $sp.signInActivity.lastSignInDateTime           # Fallback from SP object itself

    # Most recent across all vectors
    $allDates = @($lastDelegated, $lastAppOnly, $lastManagedId, $spSignIn) |
                Where-Object { $_ } |
                Sort-Object -Descending
    $lastActivity = $allDates | Select-Object -First 1

    # --- Age calculations ---
    $appAgeDays = if ($app.CreatedDateTime) { (New-TimeSpan -Start $app.CreatedDateTime -End $now).Days } else { $null }
    $daysSinceActivity = if ($lastActivity) { (New-TimeSpan -Start $lastActivity -End $now).Days } else { $null }

    # --- Classification ---
    # Skip newly created apps (< 30 days) - not enough data
    $tooNew = $appAgeDays -ne $null -and $appAgeDays -lt 30

    # Determine if "unused"
    $unusedReason = switch ($true) {
        $tooNew                              { "Too New (<30d)" }
        (-not $sp)                           { "No Service Principal" }
        (-not $sp.AccountEnabled)            { "SP Disabled" }
        ($allCredsExpired)                   { "All Creds Expired" }
        (-not $lastActivity -and
         $appAgeDays -ge 30)                 { "Never Used" }
        ($daysSinceActivity -gt 180)         { "Inactive >180d" }
        default                              { $null }
    }

    $riskLevel = switch ($unusedReason) {
        "Never Used"          { if ($hasSecrets -or $hasCerts) { "High" } else { "Medium" } }
        "Inactive >180d"      { if ($hasSecrets -or $hasCerts) { "High" } else { "Medium" } }
        "No Service Principal"{ "Low" }
        "All Creds Expired"   { "Low" }
        "SP Disabled"         { "Low" }
        "Too New (<30d)"      { "Ignore" }
        default               { "Active" }
    }

    [PSCustomObject]@{
        DisplayName          = $app.DisplayName
        AppId                = $app.AppId
        ObjectId             = $app.Id
        SignInAudience       = $app.SignInAudience
        CreatedDaysAgo       = $appAgeDays
        HasServicePrincipal  = ($null -ne $sp)
        SPEnabled            = $sp.AccountEnabled
        SPType               = $sp.ServicePrincipalType
        LastDelegatedSignIn  = $lastDelegated
        LastAppOnlySignIn    = $lastAppOnly
        LastOverallActivity  = $lastActivity
        DaysSinceActivity    = $daysSinceActivity
        HasSecrets           = $hasSecrets
        SecretExpiry         = $secretExpiry
        SecretsExpired       = $secretExpired
        HasCerts             = $hasCerts
        CertExpiry           = $certExpiry
        CertsExpired         = $certExpired
        PermissionCount      = $app.RequiredResourceAccess.Count
        UnusedReason         = $unusedReason
        RiskLevel            = $riskLevel
        Notes                = $app.Notes
    }
}

#endregion

#region --- Output ---

$active   = $report | Where-Object { $_.RiskLevel -eq "Active" }
$high     = $report | Where-Object { $_.RiskLevel -eq "High" }
$medium   = $report | Where-Object { $_.RiskLevel -eq "Medium" }
$low      = $report | Where-Object { $_.RiskLevel -eq "Low" }
$tooNew   = $report | Where-Object { $_.RiskLevel -eq "Ignore" }

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
Write-Host "Total app registrations : $($report.Count)"
Write-Host "Active                  : $($active.Count)"
Write-Host "High risk (unused+creds): $($high.Count)"  -ForegroundColor Red
Write-Host "Medium risk             : $($medium.Count)" -ForegroundColor Yellow
Write-Host "Low risk                : $($low.Count)"    -ForegroundColor Gray
Write-Host "Too new to assess       : $($tooNew.Count)" -ForegroundColor DarkGray

# Export full report
$report | Export-Csv $exportPath -NoTypeInformation
Write-Host "`nFull report exported: $exportPath" -ForegroundColor Green

# Quick console view of high-risk
if ($high.Count -gt 0) {
    Write-Host "`n--- High Risk Apps ---" -ForegroundColor Red
    $high | Select-Object DisplayName, AppId, DaysSinceActivity, UnusedReason, SecretExpiry |
        Format-Table -AutoSize
}

#endregion
