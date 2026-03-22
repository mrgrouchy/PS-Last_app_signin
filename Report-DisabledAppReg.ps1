<#
.SYNOPSIS
    Tracks Azure AD / Entra applications that are disabled and records the first date/time they were observed disabled.

.DESCRIPTION
    Creates/updates a JSON file in the working directory:
      - Adds new disabled apps with firstSeen timestamp
      - Updates lastSeen timestamp on subsequent runs
      - Does not overwrite firstSeen

    When -UseLA is specified, queries Log Analytics for attempted sign-ins starting from each app's
    firstSeen date in the JSON (not a fixed 30-day window). -LookbackDays is only used as a fallback
    for apps without a firstSeen entry.

.REQUIREMENTS
    Microsoft Graph PowerShell SDK
    Permissions: Application.ReadWrite.All (as per your example)

.PARAMETER JsonPath
    Path to the JSON tracker file. Default: .\disabled-apps-tracker.json

.PARAMETER UseLA
    Enable Log Analytics queries for attempted sign-ins. In the shared repo,
    the hardcoded WorkspaceId is intentionally redacted and must be populated
    privately before this mode will return Log Analytics data.

.PARAMETER LookbackDays
    Fallback lookback window (days) if an app has no firstSeen date in JSON. Default: 90.
    Apps WITH firstSeen will query from that date regardless of this parameter.

.PARAMETER OutCsv
    Path to export tracker items as CSV.

.PARAMETER HtmlReport
    Generate an HTML report in the current directory.
#>

## todo: once a week backup the json to \backup force with a switch


param(
    [string]$JsonPath    = (Join-Path -Path (Get-Location) -ChildPath "disabled-apps-tracker.json"),
    [switch]$UseLA,
    [int]$LookbackDays   = 90,
    [string]$OutCsv      = "",
    [switch]$HtmlReport
)

# ----------------------------
# Helper: Initialise JSON store
# ----------------------------
function Initialize-JsonStore {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        $initial = [ordered]@{
            schemaVersion = 1
            createdAt     = (Get-Date).ToString("o")
            updatedAt     = (Get-Date).ToString("o")
            items         = @()
        }

        $initial | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

# ----------------------------
# Helper: Load JSON store
# ----------------------------
function Get-JsonStore {
    param([string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        # Recover gracefully if file is empty
        return [pscustomobject]@{ schemaVersion = 1; createdAt = (Get-Date).ToString("o"); updatedAt = (Get-Date).ToString("o"); items = @() }
    }

    return ($raw | ConvertFrom-Json)
}

# ----------------------------
# Helper: Save JSON store
# ----------------------------
function Set-JsonStore {
    param(
        [string]$Path,
        [object]$Store
    )

    $Store.updatedAt = (Get-Date).ToString("o")
    $Store | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

# ----------------------------
# Helper: Generate HTML report
# ----------------------------
function New-DisabledAppsHtmlReport {
    param(
        [array]$Items,
        [string]$OutputPath
    )

    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $appsWithActivity = @($Items | Where-Object { $_.lastAttemptedAnySignIn })
    $appsWithoutActivity = @($Items | Where-Object { -not $_.lastAttemptedAnySignIn })

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disabled Apps Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; }
        h2 { color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }
        th { background-color: #2c3e50; color: white; padding: 12px; text-align: left; font-weight: bold; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f9f9f9; }
        .no-activity { color: #999; font-style: italic; }
        .has-activity { color: #e74c3c; font-weight: bold; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary-item { display: inline-block; margin-right: 30px; }
        .summary-label { font-weight: bold; color: #2c3e50; }
        .summary-value { color: #e74c3c; font-size: 18px; }
    </style>
</head>
<body>
    <h1>Disabled Applications Report</h1>
    <p>Generated: $now</p>
    <div class="summary">
        <div class="summary-item"><span class="summary-label">Total Disabled Apps:</span> <span class="summary-value">$($Items.Count)</span></div>
        <div class="summary-item"><span class="summary-label">With Attempted Sign-ins:</span> <span class="summary-value" style="color: #e74c3c;">$($appsWithActivity.Count)</span></div>
        <div class="summary-item"><span class="summary-label">Without Activity:</span> <span class="summary-value" style="color: #27ae60;">$($appsWithoutActivity.Count)</span></div>
    </div>
    <h2>Disabled Applications with Attempted Sign-in Activity</h2>
"@

    if ($appsWithActivity.Count -gt 0) {
        $html += @"
    <table>
        <tr>
            <th>Display Name</th>
            <th>App ID</th>
            <th>Date Disabled</th>
            <th>Last Attempt</th>
            <th>Days Since Attempt</th>
            <th>Interactive</th>
            <th>Non-Interactive</th>
            <th>Service Principal</th>
            <th>Total Attempts</th>
            <th>Hit Count</th>
        </tr>
"@
        foreach ($item in ($appsWithActivity | Sort-Object lastAttemptedAnySignIn -Descending)) {
            $disabledDate = if ($item.firstSeen) { ([datetime]$item.firstSeen).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
            $lastAttempt = if ($item.lastAttemptedAnySignIn) { ([datetime]$item.lastAttemptedAnySignIn).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
            $daysSince = if ($item.lastAttemptedAnySignIn) { [int]((Get-Date) - [datetime]$item.lastAttemptedAnySignIn).TotalDays } else { 'N/A' }
            $totalAttempts = ([int]$item.attemptedInteractiveCount + [int]$item.attemptedNonInteractiveCount + [int]$item.attemptedServicePrincipalCount)
            $hitCount = if ($item.attemptedSignInHitCount) { $item.attemptedSignInHitCount } else { 0 }

            $html += @"
        <tr>
            <td>$($item.displayName)</td>
            <td>$($item.appId)</td>
            <td>$disabledDate</td>
            <td>$lastAttempt</td>
            <td>$daysSince</td>
            <td>$([int]$item.attemptedInteractiveCount)</td>
            <td>$([int]$item.attemptedNonInteractiveCount)</td>
            <td>$([int]$item.attemptedServicePrincipalCount)</td>
            <td class="has-activity">$totalAttempts</td>
            <td>$hitCount</td>
        </tr>
"@
        }
        $html += "    </table>"
    } else {
        $html += "    <p class='no-activity'>No disabled apps with attempted sign-in activity.</p>"
    }

    $html += @"
    <h2>Disabled Applications Without Activity</h2>
"@

    if ($appsWithoutActivity.Count -gt 0) {
        $html += @"
    <table>
        <tr>
            <th>Display Name</th>
            <th>App ID</th>
            <th>Date Disabled</th>
            <th>Days Since Disabled</th>
        </tr>
"@
        foreach ($item in ($appsWithoutActivity | Sort-Object firstSeen -Descending)) {
            $disabledDate = if ($item.firstSeen) { ([datetime]$item.firstSeen).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
            $daysSinceDisabled = if ($item.firstSeen) { [int]((Get-Date) - [datetime]$item.firstSeen).TotalDays } else { 'N/A' }

            $html += @"
        <tr>
            <td>$($item.displayName)</td>
            <td>$($item.appId)</td>
            <td>$disabledDate</td>
            <td>$daysSinceDisabled</td>
        </tr>
"@
        }
        $html += "    </table>"
    } else {
        $html += "    <p class='no-activity'>All disabled apps have attempted sign-in activity.</p>"
    }

    $html += @"
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
}

# ----------------------------
# Helper: Get ALL pages from Graph
# ----------------------------
function Get-AllDisabledApplications {
    # Your original intent: beta applications with filter isDisabled eq true
    $isDisabledFilter = "isDisabled eq true"
    $uri = "https://graph.microsoft.com/beta/applications?`$filter=$($isDisabledFilter)"

    $all = @()

    do {
        $resp = Invoke-MgGraphRequest -Uri $uri -Method GET
        if ($resp.value) { $all += $resp.value }

        # Paging
        $uri = $resp.'@odata.nextLink'
    } while ($uri)

    return $all
}

# ----------------------------
# Helper: Chunk array for LA queries
# ----------------------------
function Split-IntoChunks {
    param(
        [array]$Items,
        [int]$ChunkSize = 500
    )

    $chunks = @()
    for ($i = 0; $i -lt $Items.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize - 1, $Items.Count - 1)
        $chunks += ,$Items[$i..$end]
    }
    return $chunks
}

# ----------------------------
# Helper: Query LA sign-ins by AppId
# ----------------------------
function Get-SignInStatsByAppId {
    param(
        [string]$WorkspaceId,
        [array]$AppInfos,
        [int]$LookbackDays
    )

    $resultsByAppId = @{}
    if (-not $WorkspaceId -or -not $AppInfos -or $AppInfos.Count -eq 0) { return $resultsByAppId }

    $chunks = Split-IntoChunks -Items $AppInfos -ChunkSize 300

    foreach ($chunk in $chunks) {
        $rows = @()
        foreach ($item in $chunk) {
            $appId = $item.AppId
            if (-not $appId) { continue }

            $firstSeen = $item.FirstSeen
            if (-not $firstSeen) {
                $firstSeen = (Get-Date).AddDays(-$LookbackDays)
            }

            $dt = ([datetime]$firstSeen).ToUniversalTime().ToString("o")
            $rows += "'$appId', datetime($dt)"
        }

        if ($rows.Count -eq 0) { continue }

        $rowsText = $rows -join ",`n    "
        $kql = @"
let apps = datatable(AppId:string, FirstSeen:datetime)[
    $rowsText
];
union isfuzzy=true
    (SigninLogs | join kind=inner (apps) on AppId | extend T = "i"),
    (AADNonInteractiveUserSignInLogs | join kind=inner (apps) on AppId | extend T = "n"),
    (AADServicePrincipalSignInLogs | join kind=inner (apps) on AppId | extend T = "sp")
| where TimeGenerated > FirstSeen
| summarize
    LastInteractive         = maxif(TimeGenerated, T == "i"),
    LastNonInteractive      = maxif(TimeGenerated, T == "n"),
    LastServicePrincipal    = maxif(TimeGenerated, T == "sp"),
    CountInteractive        = countif(T == "i"),
    CountNonInteractive     = countif(T == "n"),
    CountServicePrincipal   = countif(T == "sp"),
    LatestCorrelationIds    = make_list(CorrelationId, 10)
  by AppId
"@

        try {
            $laResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $kql -Timespan (New-TimeSpan -Days $LookbackDays)
            foreach ($row in $laResults.Results) {
                $resultsByAppId[$row.AppId] = $row
            }
        }
        catch {
            Write-Warning "Log Analytics query failed for a chunk: $_"
        }
    }

    return $resultsByAppId
}

# ============================
# Main
# ============================

# Connect to Graph (your permission scope)
Connect-MgGraph -Scopes "Application.ReadWrite.All" | Out-Null

# Hardcoded Log Analytics workspace
# Intentionally redacted in the shared repo. Set privately in your local copy if -UseLA is required.
$WorkspaceId = ""

# Connect to Log Analytics if switched on
$useLA = $UseLA.IsPresent

if ($useLA) {
    Write-Host "Log Analytics enabled (WorkspaceId: $WorkspaceId) — will query attempted sign-ins from each app's firstSeen date (fallback: $LookbackDays days)." -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
}

# Ensure JSON exists
Initialize-JsonStore -Path $JsonPath

# Load existing JSON data
$store = Get-JsonStore -Path $JsonPath

# Ensure items is an array (ConvertFrom-Json can return $null for empty)
if (-not $store.items) { $store.items = @() }

# Build an index for fast lookups (keyed by appId; you can switch to 'id' if preferred)
$index = @{}
foreach ($item in $store.items) {
    if ($null -ne $item.appId -and -not $index.ContainsKey($item.appId)) {
        $index[$item.appId] = $item
    }
}

# Get disabled apps from Graph
$apps = Get-AllDisabledApplications

# Query attempted sign-ins for disabled apps (user + SP)
$signInByAppId = @{}
if ($useLA -and $apps.Count -gt 0) {
    $appInfos = foreach ($app in $apps) {
        $appId = $app.appId
        if (-not $appId) { continue }
        $firstSeen = $null
        if ($index.ContainsKey($appId)) { $firstSeen = $index[$appId].firstSeen }
        [pscustomobject]@{ AppId = $appId; FirstSeen = $firstSeen }
    }
    Write-Host "Querying attempted sign-ins for disabled apps..." -ForegroundColor Cyan
    $signInByAppId = Get-SignInStatsByAppId -WorkspaceId $WorkspaceId -AppInfos $appInfos -LookbackDays $LookbackDays
    Write-Host "  Sign-in stats for $($signInByAppId.Count) apps" -ForegroundColor Gray
}

# Timestamp for this run
$now = (Get-Date).ToString("o")

$newCount = 0
$updatedCount = 0

foreach ($app in $apps) {

    $displayName = $app.displayName
    $appId       = $app.appId
    $objectId    = $app.id
    $isDisabled  = $app.isDisabled

    if (-not $appId) { continue } # safety

    $signIn = $signInByAppId[$appId]
    $lastInteractive    = $null
    $lastNonInteractive = $null
    $lastServicePrincipal = $null
    $countInteractive = 0
    $countNonInteractive = 0
    $countServicePrincipal = 0
    $correlationIds = @()

    if ($signIn) {
        if ($signIn.LastInteractive)    { $lastInteractive = [datetime]$signIn.LastInteractive }
        if ($signIn.LastNonInteractive) { $lastNonInteractive = [datetime]$signIn.LastNonInteractive }
        if ($signIn.LastServicePrincipal) { $lastServicePrincipal = [datetime]$signIn.LastServicePrincipal }
        $countInteractive = [int]$signIn.CountInteractive
        $countNonInteractive = [int]$signIn.CountNonInteractive
        $countServicePrincipal = [int]$signIn.CountServicePrincipal
        if ($signIn.LatestCorrelationIds) { $correlationIds = @($signIn.LatestCorrelationIds) }
    }

    $lastAttemptedAny = @($lastInteractive, $lastNonInteractive, $lastServicePrincipal) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

    $hasAttemptsThisRun = ($countInteractive -gt 0) -or ($countNonInteractive -gt 0) -or ($countServicePrincipal -gt 0)
    if (-not $index.ContainsKey($appId)) {
        # First time we've seen this app disabled → add with firstSeen
        $entry = [pscustomobject]@{
            displayName = $displayName
            appId       = $appId
            objectId    = $objectId
            isDisabled  = $isDisabled
            firstSeen   = $now
            lastSeen    = $now
            lastAttemptedInteractiveSignIn     = $lastInteractive
            lastAttemptedNonInteractiveSignIn  = $lastNonInteractive
            lastAttemptedServicePrincipalSignIn = $lastServicePrincipal
            lastAttemptedAnySignIn             = $lastAttemptedAny
            attemptedInteractiveCount          = $countInteractive
            attemptedNonInteractiveCount       = $countNonInteractive
            attemptedServicePrincipalCount     = $countServicePrincipal
            attemptedSignInHitCount             = $(if ($hasAttemptsThisRun) { 1 } else { 0 })
            latestCorrelationIds               = @($correlationIds)
        }

        $store.items += $entry
        $index[$appId] = $entry

        $newCount++
    }
    else {
        # Already tracked → update lastSeen (do NOT overwrite firstSeen)
        $existing = $index[$appId]
        foreach ($prop in @(
            "lastAttemptedInteractiveSignIn",
            "lastAttemptedNonInteractiveSignIn",
            "lastAttemptedServicePrincipalSignIn",
            "lastAttemptedAnySignIn",
            "attemptedInteractiveCount",
            "attemptedNonInteractiveCount",
            "attemptedServicePrincipalCount",
            "attemptedSignInHitCount",
            "latestCorrelationIds"
        )) {
            if (-not $existing.PSObject.Properties[$prop]) {
                Add-Member -InputObject $existing -MemberType NoteProperty -Name $prop -Value $null
            }
        }
        $existing.displayName = $displayName
        $existing.objectId    = $objectId
        $existing.isDisabled  = $isDisabled
        $existing.lastSeen    = $now
        $existing.lastAttemptedInteractiveSignIn     = $lastInteractive
        $existing.lastAttemptedNonInteractiveSignIn  = $lastNonInteractive
        $existing.lastAttemptedServicePrincipalSignIn = $lastServicePrincipal
        $existing.lastAttemptedAnySignIn             = $lastAttemptedAny
        $existing.attemptedInteractiveCount          = $countInteractive
        $existing.attemptedNonInteractiveCount       = $countNonInteractive
        $existing.attemptedServicePrincipalCount     = $countServicePrincipal
        $existing.latestCorrelationIds               = @($correlationIds)
        if ($hasAttemptsThisRun) {
            $currentCount = if ($null -ne $existing.attemptedSignInHitCount) { [int]$existing.attemptedSignInHitCount } else { 0 }
            $existing.attemptedSignInHitCount = $currentCount + 1
        }

        $updatedCount++
    }
}

# Save JSON store
Set-JsonStore -Path $JsonPath -Store $store

# Output summary
write-host ""
Write-Host "Disabled apps returned by Graph: $($apps.Count)"
Write-Host "New entries added (firstSeen recorded): $newCount"
Write-Host "Existing entries updated (lastSeen refreshed): $updatedCount"
#Write-Host "Tracker file: $JsonPath"

if ($useLA) {
    $appsWithAttempts = $store.items | Where-Object { $_.lastAttemptedAnySignIn }
    Write-Host "Apps with attempted sign-ins (last $LookbackDays days): $($appsWithAttempts.Count)"
}

# Optional: show current disabled set
$apps | Select-Object displayName, appId, id, isDisabled

if ($OutCsv) {
    $store.items | Export-Csv -Path $OutCsv -NoTypeInformation
    Write-Host "CSV exported to $OutCsv" -ForegroundColor Green
}

if ($HtmlReport) {
    $reportDayFolder = Join-Path -Path (Join-Path -Path (Get-Location) -ChildPath "reports") -ChildPath (Get-Date -Format 'yyyyMMdd')
    if (-not (Test-Path -LiteralPath $reportDayFolder)) {
        New-Item -Path $reportDayFolder -ItemType Directory -Force | Out-Null
    }
    $HtmlPath = Join-Path -Path $reportDayFolder -ChildPath ("DisabledApps_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html")
    New-DisabledAppsHtmlReport -Items $store.items -OutputPath $HtmlPath
    Write-Host "HTML report exported to $HtmlPath" -ForegroundColor Green
}
