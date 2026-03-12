param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [switch]$SkipGraphConnection
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TrimmedValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $stringValue = [string]$Value
    if ([string]::IsNullOrWhiteSpace($stringValue)) {
        return $null
    }

    return $stringValue.Trim()
}

function Get-RowValue {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,

        [Parameter(Mandatory = $true)]
        [string[]]$CandidateNames
    )

    foreach ($name in $CandidateNames) {
        $property = $Row.PSObject.Properties[$name]
        if ($null -ne $property) {
            $value = Get-TrimmedValue -Value $property.Value
            if ($null -ne $value) {
                return $value
            }
        }
    }

    return $null
}

function Assert-GraphModule {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
        throw "Microsoft.Graph.Applications is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
}

function Ensure-GraphConnection {
    param(
        [switch]$SkipConnection
    )

    if ($SkipConnection) {
        return
    }

    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $graphContext) {
        Connect-MgGraph -Scopes 'Application.Read.All'
    }
}

function Get-MatchType {
    param(
        [string]$AppId,
        [string]$ServicePrincipalId
    )

    if ($AppId -and $ServicePrincipalId) {
        throw "Row contains both AppId and ServicePrincipalId. Provide only one identifier per row."
    }

    if ($AppId) {
        return 'AppRegistration'
    }

    if ($ServicePrincipalId) {
        return 'ServicePrincipal'
    }

    throw "Row does not contain AppId or ServicePrincipalId."
}

Assert-GraphModule
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Ensure-GraphConnection -SkipConnection:$SkipGraphConnection

if (-not (Test-Path -LiteralPath $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

$rows = Import-Csv -LiteralPath $CsvPath
if (-not $rows) {
    throw "CSV file is empty: $CsvPath"
}

$matchedResults = New-Object System.Collections.Generic.List[object]
$rowNumber = 1

foreach ($row in $rows) {
    $displayName = Get-RowValue -Row $row -CandidateNames @('DisplayName', 'Displayname')
    $appId = Get-RowValue -Row $row -CandidateNames @('AppId', 'ApplicationId', 'ClientId')
    $servicePrincipalId = Get-RowValue -Row $row -CandidateNames @('ServicePrincipalId', 'ServicePrincipalObjectId', 'ObjectId', 'Id')

    if (-not $displayName) {
        Write-Warning "Row ${rowNumber} skipped: DisplayName is missing."
        $rowNumber++
        continue
    }

    try {
        $matchType = Get-MatchType -AppId $appId -ServicePrincipalId $servicePrincipalId

        switch ($matchType) {
            'AppRegistration' {
                $graphObject = Get-MgApplication -Filter "appId eq '$appId'" -ConsistencyLevel eventual -All | Select-Object -First 1
                if (-not $graphObject) {
                    Write-Warning "Row ${rowNumber}: no app registration found for AppId '$appId'."
                    break
                }

                if ($graphObject.DisplayName -eq $displayName) {
                    $result = [pscustomobject]@{
                        RowNumber    = $rowNumber
                        MatchType    = 'AppRegistration'
                        DisplayName  = $displayName
                        Identifier   = $appId
                        GraphObjectId = $graphObject.Id
                    }

                    $matchedResults.Add($result)
                    Write-Host ("MATCH [{0}] DisplayName='{1}' AppId='{2}'" -f $result.MatchType, $result.DisplayName, $result.Identifier) -ForegroundColor Green
                }
                else {
                    Write-Warning "Row ${rowNumber}: AppId '$appId' resolved to '$($graphObject.DisplayName)', not '$displayName'."
                }
            }
            'ServicePrincipal' {
                $graphObject = Get-MgServicePrincipal -ServicePrincipalId $servicePrincipalId
                if (-not $graphObject) {
                    Write-Warning "Row ${rowNumber}: no service principal found for Id '$servicePrincipalId'."
                    break
                }

                if ($graphObject.DisplayName -eq $displayName) {
                    $result = [pscustomobject]@{
                        RowNumber    = $rowNumber
                        MatchType    = 'ServicePrincipal'
                        DisplayName  = $displayName
                        Identifier   = $servicePrincipalId
                        GraphObjectId = $graphObject.Id
                    }

                    $matchedResults.Add($result)
                    Write-Host ("MATCH [{0}] DisplayName='{1}' ServicePrincipalId='{2}'" -f $result.MatchType, $result.DisplayName, $result.Identifier) -ForegroundColor Green
                }
                else {
                    Write-Warning "Row ${rowNumber}: ServicePrincipalId '$servicePrincipalId' resolved to '$($graphObject.DisplayName)', not '$displayName'."
                }
            }
        }
    }
    catch {
        Write-Warning "Row ${rowNumber} failed: $($_.Exception.Message)"
    }

    $rowNumber++
}

Write-Host ""
Write-Host ("Successful matches: {0}" -f $matchedResults.Count) -ForegroundColor Cyan

if ($matchedResults.Count -gt 0) {
    $matchedResults | Format-Table -AutoSize
}
