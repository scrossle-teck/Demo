<#
.SYNOPSIS
    Lists on-prem Active Directory security groups whose names contain "citrix" or "ctx" and displays their Managed By.

.DESCRIPTION
    Requires RSAT ActiveDirectory module. Resolves the ManagedBy DN to a readable name where possible.
    Filters groups whose Name matches *citrix* or *ctx* (case-insensitive) and returns Name and ManagedByDisplay.

.PARAMETER ExportCsv
    Optional path to export results as CSV.

.EXAMPLE
    .\Get-CitrixGroups.ps1

.EXAMPLE
    .\Get-CitrixGroups.ps1 -ExportCsv .\citrix-groups.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $ExportCsv
)

function Ensure-ActiveDirectoryModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module not found. Install RSAT: Active Directory module for Windows PowerShell."
        Write-Warning "On Windows 10/11: 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' (Run as admin)."
        throw "ActiveDirectory module is required."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Resolve-ManagedByDisplayName {
    param(
        [string] $ManagedBy
    )
    if ([string]::IsNullOrWhiteSpace($ManagedBy)) { return $null }
    try {
        # ManagedBy is usually a DN; try to fetch and return the name (CN) or DisplayName
        $obj = Get-ADObject -Identity $ManagedBy -Properties name, displayName -ErrorAction Stop
        if ($obj.DisplayName) { return $obj.DisplayName }
        elseif ($obj.Name) { return $obj.Name }
        else { return $ManagedBy }
    } catch {
        # If not resolvable, fall back to the raw value
        return $ManagedBy
    }
}

function Resolve-ManagedByEmail {
    param(
        [string] $ManagedBy
    )
    if ([string]::IsNullOrWhiteSpace($ManagedBy)) { return $null }
    # Try as a user first (supports DN, GUID, SID, or SamAccountName)
    try {
        $u = Get-ADUser -Identity $ManagedBy -Properties mail -ErrorAction Stop
        if ($u.Mail) { return $u.Mail }
    } catch { }
    # Fall back to a generic AD object and check common email attributes (contacts etc.)
    try {
        $obj = Get-ADObject -Identity $ManagedBy -Properties mail, proxyAddresses -ErrorAction Stop
        if ($obj.Mail) { return $obj.Mail }
        # If proxyAddresses exists, pick the primary SMTP (prefixed with 'SMTP:')
        if ($obj.ProxyAddresses) {
            $primary = $obj.ProxyAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1
            if ($primary) { return ($primary -replace '^SMTP:', '') }
        }
    } catch { }
    return $null
}

try {
    Ensure-ActiveDirectoryModule

    # Server-side filter: only Security groups whose name contains citrix or ctx
    $groups = Get-ADGroup -Filter {(GroupCategory -eq 'Security') -and ((name -like '*citrix*') -or (name -like '*ctx*'))} -Properties ManagedBy, GroupCategory

    $results = foreach ($g in $groups) {
        [pscustomobject]@{
            Name              = $g.Name
            ManagedByDisplay  = Resolve-ManagedByDisplayName -ManagedBy $g.ManagedBy
            ManagedByEmail    = Resolve-ManagedByEmail -ManagedBy $g.ManagedBy
        }
    }

    if ($null -eq $results -or -not $results) {
        Write-Host "No matching security groups found." -ForegroundColor Yellow
        return
    }

    $results | Sort-Object Name | Format-Table -AutoSize

    if ($ExportCsv) {
        $results | Sort-Object Name | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Exported to: $ExportCsv" -ForegroundColor Green
    }
}
catch {
    Write-Error $_
    exit 1
}