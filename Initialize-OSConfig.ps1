<#
    .SYNOPSIS
        Initialisiert die OSConfig-Baseline auf einem Windows OS / Server 2022/2025.

    .DESCRIPTION
        Dieses Skript installiert das PowerShell-Modul Microsoft.OSConfig aus der PSGallery,
        wendet eine vordefinierte Sicherheitsbaseline an und überprüft die Konformität.
        Zusätzlich erstellt es einen TXT-Report der Änderungen (Vorher/Nachher) unter C:\Users\Public\Documents.
        
        Unterstützte Szenarien:
        - MemberServer        | Windows Server, Mitglied einer Domäne (z. B. Fileserver, Applikationsserver).
        - WorkgroupMember     | Windows Server, nicht in einer Domäne, sondern nur in einer Workgroup. 
        - DomainController    | Speziell für Active Directory Domain Controller.
        - SecuredCore Windows | Für Server, die als Secured-Core-Server laufen sollen. Hardwarevoraussetzungen müssen erfüllt sein.
        - DefenderAntivirus   | Reine Baseline für Microsoft Defender Antivirus.

    .PARAMETER Scenario
        Das anzuwendende Szenario (z.B. 'MemberServer').

    .NOTES
        Autor:       Justus Knoop (thinformatics AG))
        Erstellt:    2025-09-23
        Version:     1.0.2   # PS 5.1 kompatibel (keine '?.' / '??')
        GitHub:      https://github.com/thinformatics/azure-lz-templates

    .EXAMPLE
        .\Initialize-OSConfig.ps1 -Scenario MemberServer 
        Initialisiert die Baseline für einen Member Server.

    .LINK
        https://learn.microsoft.com/de-de/windows-server/security/osconfig/osconfig-overview
        https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines
        https://www.powershellgallery.com/packages/Microsoft.OSConfig
    
#>

[CmdletBinding(SupportsShouldProcess)]
#region define parameters
param(
    # Scenario: Welches Szenario soll angewendet werden?
    [Parameter(Mandatory=$true)]
    [ValidateSet('MemberServer','WorkgroupMember','DomainController','SecuredCore','DefenderAntivirus')]
    [string]$Scenario
)
#endregion

# --- Unattended Defaults ---
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'  # Telemetrie-Hinweis stummschalten

# --- Report-Ziel: Public Documents ---
$PublicDocs = Join-Path $env:PUBLIC 'Documents'
try { New-Item -ItemType Directory -Path $PublicDocs -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
$ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutTxt = Join-Path $PublicDocs ("OSConfig_Aenderungen_{0}_{1}.txt" -f $env:COMPUTERNAME, $ts)

#region Funktionen
function Install-OSConfigOnline {
    Write-Verbose "Installiere Microsoft.OSConfig (Online) aus PSGallery..."

    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -ErrorAction Stop
    }

    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $repo) {
        Register-PSRepository -Name 'PSGallery' -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted -ErrorAction Stop
    } elseif ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop
    }

    Install-Module -Name Microsoft.OSConfig -Scope AllUsers -Repository PSGallery -Force -AcceptLicense -Confirm:$false -ErrorAction Stop
    Import-Module Microsoft.OSConfig -Force -ErrorAction Stop
}

function Get-ScenarioPath {
    param([string]$Scenario)
    switch ($Scenario) {
        'MemberServer'       { 'SecurityBaseline/WS2025/MemberServer' }
        'WorkgroupMember'    { 'SecurityBaseline/WS2025/WorkgroupMember' }
        'DomainController'   { 'SecurityBaseline/WS2025/DomainController' }
        'SecuredCore'        { 'SecuredCore' }
        'DefenderAntivirus'  { 'Defender/Antivirus' }
        default              { throw "Unbekanntes Szenario: $Scenario" }
    }
}

function Index-ByName {
    param([object[]]$Items)
    $map = @{}
    foreach ($i in $Items) { if ($null -ne $i -and $null -ne $i.Name) { $map[$i.Name] = $i } }
    return $map
}

function Nz {
    param($Value, $Fallback='n/a')
    if ($null -eq $Value) { return $Fallback }
    if ($Value -is [string] -and $Value -eq '') { return $Fallback }
    return $Value
}

function Get-ComplianceStatus($obj) {
    if ($null -eq $obj) { return $null }
    if ($null -eq $obj.Compliance) { return $null }
    return $obj.Compliance.Status
}
function Get-ComplianceReason($obj) {
    if ($null -eq $obj) { return $null }
    if ($null -eq $obj.Compliance) { return $null }
    return $obj.Compliance.Reason
}
#endregion

#region Hauptskript
try {
    Install-OSConfigOnline

    $scenarioPath = Get-ScenarioPath -Scenario $Scenario

    # Snapshot VORHER
    $before = @(Get-OSConfigDesiredConfiguration -Scenario $scenarioPath -ErrorAction Stop)
    $beforeIdx = Index-ByName -Items $before

    # Default-Baseline anwenden
    Set-OSConfigDesiredConfiguration -Scenario $scenarioPath -Default -ErrorAction Stop

    # Snapshot NACHHER
    $after = @(Get-OSConfigDesiredConfiguration -Scenario $scenarioPath -ErrorAction Stop)
    $afterIdx = Index-ByName -Items $after

    # Auswertung
    $remediated = New-Object System.Collections.Generic.List[object]
    $stillNC    = New-Object System.Collections.Generic.List[object]
    $newNC      = New-Object System.Collections.Generic.List[object]

    foreach ($name in $afterIdx.Keys) {
        $a = $afterIdx[$name]
        $aStat   = Get-ComplianceStatus $a
        $aReason = Get-ComplianceReason $a

        $b = $beforeIdx[$name]
        $bStat   = Get-ComplianceStatus $b
        $bReason = Get-ComplianceReason $b

        if ($bStat -ne 'Compliant' -and $aStat -eq 'Compliant') {
            $remediated.Add([pscustomobject]@{ Name=$name; BeforeStatus=$bStat; BeforeReason=$bReason; AfterStatus=$aStat })
        }
        elseif ($bStat -ne 'Compliant' -and $aStat -ne 'Compliant') {
            $stillNC.Add([pscustomobject]@{ Name=$name; Status=$aStat; Reason=$aReason })
        }
        elseif ($bStat -eq 'Compliant' -and $aStat -ne 'Compliant') {
            $newNC.Add([pscustomobject]@{ Name=$name; Status=$aStat; Reason=$aReason })
        }
    }

    $totalBefore = $before.Count
    $ncBefore    = ($before | Where-Object { (Get-ComplianceStatus $_) -ne 'Compliant' }).Count
    $totalAfter  = $after.Count
    $ncAfter     = ($after  | Where-Object { (Get-ComplianceStatus $_) -ne 'Compliant' }).Count

    # TXT-Report schreiben
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("OSConfig – Änderungen durch Baseline (Vorher/Nachher)")
    $lines.Add("Host: $env:COMPUTERNAME")
    $lines.Add("Scenario: $Scenario ($scenarioPath)")
    $lines.Add("Zeitpunkt: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("")
    $lines.Add(("Übersicht: Total(Vorher)={0} | NonCompliant(Vorher)={1} | Total(Nachher)={2} | NonCompliant(Nachher)={3}" -f $totalBefore,$ncBefore,$totalAfter,$ncAfter))
    $lines.Add(("Remediiert: {0} | Weiterhin NonCompliant: {1} | Neu NonCompliant: {2}" -f $remediated.Count,$stillNC.Count,$newNC.Count))
    $lines.Add("")

    $maxItems = 100
    if ($remediated.Count -gt 0) {
        $lines.Add("Remediiert (max. $maxItems):")
        foreach ($i in $remediated | Select-Object -First $maxItems) {
            $lines.Add(" - {0} | vorher: {1} ({2}) -> nachher: {3}" -f $i.Name, (Nz $i.BeforeStatus), (Nz $i.BeforeReason), (Nz $i.AfterStatus))
        }
        $lines.Add("")
    }
    if ($stillNC.Count -gt 0) {
        $lines.Add("Weiterhin nicht konform (max. $maxItems):")
        foreach ($i in $stillNC | Select-Object -First $maxItems) {
            $lines.Add(" - {0}: {1} ({2})" -f $i.Name, (Nz $i.Status), (Nz $i.Reason))
        }
        $lines.Add("")
    }
    if ($newNC.Count -gt 0) {
        $lines.Add("Neu nicht konform (max. $maxItems):")
        foreach ($i in $newNC | Select-Object -First $maxItems) {
            $lines.Add(" - {0}: {1} ({2})" -f $i.Name, (Nz $i.Status), (Nz $i.Reason))
        }
        $lines.Add("")
    }

    if ($ncAfter -eq 0) {
        $lines.Add("Ergebnis: Alle geprüften Einstellungen sind nach der Anwendung konform.")
    } else {
        $lines.Add("Ergebnis: Es verbleiben nicht konforme Einstellungen. Details siehe oben.")
    }

    $lines -join [Environment]::NewLine | Out-File -FilePath $OutTxt -Encoding UTF8

    exit 0
}
catch {
    $msg = "FEHLER: " + $_.Exception.Message
    try { $msg | Out-File -FilePath $OutTxt -Encoding UTF8 } catch {}
    exit 1
}
#endregion
