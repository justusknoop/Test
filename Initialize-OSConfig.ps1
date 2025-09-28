<#
    .SYNOPSIS
        Initialisiert die OSConfig-Baseline auf einem Windows OS / Server 2022/2025.

    .DESCRIPTION
        Dieses Skript installiert das PowerShell-Modul Microsoft.OSConfig aus der PSGallery,
        wendet eine vordefinierte Sicherheitsbaseline an und überprüft die Konformität.
        
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
        Version:     1.0.0
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

#region Funktionen
function Install-OSConfigOnline {
    Write-Verbose "Installiere Microsoft.OSConfig (Online) aus PSGallery..."

    # NuGet-Provider sicherstellen
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
    }

    # PSGallery ggf. vertrauen (vermeidet Prompt in unbeaufsichtigten Deployments)
    try { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop } catch {}

    # Modul installieren/aktualisieren
    Install-Module -Name Microsoft.OSConfig -Scope AllUsers -Force -ErrorAction Stop

    # Laden prüfen
    Import-Module Microsoft.OSConfig -ErrorAction Stop
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
#endregion

#region Hauptskript
try {
    Install-OSConfigOnline

    $scenarioPath = Get-ScenarioPath -Scenario $Scenario
    Write-Host "Wende Baseline an: $scenarioPath"

    # Default-Baseline anwenden
    Set-OSConfigDesiredConfiguration -Scenario $scenarioPath -Default -ErrorAction Stop

    exit 0
}

# Catch-Block für Fehlerbehandlung
catch {
    Write-Error $_.Exception.Message
    exit 1
}
#endregion