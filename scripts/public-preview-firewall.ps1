#Requires -Version 7.0
param([switch]$AllowAllInbound, [switch]$Rollback)
$ErrorActionPreference = 'Stop'
$previewRuleNames = @('Sifruno-UserRequested-AllTCP','Sifruno-UserRequested-AllUDP')
$previewWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$previewReportRoot = Join-Path $previewWorkspace '.cache\public-preview'
if (-not $IsWindows) { throw 'This firewall operation is Windows specific.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows administrator elevation is required for firewall changes.' }
if ($AllowAllInbound -eq $Rollback) { throw 'Choose exactly one explicit action: -AllowAllInbound or -Rollback.' }
New-Item -ItemType Directory -Force -Path $previewReportRoot | Out-Null
if ($Rollback) {
    foreach ($previewRuleName in $previewRuleNames) {
        Get-NetFirewallRule -Name $previewRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    Write-Host 'Removed only the two Sifruno user-requested all-port rules.'
    exit 0
}
$previewBefore = [ordered]@{
    observed_at = [DateTime]::UtcNow.ToString('o')
    profiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction)
    managed_rules = @(foreach ($previewRuleName in $previewRuleNames) { Get-NetFirewallRule -Name $previewRuleName -ErrorAction SilentlyContinue | Select-Object Name,Enabled,Action,Direction })
}
$previewBefore | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $previewReportRoot 'firewall-before.json') -Encoding utf8
foreach ($previewProtocol in @('TCP','UDP')) {
    $previewRuleName = 'Sifruno-UserRequested-All' + $previewProtocol
    $previewRule = Get-NetFirewallRule -Name $previewRuleName -ErrorAction SilentlyContinue
    if ($previewRule) {
        if ($previewRule.DisplayName -ne ('Sifruno user-requested all inbound '+$previewProtocol)) { throw 'Existing rule identity does not match this managed operation.' }
        $previewRule | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any -ErrorAction Stop
        $previewRule | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol $previewProtocol -LocalPort Any -RemotePort Any
    } else {
        New-NetFirewallRule -Name $previewRuleName -DisplayName ('Sifruno user-requested all inbound '+$previewProtocol) -Description 'Explicit user request: allow all inbound TCP/UDP ports. Existing block rules and provider firewalls still take precedence.' -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $previewProtocol -LocalPort Any -RemoteAddress Any -ErrorAction Stop | Out-Null
    }
}
$previewAfter = @(foreach ($previewRuleName in $previewRuleNames) {
    $previewRule = Get-NetFirewallRule -Name $previewRuleName
    $previewPort = $previewRule | Get-NetFirewallPortFilter
    if ($previewRule.Enabled -ne 'True' -or $previewRule.Action -ne 'Allow' -or $previewRule.Direction -ne 'Inbound' -or $previewPort.LocalPort -ne 'Any') { throw 'Requested firewall rule did not verify.' }
    [pscustomobject]@{name=$previewRule.Name; enabled=[string]$previewRule.Enabled; action=[string]$previewRule.Action; direction=[string]$previewRule.Direction; protocol=[string]$previewPort.Protocol; local_port=[string]$previewPort.LocalPort}
})
@{observed_at=[DateTime]::UtcNow.ToString('o'); rules=$previewAfter; firewall_profiles_disabled=$false; provider_firewall_verified=$false} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $previewReportRoot 'firewall-after.json') -Encoding utf8
$previewAfter | ConvertTo-Json -Depth 4
