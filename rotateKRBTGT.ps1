<#
    .SYNOPSIS
    Simple script to be used together with a scheduled task, to rotate Kerberos Service Account's (krbtgt) password every 180 days.

    .LINK
    1. Pseudo password generator in PowerShell @ https://www.sharepointdiary.com/2020/04/powershell-generate-random-password.html
    2. ATT&CK MITRE M1015 @ https://attack.mitre.org/mitigations/M1015/
    
    .NOTES
    According to ATT&CK MITRE (M1015) changing the password of krbtgt principal is essential to counter Kerberos protocol related attacks, such as compromising a Kerberos Golden ticket (T1558/.001)
    
    ### Contributors ###
    1. Stefanos Daniil
#>

$diff = (New-TimeSpan -Start (Get-ADUser "krbtgt" -Properties *).PasswordLastSet -End (Get-Date)).Days
if($diff -lt "180")
{
    Exit
}

$pw = ConvertTo-SecureString -String "$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_}))" -AsPlainText -Force

Set-ADAccountPassword -Identity "krbtgt" -NewPassword $pw
Start-Process -FilePath "C:\Windows\System32\repadmin.exe" -ArgumentList @("/syncall","/ADeP") -WindowStyle Hidden -Wait
Write-EventLog -LogName "System" -Source "LsaSrv" -EntryType "Information" -EventId 9999 -Message "KRBTGT's account password has been sucessfully changed once."

Start-Sleep -Seconds 10

$pw = ConvertTo-SecureString -String "$(-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_}))" -AsPlainText -Force

Set-ADAccountPassword -Identity "krbtgt" -NewPassword $pw
Start-Process -FilePath "C:\Windows\System32\repadmin.exe" -ArgumentList @("/syncall","/ADeP") -WindowStyle Hidden -Wait
Write-EventLog -LogName "System" -Source "LsaSrv" -EntryType "Information" -EventId 10000 -Message "KRBTGT's account password has been sucessfully changed twice."