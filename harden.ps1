###### DOCUMENTATION ######
# About TLS cmdlets @ https://learn.microsoft.com/en-us/powershell/module/tls/?view=windowsserver2022-ps
# TLS support on Windows platforms @ https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
# TLS registry settings @ https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
# Cipher suites supported on Windows platforms @ https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel
# Demystifying SChannel @ https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233
#
#
# Notes #
# Execution directly from Git: 
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process;Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stefanos007/PSScripts/main/harden.ps1").Content
#
# Credits #
# 1. Write-Color Function @ https://stackoverflow.com/questions/2688547/multiple-foreground-colors-in-powershell-in-one-command
#
# Contributors #
#####################
# 1. Stefanos Daniil
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
    for ($i = 0; $i -lt $Text.Length; $i++) {
        Write-Host $Text[$i] -Foreground $Color[$i] -NoNewLine
    }
    Write-Host
}
Add-BitLockerKeyProtectorAdd-BitsFileAdd-BitsFileAdd-BitsFileAdd-BitsFile
#Multi-Protocol Unified Hello
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#PCT 1.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#SSL 2.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#SSL 3.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#TLS 1.0
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#TLS 1.1
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" | Out-Null

#TLS 1.2
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name "Enabled" -Value "1" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name "DisabledByDefault" -Value "0" -PropertyType "DWORD" | Out-Null
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name "Enabled" -Value "1" -PropertyType "DWORD" | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name "DisabledByDefault" -Value "0" -PropertyType "DWORD" | Out-Null

#Collect Error and Warning events from SChannel provider
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name "EventLogging" -Value "3" | Out-Null

Write-Host "SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 are DISABLED." -ForegroundColor Red
Write-Host "TLS 1.2 is ENABLED.`n" -ForegroundColor Green

#Strong Auth For .NET 
Write-Host "Verifying whether .NET Frameworks exists..."
#64-bit apps
if(Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework')
{
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" | Out-Null
    Write-Color -Text "64-bit .NET ", "OK!" -Color White,Green 
}
else
{
    Write-Warning ".NET Framework has not been found."
}
#32-bit apps
if(Test-Path -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework')
{
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" | Out-Null
    Write-Color -Text "32-bit .NET ", "OK!" -Color White,Green
}

# Ciphers Suites
Write-Color -Text "`nBacking up Cipher Suites and ECC Curves. To revert run the powershell script at ","C:\tls.ps1 ","..." -Color White,Yellow,White
Set-Content -Path "C:\tls.ps1" -Value "### Run the following script to revert. ###`n"
$ciphers = "@("
ForEach($cipher in (Get-TlsCipherSuite))
{
	$ciphers = $ciphers + "`"" + $cipher.Name + "`","
}
$ciphers = $ciphers.TrimEnd(',') + ")"
Add-Content -Path "C:\tls.ps1" -Value "`$ciphers=$ciphers"
$ciphers = "@("
ForEach($ecc in (Get-TlsEccCurve))
{
	$ciphers = $ciphers + "`"" + $ecc + "`","
}
$ciphers = $ciphers.TrimEnd(',') + ")"
Add-Content -Path "C:\tls.ps1" -Value "`$ecc=$ciphers"
Add-Content -Path "C:\tls.ps1" -Value "ForEach(`$cipher in `$ciphers)`n`{`n`tEnable-TlsCipherSuite -Name `$cipher`n`}`nForEach(`$curve in `$ecc)`n`{`n`tEnable-TlsEccCurve -Name `$curve`n`}"
Start-Process -FilePath "C:\Windows\System32\attrib.exe" -ArgumentList @("+h","C:\tls.ps1")

if((Get-ComputerInfo).WindowsProductName -like "Windows Server 2022*")
{
    #Windows Server 2022 Ciphers and Curves
    #Disable current cipher suites and ecc curves
    ForEach($cipher in (Get-TlsCipherSuite))
    {
        Disable-TlsCipherSuite -Name $cipher.Name
    }
    ForEach($ecc in (Get-TlsEccCurve))
    {
        Disable-TlsEccCurve -Name $ecc
    }
    $ciphers = @("TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256")
    $curves = @("nistP521","NistP384","NistP256")

    #Enable strong cipher suites and ecc curves
    ForEach($cipher in $ciphers)
    {
        Enable-TlsCipherSuite -Name $cipher
    }
    ForEach($ecc in $curves)
    {
        Enable-TlsEccCurve -Name $ecc
    }

    #Diffie-Hellman & RSA key bit length
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" | Out-Null
}
elseif ((Get-ComputerInfo).WindowsProductName -like "Windows Server 201[69]*")
{
    #Windows Server 2019 and 2016 Ciphers and Curves
    #Disable current cipher suites and ecc curves
    ForEach($cipher in (Get-TlsCipherSuite))
    {
        Disable-TlsCipherSuite -Name $cipher.Name
    }
    ForEach($ecc in (Get-TlsEccCurve))
    {
        Disable-TlsEccCurve -Name $ecc
    }
    
    $ciphers = @("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256")
    $ecc = @("nistP521","NistP384","NistP256")

    #Enable strong cipher suites and ecc curves
    ForEach($cipher in $ciphers)
    {
        Enable-TlsCipherSuite -Name $cipher
    }
    ForEach($ecc in $curves)
    {
        Enable-TlsEccCurve -Name $ecc
    }

    #Diffie-Hellman & RSA key bit length
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" | Out-Null
}
elseif (((Get-ComputerInfo).WindowsProductName -like "Windows Server 2012*") -or ((Get-ComputerInfo).WindowsProductName -like "Windows Server 2008[rR]2*"))
{
    #Windows Server 2012R2, 2012 and 2008R2 Ciphers and Curves
    #Disable current cipher suites and ecc curves
    ForEach($cipher in (Get-TlsCipherSuite))
    {
        Disable-TlsCipherSuite -Name $cipher.Name
    }
    ForEach($ecc in (Get-TlsEccCurve))
    {
        Disable-TlsEccCurve -Name $ecc
    }
    
    $ciphers = @("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256","TLS_DHE_DSS_WITH_AES_256_CBC_SHA256","TLS_DHE_DSS_WITH_AES_128_CBC_SHA256")
    $ecc = @("nistP521","NistP384","NistP256")

    #Enable strong cipher suites and ecc curves
    ForEach($cipher in $ciphers)
    {
        Enable-TlsCipherSuite -Name $cipher
    }
    ForEach($ecc in $curves)
    {
        Enable-TlsEccCurve -Name $ecc
    }
}
else
{
    Write-Warning "Not supported."
}

# Enable SMB Signing
#Client
Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
#Server
Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
