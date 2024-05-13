<#
    .SYNOPSIS 
    The purpose of the script, is to help system administrators harden basic security components of Windows systems and patch or disable deprecated protocols which may be potentially exploited.    
    .NOTES
    Execution is also supported via web invokation in GitHub. Please check EXAMPLE 2.
    ### Contributors ###
    1. Stefanos Daniil

    ### Credits ###
    1. Write-Color Function @ https://stackoverflow.com/questions/2688547/multiple-foreground-colors-in-powershell-in-one-command
    .PARAMETER SMB
    The SMB option enables SMB signing. Omit to ignore the functionality.
    .PARAMETER LLMNR
    The LLMNR option disables the Link-Local Multicast Name Resolution protocol which is considered to be deprecated and insecure. Omit to ignore the functionality.
    .PARAMETER NBT
    The NBT option disable the NetBIOS over TCP/IP which is considered to be deprecated and insecure. Omit to ignore the functionality.
    .PARAMETER NTLM
    The NTLM option enforces NTLMv2 protocol to all ingress and egress communications. Furthermore it denies incoming NT and NTLMv1 protocols as authentication mechanisms.
    .PARAMETER RDP
    The RDP option enables NLA (Network Level Authentication) in Remote Desktop connections. In addition it increases the encryption level in RDP connections to be compliant with FIPS standards.

    .FUNCTIONALITY 
    harden.ps1 <[-TLS | -SMB | -LLMNR | -NBT | -NTLM | -RDP]>

    .EXAMPLE
    harden.ps1 -TLS -NBT
    .EXAMPLE
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force;Invoke-Expression "& { $((Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/stefanos007/PSScripts/main/harden.ps1').Content)} -TLS" 
    
    .LINK
    1. About TLS cmdlets @ https://learn.microsoft.com/en-us/powershell/module/tls/?view=windowsserver2022-ps
    .LINK
    2. TLS support on Windows platforms @ https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-
    .LINK
    3. TLS registry settings @ https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
    .LINK
    4. Cipher suites supported on Windows platforms @ https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel
    .LINK
    5. Demystifying SChannel @ https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233
    .LINK
    6. Enforce NTLMv2 @ https://kb.iu.edu/d/atcb
    .LINK
    7. RDP encryption level @ https://learn.microsoft.com/en-us/answers/questions/191055/how-to-changeterminal-services-encryption-level-to
#>

param 
(
    [switch]$TLS,
    [switch]$SMB,
    [switch]$LLMNR,
    [switch]$NBT,
    [switch]$NTLM,
    [switch]$RDP
)

if($PSBoundParameters.Count -eq 0)
{
    Write-Warning "You should set at least one (1) parameter. Run `"Get-Help`" for examples."
    exit
}

function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) 
{
    for ($i = 0; $i -lt $Text.Length; $i++) 
    {
        Write-Host $Text[$i] -Foreground $Color[$i] -NoNewLine
    }
    Write-Host
}

#Backup current TLS ECC and Ciphers configuration
function Backup-Tls
{
    if(!(Test-Path -Path "C:\Harden Backup\tls.ps1"))
    {
        Write-Color -Text "`nBacking up Cipher Suites and ECC Curves. To revert run the powershell script at ","C:\Harden Backup\tls.ps1 ","..." -Color White,Yellow,White
        Set-Content -Path "C:\Harden Backup\tls.ps1" -Value "### Run the following script to revert. ###`n"
        $ciphers = "@("
        ForEach($cipher in (Get-TlsCipherSuite))
        {
            $ciphers = $ciphers + "`"" + $cipher.Name + "`","
        }
        $ciphers = $ciphers.TrimEnd(',') + ")"
        Add-Content -Path "C:\Harden Backup\tls.ps1" -Value "`$ciphers=$ciphers"
        $ciphers = "@("
        ForEach($ecc in (Get-TlsEccCurve))
        {
            $ciphers = $ciphers + "`"" + $ecc + "`","
        }
        $ciphers = $ciphers.TrimEnd(',') + ")"
        Add-Content -Path "C:\Harden Backup\tls.ps1" -Value "`$ecc=$ciphers"
        Add-Content -Path "C:\Harden Backup\tls.ps1" -Value "ForEach(`$cipher in `$ciphers)`n`{`n`tEnable-TlsCipherSuite -Name `$cipher`n`}`nForEach(`$curve in `$ecc)`n`{`n`tEnable-TlsEccCurve -Name `$curve`n`}"
    }
}

if(New-Item -Path "C:\" -Name "Harden Backup" -ItemType Directory -ErrorAction Ignore)
{
    Start-Process -FilePath "C:\Windows\System32\attrib.exe" -ArgumentList @("+h",'"C:\Harden Backup"')
    Write-Host "Configuration will be backed up on `"C:\Harden Backup`" directory."
}

if($TLS)
{
    #Backup SChannel
    Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",'"C:\Harden Backup\protocols.reg"',"/y")

    #Multi-Protocol Unified Hello
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #PCT 1.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #SSL 2.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #SSL 3.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #TLS 1.0
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #TLS 1.1
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name "Enabled" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name "DisabledByDefault" -Value "1" -PropertyType "DWORD" -Force | Out-Null

    #TLS 1.2
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name "Enabled" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name "DisabledByDefault" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name "Enabled" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name "DisabledByDefault" -Value "0" -PropertyType "DWORD" -Force | Out-Null

    #Collect Error and Warning events from SChannel provider
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name "EventLogging" -Value "3" -Force | Out-Null

    Write-Host "SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 are DISABLED." -ForegroundColor Red
    Write-Host "TLS 1.2 is ENABLED.`n" -ForegroundColor Green

    #Strong Auth For .NET 
    Write-Host "Verifying whether .NET Frameworks exists..."
    #64-bit apps
    if(Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework')
    {
        #Backup .NET 64-bit
        Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SOFTWARE\Microsoft\.NETFramework",'"C:\Harden Backup\dotNETx64.reg"',"/y")

        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        Write-Color -Text "64-bit .NET ", "OK!" -Color White,Green 
    }
    else
    {
        Write-Warning ".NET Framework has not been found."
    }
    #32-bit apps
    if(Test-Path -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework')
    {
        #Backup .NET 32-bit
        Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework",'"C:\Harden Backup\dotNETx32.reg"',"/y")

        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name "SchUseStrongCrypto" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name "SystemDefaultTlsVersions" -Value "1" -PropertyType "DWORD" -Force | Out-Null
        Write-Color -Text "32-bit .NET ", "OK!" -Color White,Green
    }

    if(((Get-ComputerInfo).WindowsProductName -like "Windows Server 2022*") -or ((Get-ComputerInfo).OsName -like "*Windows 11*"))
    {
        Backup-Tls
        
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
        $curves = @("nistP521","NistP384","NistP256","curve25519")

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
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" -Force | Out-Null

        Write-Color -Text "Strong ciphers and curves have been successfully set. Use `"Get-TlsCipherSuite`" and `"Get-TlsEccCurve`" to verify.`nMinimum Diffie-Hellman and RSA client key bit length is set at ","2048 bits.`n" -Color Green,Yellow
    }
    elseif (((Get-ComputerInfo).WindowsProductName -like "Windows Server 201[69]*") -or ((Get-ComputerInfo).OsName -like "*Windows 10*"))
    {
        Backup-Tls
        
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
        $curves = @("nistP521","NistP384","NistP256","curve25519")

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
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS' -Name "ClientMinKeyBitLength" -Value "0x800" -PropertyType "DWORD" -Force | Out-Null

        Write-Color -Text "Strong ciphers and curves have been successfully set. Use `"Get-TlsCipherSuite`" and `"Get-TlsEccCurve`" to verify.`nMinimum Diffie-Hellman and RSA client key bit length is set at ","2048 bits.`n" -Color Green,Yellow
    }
    elseif (((Get-ComputerInfo).WindowsProductName -like "Windows Server 2012*") -or ((Get-ComputerInfo).WindowsProductName -like "Windows Server 2008[rR]2*"))
    {
        #Windows Server 2012R2, 2012 and 2008R2 Ciphers and Curves
        #Backup ciphers & ecc
        Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002",'"C:\Harden Backup\ciphers-ecc.reg"',"/y")
        $ciphers = @("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256","TLS_DHE_DSS_WITH_AES_256_CBC_SHA256","TLS_DHE_DSS_WITH_AES_128_CBC_SHA256")
        $curves = @("nistP521","NistP384","NistP256","curve25519")

        #Enable strong cipher suites and ecc curves
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' -Name "Functions" -Value $ciphers -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002' -Name "EccCurves" -Value $curves -PropertyType "Multistring" -Force | Out-Null
    }
    else
    {
        Write-Warning "Unsupported operating system."
    }
}

#Enable SMB Signing & disable SMB1.x
if($SMB)
{
    #Client
    Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
    #Server
    Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -AuditSmb1Access $true -EnableSMB1Protocol $false -EnableSMB2Protocol $true -Force
    Write-Color -Text "SMBv1 is", " DISABLED."," SMB Signing is enabled and set to", " REQUIRED." -Color White,Red,White,Green
}

#Disable LLMNR
if($LLMNR)
{
    if(Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient')
    {
        #Backup DNS Client configuration
        Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",'"C:\Harden Backup\DNS.reg"',"/y")

        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name "EnableMultiCast" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    }
    else
    {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name "EnableMultiCast" -Value "0" -PropertyType "DWORD" -Force | Out-Null
    }
    #Set-NetFirewallRule -Name "FPS-LLMNR-In-UDP" -Profile Any -Enabled False
    #Set-NetFirewallRule -Name "FPS-LLMNR-Out-UDP" -Profile Any -Enabled True -Action Block
    Write-Color -Text "Link-Local Multicast Name Resolution(LLMNR) has been", " DISABLED." -Color White,Red
}

#Disable NBT-NS
if($NBT)
{
    #Backup NETBIOS configuration in interfaces
    Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces",'"C:\Harden Backup\interfaces.reg"',"/y")

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*' -Name "NetbiosOptions" -Value "2" -Force | Out-Null
    #Set-NetFirewallRule -Name @("FPS-NB_Session-In-TCP-NoScope","FPS-NB_Datagram-In-UDP-NoScope","FPS-NB_Name-In-UDP-NoScope") -Profile Domain -Enabled False
    #Set-NetFirewallRule -Name @("FPS-NB_Session-Out-TCP-NoScope","FPS-NB_Datagram-Out-UDP-NoScope","FPS-NB_Name-Out-UDP-NoScope") -Profile Domain -Enabled True -Action Block
    Write-Color -Text "NetBIOS Over TCP/IP(NBT-NS) has been", " DISABLED." -Color White,Red
}

#Disable LM & NTLMv1 & Enforce NTLMv2
if($NTLM)
{
    #Backup LSA configuration
    Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export","HKLM\SYSTEM\CurrentControlSet\Control\Lsa",'"C:\Harden Backup\LSA.reg"',"/y")
    
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value "5" -PropertyType "DWORD" -Force | Out-Null
    Write-Color -Text "Authentication protocols ","LM ","&"," NTLMv1"," have been disabled and denied."," NTLMv2 is enforced." -Color White,Red,White,Red,White,Green
}

#Increase RDP encryption level to 4 (FIPS-compliant) & Enable Network Level Authentication (NLA)
if($RDP)
{
    #Backup RDP configuration
    Start-Process -FilePath "C:\Windows\System32\reg.exe" -ArgumentList @("export",'"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"','"C:\Harden Backup\RDP.reg"',"/y")
    
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value "1" -PropertyType "DWORD" -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value "2" -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -Value "4" -Force | Out-Null
    Write-Color -Text "RDP minimum encryption level has been set on ","4 (FIPS compliant)" -Color White,Green
}
