Import-Module ".\troubleshooter.psm1"

if(!(New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -and ([System.Environment]::UserName -ne "SYSTEM"))
{
	Write-Warning -Message "Insufficient permissions or running as SYSTEM principal."
	exit(1)
}

$commands = @{
	"RDP Connections" = Get-WinEvent -FilterHashtable @{"LogName" = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; "Id" = "131"} | % { $log = [xml]$_.ToXml();$log = $log.Event.EventData.Data[1]."`#text" -replace "[\[\]]","";"<tr><td>$([datetime]$_.TimeCreated)</td><td>$log</td></tr>" }
	"Shutdowns" = Get-WinEvent -FilterHashtable @{"LogName" = "System"; "ProviderName" = "User32"} | % { "<tr><td>$([datetime]$_.TimeCreated)</td><td>$([string]$_.Message)</td></tr>" }
	"OS ver" = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Select-Object ProductName,DisplayVersion,CurrentBuild,UBR).psobject.properties.value -join " "
	"Sys Model" = ((Get-CimInstance -ClassName Win32_ComputerSystem) | Select-Object Manufacturer,SystemFamily,Model).psobject.properties.value -join " "
	"SN" = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
	"Uptime" = (New-TimeSpan -Start (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime -End (Get-Date)).ToString("dd' Days 'hh' Hours 'mm' Minutes 'ss' Seconds'")
}

$htmlBuilder = "<html><head><style>table, th, td {  border: 1px solid; }th, td { padding: 15px; } tr:nth-child(even) {background-color: #f2f2f2;} tr:hover {background-color: coral;} .tables { margin: auto; }</style></head><body>"

$htmlBuilder += "<div class='tables'><h2>[System Info]</h2><table>"
$htmlBuilder += "<tr><td><b>OS Version</b></td><td>$($commands["OS ver"])</td></tr>"
$htmlBuilder += "<tr><td><b>Uptime</b></td><td>$($commands["Uptime"])</td></tr>"
$htmlBuilder += "<tr><td><b>System Model</b></td><td>$($commands["Sys Model"])</td></tr>"
$htmlBuilder += "<tr><td><b>Serial Number</b></td><td>$($commands["SN"])</td></tr>"
$htmlBuilder += "</table></div><br>"

if($PSBoundParameters.Count -eq 0)
{
	$htmlBuilder += Get-RDPAccess $commands["RDP Connections"]
	$htmlBuilder += Get-Shutdowns $commands["Shutdowns"]
}

$htmlBuilder += "</body></html>"
Out-File -FilePath "C:\Users\$([Environment]::UserName)\Desktop\info.html" -InputObject $htmlBuilder -Force