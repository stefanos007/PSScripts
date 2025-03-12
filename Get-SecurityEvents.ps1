[CmdletBinding()]param(
    [Parameter(ParameterSetName = "TargetOnly", Mandatory = $true)]
    [Parameter(ParameterSetName = "Both", Mandatory = $true)]
    [string[]]$Target,
    [Parameter(ParameterSetName = "SubjectOnly", Mandatory = $true)]
    [Parameter(ParameterSetName = "Both", Mandatory = $true)]
    [string[]]$Subject,
    [Parameter(ParameterSetName = "Both", Mandatory = $true)]
    [Parameter(DontShow)]
	[ValidateSet("or","and")]
	[string]$Operation,
	[string]$Id,
	[int]$MaxEvents=25
)

if(!([string]::IsNullOrEmpty($Id)))
{
	if ($PSCmdlet.ParameterSetName -eq "Both") 
	{
		$query = "*[System[EventID=$Id] and (("
		$Target | foreach { $query += "EventData[Data[@Name='TargetUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + ") $Operation ("
		$Subject | foreach { $query += "EventData[Data[@Name='SubjectUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + "))]"
	}
	if ($PSCmdlet.ParameterSetName -eq "TargetOnly") 
	{
		$query = "*[System[EventID=$Id] and (("
		$Target | foreach { $query += "EventData[Data[@Name='TargetUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + "))]"
	}
	if ($PSCmdlet.ParameterSetName -eq "SubjectOnly") 
	{
		$query = "*[System[EventID=$Id] and ((" 
		$Subject | foreach { $query += "EventData[Data[@Name='SubjectUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + "))]"
	}
}
else
{
	if ($PSCmdlet.ParameterSetName -eq "Both") 
	{
		$query = "*[("
		$Target | foreach { $query += "EventData[Data[@Name='TargetUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + ") $Operation ("
		$Subject | foreach { $query += "EventData[Data[@Name='SubjectUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + ")]"
	}
	if ($PSCmdlet.ParameterSetName -eq "TargetOnly") 
	{
		$query = "*[("
		$Target | foreach { $query += "EventData[Data[@Name='TargetUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + ")]"
	}
	if ($PSCmdlet.ParameterSetName -eq "SubjectOnly") 
	{
		$query = "*[(" 
		$Subject | foreach { $query += "EventData[Data[@Name='SubjectUserName']=`'$_`'] or " }
		$query = $query.TrimEnd(" or ") + ")]"
	}
}

$htmlBuilder = "<html><head><style>table, th, td {  border: 1px solid;border-collapse: collapse; }th, td { padding: 15px; } tr:nth-child(even) {background-color: #f2f2f2;} tr:hover {background-color: coral;} .tables { margin: auto; }</style></head><body>"
$htmlBuilder += "<div class='tables'><h2>[$($(hostname).ToUpper())]</h2><table><tr><th>Property</th><th>Value</th></tr>"

foreach($log in (Get-WinEvent -FilterXPath $query -LogName Security -MaxEvents $MaxEvents))
{
	$xmlLog = $([xml]$log.ToXml()).Event
	$htmlBuilder += "<tr><th colspan='2'>ID: $($log.Id) <br> Created On: $($log.TimeCreated) <br> Level: $($log.LevelDisplayName) <br> Process ID: $($xmlLog.System.Execution.ProcessID) </th></tr>"
	$xmlLog.EventData.Data | foreach{ $htmlBuilder += "<tr><td><b>$($_.Name)</b></td><td>$($_.'#text')</td></tr>" }
}
$htmlBuilder += "</table></body></html>"
Out-File -FilePath "C:\Users\$([Environment]::UserName)\Desktop\sec_events.html" -InputObject $htmlBuilder -Force