function Get-RDPAccess($command)
{
	$localhtmlBuilder = "<div class='tables'><h2>[RDP Access]</h2><table><tr><th>Timestamp</th><th>Client IP</th></tr>"
	$localhtmlBuilder += $command
	$localhtmlBuilder += "</table></div><br>"
	return $localhtmlBuilder
}

function Get-Shutdowns($command)
{
	$localhtmlBuilder = "<div class='tables'><h2>[Shutdown Events]</h2><table><tr><th>Timestamp</th><th>Description</th></tr>"
	$localhtmlBuilder += $command
	$localhtmlBuilder += "</table></div><br>"
	return $localhtmlBuilder
}
