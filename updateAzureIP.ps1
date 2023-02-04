Import-Module Az.Network
Connect-AzAccount

$public=(Invoke-WebRequest ifconfig.me/ip).Content.Trim()
$nsg=Get-AzNetworkSecurityGroup -Name "Altairnsg933" -ResourceGroupName "Orion"
$rule=$nsg | Get-AzNetworkSecurityRuleConfig -Name "RDP"

Set-AzNetworkSecurityRuleConfig `
-Name $rule.Name `
-Access $rule.Access`
-Protocol $rule.Protocol `
-Direction $rule.Direction `
-Priority $rule.Priority `
-SourceAddressPrefix "$public", "195.46.21.4" `
-SourcePortRange $rule.SourcePortRange `
-DestinationAddressPrefix $rule.DestinationAddressPrefix `
-DestinationPortRange "53", "389", "443", "636", "3268", "3269", "3389" `
-NetworkSecurityGroup $nsg

$nsg | Set-AzNetworkSecurityGroup