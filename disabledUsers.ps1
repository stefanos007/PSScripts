$eventDisabled=Get-WinEvent -FilterHashtable @{LogName = "Security"; ID = 4725} | ForEach-Object {
    $eventXML=([xml]$_.ToXml())

    $disabled=$eventXML.Event.EventData.Data[0] | Select-Object -ExpandProperty "#text"  # Target Username
    $disabler=$eventXML.Event.EventData.Data[4] | Select-Object -ExpandProperty "#text" # Source Usernam
    $dateDisabled=$_.TimeCreated.ToString().Split(" ")[0]

    $isNull=(Get-ADUser -Filter {samAccountName -eq $disabled} -Properties *).disabledTimestamp

    if($isNull -eq $null){
        Set-ADUser -Identity "$disabled" -Description "The user has been disabled by PROXIMA\$disabler at $dateDisabled" -Add @{disabledTimestamp=$dateDisabled}
    }  
}