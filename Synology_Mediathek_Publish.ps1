#region Global Settings
$future = $true # Search for future airings ?
$NumberOfDaysBack = 3000 # Number of days to search back in Mediathekviewweb
$MinimumSize = 100000 # Minimum Size of the MP4 file, trying to remove stupid sizes
#$MinimumLength = "00:15:00" # Minimum length of the Airing in HH:MM:SS
$MinimumLength = 900 # Minimum length in Seconds
$MaxReturnEntries = 25 #Maximum entries, that will be returned by Mediathekwebview
$ForceQueryRerunMinutes = 30 # Check fo LastRunTime and if it is less then this Minutes, dont ask the Mediathek again. Only Works if PS Session stays active.
$ListHdIfBelowBytesSec = 185kb # Also list HD Stream im KB/Sec are below this value
$MaxFinishedBeforeDeleteQuestion = 4
$SaveMediathekResultToFile = $true
$MaxTopicLength = 25
$MaxRestRetries = 20
# Replace with your URI, can be internal or external URI.
# Standard Ports: 5000 : HTTP, 5001 : HTTPS (strongly recommended!!!)
# If you are using SSL make sure the SSL Cert matches!
$SynologyURI = "https://mysynology.home.net:5001" 
$SynologyWakeupAfterSearch = $true
$SynologyMacAddress = "00:11:22:33:44:55"
$SynologyWakeUpBroadcastAddress = "192.168.0.255"

#region Display Init
#Section to define, which rows should be shown in which type of Gridview
$DisplayInformationsDesktop = @(
    "Index" #Never remove Index!
    "channel"
    "topic"
    "title"
    "timestamp"
    "duration"
    "size"
    "description"
)
$DisplayInformationsConsole = @(
    "Index" #Never remove Index!
    "channel"
    "topicshort"
    "title"
    "timestamp"
    "duration"
    "size"
)
$StartTime = Get-Date
$TimeDelta = "[Math]::Round((New-TimeSpan -Start `$StartTime -End (Get-Date)).TotalSeconds,2)"
#endregion

#region Character Replace Table
# German Umlauts have to be replaced and the table lists them with charvalues, as text format conversion happens too often
# We have to replace umlauts as the Syno-API are not consistent in handling umlauts!
# Additionally we are replacing some characters which will not work in some filesystems. If you find additional ones add them here!
$CharacterReplaceTable = @{
    '|'                = '_'
    ':'                = '_'
    '/'                = '_'
    '?'                = '_'
    '&'                = 'und'
    'á'                = 'a'
    '"'                = "_"
    [string][char]252  = 'ue'
    [string][char]228  = 'ae'
    [string][char]246  = 'oe'
    [string][char]223  = 'ss'
    [string][char]8211 = '-'
}
#endregion Character Replace Table

#region Filter Airings with
#titles with these keywords will excluded. If you want any of them, remove the lines or add if you find some annoying lines
$ExcludeTitlesKeywords = @(
    "Audiodeskription"
    "Geb$([string][char]228)rdensprache"
    "H$([string][char]246)rfassung"    
)
#endregion Filter Airings with

#region Synology Errorcodes
$SynoErrorCodes = @{
    Tasks          = @{
        '400' = "File upload failed"
        '401' = "Max number of tasks reached"
        '402' = "Destination denied"
        '403' = "Destination does not exist"
        '404' = "Invalid task id"
        '405' = "Invalid task action"
        '406' = "No default destination"
        '407' = "Set destination failed"
        '408' = "File does not exist"
    }
    Authentication = @{
        '400' = "No such account or incorrect password"
        '401' = "Account disabled"
        '402' = "Permission denied"
        '403' = "2-step verification code required"
        '404' = "Failed to authenticate 2-step verification code"
    }
    FileStation    = @{
        '400'  = "Invalid parameter of file operation"
        '401'  = "Unknown error of file operation"
        '402'  = "System is too busy"
        '403'  = "Invalid user do es this file operation"
        '404'  = "Invalid group do es this file operation"
        '405'  = "Invalid user and group do es this file operation"
        '406'  = "Can t get user /group information from the account server"
        '407'  = "Operation not permitted"
        '408'  = "No such file or directory"
        '409'  = "Non supported file system"
        '410'  = "Failed to connect internet based file system (ex: CIFS)"
        '411'  = "Read only file system"
        '412'  = "Filename too long in the non encrypt ed file system"
        '413'  = "Filename too long in the encrypt ed file system"
        '414'  = "File already exists"
        '415'  = "Disk quota exceeded"
        '416'  = "No space left on device"
        '417'  = "Input/output error"
        '418'  = "Illegal name or path"
        '419'  = "Illegal file name"
        '420'  = "Illegal file name on FAT files system"
        '421'  = "Device or resource busy"
        '599'  = "No such task of the file operation"
        '1100' = "Failed to create a folder. More information in <errors> object."
        '1101' = "The number of folder s to the parent folder would exceed the system limitation"    
        '1200' = "Failed to rename it. More information in <errors> object."
    }
}
#endregion Synology Errorcodes
#Remove Progressbar as it seems to have redrawing problemns on TMUX/Linux
$progressPreference = 'silentlyContinue'

#Functions
Function TimedPrompt {   
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Prompt,
        [Parameter()]
        [int32]
        $SecondsToWait,
        [Parameter()]
        [string]
        $PossibleChars,
        [Parameter()]
        [char]
        $DefaultChar
    )
    Write-Host -NoNewline $prompt
    do {
        $secondsCounter = 0
        $subCounter = 0
        While ( (!$host.ui.rawui.KeyAvailable) -and ($secondsCounter -lt $secondsToWait) ) {
            start-sleep -m 10
            $subCounter = $subCounter + 10
            if ($subCounter -eq 1000) {
                $secondsCounter++
                $subCounter = 0
                Write-Host -NoNewline "."
            }       
            If ($secondsCounter -eq $secondsToWait) { 
                Write-Host "`r`n"
                return $DefaultChar;
            }
        }
        $ChosenChar = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } until ($ChosenChar.Character -in [char[]]$PossibleChars)
    return $ChosenChar.Character;
}

function WakeUpNAS {
    param (
        [Parameter(Mandatory)]
        [String]
        $Mac,
        [Parameter(Mandatory)]
        [String]
        $BroadcastIP
    )
    #$Mac = "00:11:32:4b:0c:a5"
    $Broadcast = ([System.Net.IPAddress]::Broadcast)
    $Broadcast = [Net.IPAddress]::Parse($BroadcastIP)
    $MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_" }
    [Byte[]] $MagicPacket = (, 0xFF * 6) + ($MacByteArray * 16)
    $UdpClient = New-Object System.Net.Sockets.UdpClient
    $UdpClient.EnableBroadcast = $true
    $UdpClient.Connect($Broadcast, 9)
    $UdpClient.Send($MagicPacket, $MagicPacket.Length)
    $UdpClient.Close()
}


#endregion Global Settings

#region Airings to search for
# Translation of field-Settings in German:
# channel = Sender, topic = Thema, title = Titel
# Also look at: https://gist.github.com/bagbag/a2888478d27de0e989cf777f81fb33de

$MediathekDownload = @(
    @{ # Temporary Full Search
        Enabled        = $true 
        MediathekQuery = @{
            queries = @(
                @{fields = "topic", "title"; query = "Krauses" } 
            )
            sortBy = "timestamp"; sortOrder = "desc"; future = $future; size = $MaxReturnEntries
        }
        DownloadInfos  = @{
            Destination      = "Videostation/Download"
            AskForFileName   = $false
            AutoRename       = $true
            AutoRenameString = "timestamp", "topic", "title"
        }
        Tags             = @("Kinder", "Krimis", "Doku", "Filme") 
    }
    @{
        Enabled        = $true
        MediathekQuery = @{
            queries = @(
                @{fields = "topic"; query = "Die Chefin" }
                @{fields = "channel"; query = "zdf" }
            )
            sortBy = "timestamp"; sortOrder = "desc"; future = $future; size = $MaxReturnEntries
        }
        DownloadInfos  = @{
            Destination      = "Videostation/Krimis/Die_Chefin"
            AskForFileName   = $false
            AutoRename       = $true
            AutoRenameString = "timestamp", "title"
        }
    }    
)
#endregion Airings to search for


#region Out-ConsoleGridview Init
#Use Out-ConsoleGridView if Out-Gridview does not exist (typical Unix,Mac,...)
$OutGridView = $true
if (!(Get-Command -Name Out-GridView -ErrorAction SilentlyContinue)) {
    if (Get-Command -Name Out-ConsoleGridView) {
        $OutGridView = $false
    }
    else {
        Write-Error "Script running on non-Desktop, Please install Module Microsoft.PowerShell.ConsoleGuiTools for CmdLet Out-ConsoleGridView!"
        break
    }
}
#endregion Out-ConsoleGridview Init

#region Initialization Part
$ScriptFileName = $MyInvocation.MyCommand.Name
$ScriptFileNamePlain = [System.IO.Path]::GetFileNameWithoutExtension($ScriptFileName)

if ($OutGridView) {
    $AuswahlTag = @("Alle") + $MediathekDownload.Tags | Select-Object -Property @{Name = "Tags"; Expression = { $_ } } -Unique | Out-GridView -Title "Bitte entsprechend Tag auswählen oder Alle (ESC = Abbruch)" -Passthru -Outputmode Single
}
else {
    $AuswahlTag = @("Alle") + $MediathekDownload.Tags | Select-Object -Property @{Name = "Tags"; Expression = { $_ } } -Unique | Out-ConsoleGridView -Title "Bitte entsprechend Tag auswählen oder Alle (ESC = Abbruch)" -Outputmode Single
}
if (-Not $AuswahlTag) {
    break
    <#$AuswahlTag = [PSCustomObject]@{
        Tags = "Alle"
    }#>
}

if ($AuswahlTag.Tags -ne "Alle") {
    $MediathekDownload = $MediathekDownload | Where-Object { $AuswahlTag.Tags -in $_.Tags }
}

#region Script State initialization
$ForceReQuery = $true
if (Test-Path "$PSScriptRoot\$ScriptFileNamePlain.xml") {
    $ScriptState = Import-Clixml "$PSScriptRoot\$ScriptFileNamePlain.xml"
    if ($ScriptState.Credentials.GetNetworkCredential().Password -eq "" -or $ScriptState.Credentials.GetNetworkCredential().Password -eq "please_ask_for_password") {
        $Credentials = Get-Credential -UserName $Credentials.UserName -Title "Password not saved!" -Message "Please provide the Synology Password for this session!"
    }
    else {
        $Credentials = $ScriptState.Credentials
    }
    #$LastMediathekSearch = $ScriptState.LastMediathekSearch
    $ScriptState.LastMediathekSearch = Get-Date
    if ($ScriptState.LastSearchTag -ne $AuswahlTag.Tags) {
        Write-Host "Have to rescan Mediathek, as the Tag changed from last search!"
        $ScriptState.LastSearchTag = $AuswahlTag.Tags
    }
    else {
        $ForceReQuery = $false
    }
    $ScriptState | Export-Clixml "$PSScriptRoot\$ScriptFileNamePlain.xml" -Force -Encoding utf8
}
else {
    #Init the state-file
    $ScriptState = @{
        #LastMediathekSearch = Get-Date
    }
    $title = "Save the password?"
    $msg = "Do you want save the password to a file (No=Ask every start for the password) ?"
    $options = '&Yes', '&No'
    $default = 0  # 0=Yes, 1=No
    $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
    #Interim solution as Linux PWSH cannot reimport clixml with an empty password. We will fill it with this password, so we know that it is intended to not save the password!
    if ($response -eq 1) {
        $Credentials = Get-Credential -Title "Synology Credentials" -Message "Please provide the credentials for the Synology! They will not be saved to file!"
        $TmpPassword = ConvertTo-SecureString -AsPlainText -Force "please_ask_for_password"
        $SaveCredentials = new-object -typename System.Management.Automation.PSCredential -argumentlist ($Credentials.UserName, $TmpPassword)
    }
    else {
        $Credentials = Get-Credential -Title "Synology Credentials" -Message "Please provide the credentials for the Synology! Password will be saved!"
        $SaveCredentials = $Credentials
    }
    [System.Management.Automation.PSCredential]$ScriptState.Credentials = $SaveCredentials
    $ScriptState.LastSearchTag = $AuswahlTag.Tags
    $ScriptState | Export-Clixml "$PSScriptRoot\$ScriptFileNamePlain.xml" -Force -Encoding utf8
    #$LastMediathekSearch = $ScriptState.LastMediathekSearch.AddMinutes(0 - $ForceQueryRerunMinutes - 1) #Force Run as we init
}
#Take Last Query from Filetime of the cachefile
$FileInfo = Get-Item -Path "$PSScriptRoot\$ScriptFileNamePlain-QueryResult.xml" -ErrorAction SilentlyContinue
if ($FileInfo) {
    $LastMediathekSearch = $FileInfo.LastWriteTimeUtc
}
else {
    $LastMediathekSearch = (Get-Date).AddMinutes(0 - $ForceQueryRerunMinutes - 1).ToUniversalTime()
}
#endregion Script State initialization


#region Password Initialization
$SynologyUserName = $Credentials.Username
$SynologyPassword = $Credentials.GetNetworkCredential().Password
#endregion Password Initialization

#region Reload from Mediathek Query
if ($LastMediathekSearch) {
    if ((New-TimeSpan -Start $LastMediathekSearch -End (Get-date).ToUniversalTime()).TotalMinutes -le $ForceQueryRerunMinutes -and $SaveMediathekResultToFile) {
        if ((New-TimeSpan -Start $LastMediathekSearch -End (Get-ChildItem $PSScriptRoot\$ScriptFileName).LastWriteTimeUtc).TotalSeconds -gt 0 -or $ForceReQuery) {
            #$response = 0
            $response = "y"
            Write-Host "Forcing Requery!"
        }
        else {
            $DeltaTime = [Math]::Round((New-TimeSpan -Start $LastMediathekSearch -End (Get-Date).ToUniversalTime()).TotalMinutes, 2)
            Write-Host "Last Mediathek Search was $DeltaTime Minutes ago. Rerun?"
            $response = TimedPrompt -Prompt "Rerun Mediathek Search? (y/*n)" -SecondsToWait 5 -PossibleChars "ynYN" -DefaultChar "n"
            <#            $title = "Rerun Mediathek Search?"
        $DeltaTime = [Math]::Round((New-TimeSpan -Start $LastMediathekSearch -End (Get-Date).ToUniversalTime()).TotalMinutes, 2)
        $msg = "Last Mediathek Search was $DeltaTime Minutes ago. Rerun?"
        $options = '&Yes', '&No'
        $default = 1  # 0=Yes, 1=No
            $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)#>
        }
        if ($response -eq "n") {
            #No Rerun whished
            $MediathekRerunQuery = $false
            if ((Test-Path "$PSScriptRoot\$ScriptFileNamePlain-QueryResult.xml") -and $SaveMediathekResultToFile) {
                Write-Host "Will reimport the last Query Results!" -ForegroundColor Green
                $FilteredList = Import-Clixml -Path "$PSScriptRoot\$ScriptFileNamePlain-QueryResult.xml"
            }
            else {
                Write-Host "Have to run Query as there is no saved data!" -ForegroundColor Red
                $MediathekRerunQuery = $true
            }
        }
        else {
            #Rerun wished
            Write-Host "Info: Rerunning the query by request!" -ForegroundColor Yellow
            $MediathekRerunQuery = $true
        }
    }
    else {
        Write-Host "Info: Running query, as cache is too old or missing!" -ForegroundColor Yellow
        $MediathekRerunQuery = $true
    }
}
else {
    #No Last Run available so Query has to run
    $MediathekRerunQuery = $true
}
#endregion Reload from Mediathek Query

#endregion Initialization Part

#region Airings to search for
# Translation of field-Settings in German:
# channel = Sender, topic = Thema, title = Titel
$MediathekDownload = @(
    @{ # Temporary Full Search
        Enabled        = $true 
        MediathekQuery = @{
            queries = @(
                @{fields = "topic", "title"; query = "Krauses" } 
            )
            sortBy = "timestamp"; sortOrder = "desc"; future = $future; size = $MaxReturnEntries
        }
        DownloadInfos  = @{
            Destination      = "Videostation/Download"
            AskForFileName   = $false
            AutoRename       = $true
            AutoRenameString = "timestamp", "topic", "title"
        }
    }
    @{
        Enabled        = $true
        MediathekQuery = @{
            queries = @(
                @{fields = "topic"; query = "Die Chefin" }
                @{fields = "channel"; query = "zdf" }
            )
            sortBy = "timestamp"; sortOrder = "desc"; future = $future; size = $MaxReturnEntries
        }
        DownloadInfos  = @{
            Destination      = "Videostation/Krimis/Die_Chefin"
            AskForFileName   = $false
            AutoRename       = $true
            AutoRenameString = "timestamp", "title"
        }
    }    
)
#endregion Airings to search for

#region Mediathek-Queries
if ($MediathekRerunQuery) {
    $LastMediathekSearch = Get-Date
    #$FullList = @()
    #$FullList = New-Object -TypeName System.Collections.ArrayList
    $FullList = [System.Collections.Generic.List[System.Object]]@()
    $OutputList = [System.Collections.Generic.List[System.Object]]@()
    $FilmListTimeStamp = [datetime]::MinValue
    $Runtime = Measure-Command {
    foreach ($MediathekEntry in $MediathekDownload) {
            #$MediathekDownload | ForEach-Object -ThrottleLimit 1 -Parallel {
            #$MediathekEntry = $_
        if ($Null -eq $MediathekEntry.Enabled -or $MediathekEntry.Enabled -eq $true) {
                $OutputElement = @{
                    SearchFor = ($MediathekEntry.MediathekQuery.queries.query -join ',')
                }
            Write-Host "Mediathek search for: $($MediathekEntry.MediathekQuery.queries.query -join ',')"
            #As PS Core is working slightly different with ConvertTo-Json we have to check for desktop or core here
            if ($PSVersionTable.PSEdition -eq "Desktop") {
                $QueryJSON = $MediathekEntry.MediathekQuery | ConvertTo-Json -Depth 20
            }
            else {
                #Core supports a new escaping, which is needed for umlauts in core, but not in 5.1
                $QueryJSON = $MediathekEntry.MediathekQuery | ConvertTo-Json -Depth 20 -EscapeHandling EscapeNonAscii
            }
            $Antwort = Invoke-RestMethod -Method Post -Uri "https://mediathekviewweb.de/api/query" -Body $QueryJSON -ContentType "text/plain"
            $DownloadInfos = $MediathekEntry.DownloadInfos.Clone()
            $DownloadInfos.DownloadStatus = "None"
            $DownloadInfos.DownloadFileName = ""
            $DownloadInfos.NewFileName = ""
                $AntwortConverted = @($Antwort.result.results | Select-Object Channel, topic, title, @{Label = "timestamp"; Expression = { ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($_.timestamp).ToLocalTime() } }, @{Label = "duration"; Expression = { [timespan]::FromSeconds($_.duration) } }, @{Label = "filmlisteTimestamp"; Expression = { ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($_.filmlisteTimestamp).ToLocalTime() } }, size, description, url_website, url_video, url_video_hd, @{Label = "DownloadInfos"; Expression = { $DownloadInfos.Clone() } })
            if (!$AntwortConverted) {
                    Write-Host "-------------------------------------------------------------------------------------------------------------------------"
                continue
            }
                if ($AntwortConverted.Count -eq $MediathekEntry.MediathekQuery.size) {
                    #$MaxReturnEntries
                Write-Host "Found $($AntwortConverted.Count) entries WARNING Max entries reached!!!" -ForegroundColor Yellow
                if ((New-TimeSpan -Start $AntwortConverted[-1].timestamp -End (Get-Date)).TotalDays -gt $NumberOfDaysBack) {
                    Write-Host "But all is safe, as all elements with date limit are downloaded!" -ForegroundColor Green
                        $OutputElement["DatesOK"] = $true
                }
                else {
                    Write-Host "Could not get all elements inside of date limit!!!! Oldest entry is:$($AntwortConverted[-1].timestamp)" -ForegroundColor Red
                        $OutputElement["DatesOK"] = $false
                }
            }
                Write-Host "Mediathekquery: totalResults: $($Antwort.result.queryInfo.totalResults) Returned: $($Antwort.result.queryInfo.resultCount) Filmliste Timestamp: $((Get-Date '01/01/1970').ToLocalTime().AddSeconds($Antwort.result.queryInfo.filmlisteTimestamp)) Oldest: $($AntwortConverted[-1].timestamp)"
                $OutputElement["Total"] = ($Antwort.result.queryInfo.totalResults)
                $OutputElement["Results"] = $Antwort.result.queryInfo.resultCount
                $OutputElement["Oldest"] = $AntwortConverted[-1].timestamp
                $FilmListTimeStamp = ((Get-Date '01/01/1970').ToLocalTime().AddSeconds($Antwort.result.queryInfo.filmlisteTimestamp))
                #$FullList += $AntwortConverted | where-object { (New-TimeSpan -Start $_.timestamp -End (Get-Date)).TotalDays -lt $NumberOfDaysBack }
                [Array]$AntwortConverted = $AntwortConverted | where-object { (New-TimeSpan -Start $_.timestamp -End (Get-Date)).TotalDays -lt $NumberOfDaysBack }
                if ($MediathekEntry.FilterOutTitleMatch) {
                    [Array]$AntwortConverted = $AntwortConverted | where-object { $_.title -notmatch $MediathekEntry.FilterOutTitleMatch }
                }
                if ($AntwortConverted) {
                    $FullList.AddRange($AntwortConverted)
                    $OutputList.Add([pscustomobject]$OutputElement)
                }
        }
        else {
            Write-Host "Mediathek search DISABLED for: $($MediathekEntry.MediathekQuery.queries.query -join ',')"
            }
            Write-Host "-------------------------------------------------------------------------------------------------------------------------"
        }
    }
    $OutputList | select-object SearchFor, Total, Results, Oldest | Format-Table
    Write-Host "Film List on Mediathek last updated: $FilmListTimeStamp"
    Write-Host "Search for airing took $($Runtime.TotalSeconds) Sec"
    #Now filter the output by some criterias

    #Skip if Array with Keywords is empty
    if ($ExcludeTitlesKeywords.Count -gt 0) {
        $FilteredList = $FullList | where-object { $_.title -notmatch ($ExcludeTitlesKeywords -join "|") }
    }
    else {
        $FilteredList = $FullList
    }
    #Check if any airings are below the quality rules and then also add the HD-Version
    Write-Host "Searching for HD airings where needed!"
    if ($PSVersionTable.PSEdition -eq "Desktop") {
        Write-Host "Detected Desktop Edition of Powershell, will use slow non-parallel search"
        #$AddedHD = New-Object -TypeName System.Collections.ArrayList
        $AddedHD = [System.Collections.Generic.List[System.Object]]@()
        foreach ($Entry in $FilteredList) {
            if (($entry.size / $Entry.duration.TotalSeconds) -lt $ListHdIfBelowBytesSec -and ($Null -eq $Entry.DownloadInfos.SearchForHD -or $Entry.DownloadInfos.SearchForHD -eq $true)) {
                #if (($entry.size / $Entry.duration.TotalSeconds) -lt $ListHdIfBelowBytesSec) {
                try {
                    [long]$HDVideoSize = ((Invoke-WebRequest -Method Head -URI $Entry.url_video_hd).Headers.'Content-Length')[0]
                    $NewHD = $Entry.PSObject.Copy()
                    $NewHD.DownloadInfos = $Entry.DownloadInfos.psobject.Copy()
                    $NewHD.size = $HDVideoSize
                    $NewHD.url_video = $NewHD.url_video_hd
                    $NewHD.title = $NewHD.title + " (HD)"
                    #$NewHD.DownloadInfos.NewFileName = $NewHD.DownloadInfos.NewFileName + " (HD)"
                    $Null = $AddedHD.Add($NewHD)
                }
                catch {
                }
            }
        }
    }
    else {
        Write-Host "Detected Core Edition of Powershell, will use parallel search"
        $Runtime = Measure-Command {
            $AddedHD = $FilteredList | Where-Object { (($_.size / $_.duration.TotalSeconds) -lt $ListHdIfBelowBytesSec -and ($Null -eq $_.DownloadInfos.SearchForHD -or $_.DownloadInfos.SearchForHD -eq $true) -or $_.DownloadInfos.ForceHDSearch) } | ForEach-Object -ThrottleLimit 12 -Parallel {
                $Entry = $_
                #$ListHdIfBelowBytesSec = $Using:ListHdIfBelowBytesSec
                #if (($entry.size / $Entry.duration.TotalSeconds) -lt $ListHdIfBelowBytesSec -and ($Null -eq $Entry.DownloadInfos.SearchForHD -or $Entry.DownloadInfos.SearchForHD -eq $true)) {
                try {
                    #    Write-Host $Entry.title
                    
                    [long]$HDVideoSize = ((Invoke-WebRequest -Method Head -URI $Entry.url_video_hd).Headers.'Content-Length')[0]
                    $NewHD = $Entry.PSObject.Copy()
                    $NewHD.DownloadInfos = $Entry.DownloadInfos.psobject.Copy()
                    $NewHD.size = $HDVideoSize
                    $NewHD.url_video = $NewHD.url_video_hd
                    $NewHD.title = $NewHD.title + " (HD)"
                    #$Null=$AddedHD.Add($NewHD)
                    $NewHD
                }
                catch {
                }
                #}
            }
        }
    }
    Write-Host "Adding $($AddedHD.Count) HD airings to the list! (Search took: $($Runtime.TotalSeconds))"
    $FilteredList += $AddedHD
    #Remove all entries that have a too small size (eg. 0)
    Write-Host "Filter the list by MinimumSize $MinimumSize"
    $FilteredList = $FilteredList | where-object { $_.size -gt $MinimumSize <#-and $_.duration -gt $MinimumLength#> } 
    $FilteredList = $FilteredList | Sort-Object -Property timestamp -Descending 
    #Now limit topic to MaxChars
    foreach ($Entry in $FilteredList) {
        if ($Entry.topic.Length -gt $MaxTopicLength) {
            $Entry | Add-Member -MemberType NoteProperty -Name "topicshort" -Value ($Entry.topic.Substring(0, $MaxTopicLength))
            #$Entry.topic = $Entry.topic.Substring(0, $MaxTopicLength)
        }
        else {
            $Entry | Add-Member -MemberType NoteProperty -Name "topicshort" -Value $Entry.topic
        }
    }

    #Will now put an Index in every entry to make it possible to show less elements
    Write-Host "Adding index to every entry"
    $Zaehler = 0
    foreach ($Entry in $FilteredList) {
        $Entry | Add-Member -MemberType NoteProperty -Name "Index" -Value $Zaehler
        $Zaehler++
    }
}
else {
    Write-Host "Skipping Query as last query was Less then $SkipQueryMinutes (Last Query: $($LastMediathekSearch))"
}
$FilteredList | Export-Clixml -Path "$PSScriptRoot\$ScriptFileNamePlain-QueryResult.xml" -Force -Encoding utf8
#endregion Mediathek-Queries

#region User-Presentation
Write-Host "Found Total: $($FullList.Count) Filtered and shown: $($FilteredList.Count)"
Write-Host "-----------------------------------------------------------------------------------------"
if ($OutGridView) {
    $AuswahlIndex = $FilteredList | Select-Object $DisplayInformationsDesktop | Out-GridView -Title "Bitte Sendungen zum Download auswaehlen" -PassThru
}
else {
    $AuswahlIndex = $FilteredList | select-object $DisplayInformationsConsole | Out-ConsoleGridView -Title "Bitte Sendungen zum Download auswaehlen (Mediathek-Stand: $FilmListTimeStamp)" -OutputMode Multiple
}
#endregion User-Presentation

#region Now get the full lines for the titles that are needed for the downloads. Primary Key is the Index
$Auswahl = @()
foreach ($Index in $AuswahlIndex) {
    $Auswahl += $FilteredList[$Index.Index]
}
#endregion Now get the full lines for the titles that are needed for the downloads. Primary Key is the Index

#region Main Download Code
#Only do something if the user has choosen at least one entry
if ($Auswahl) {
    #region Now check all entries for Manual Rename or Autorename
    $RenameJobs = @()
    foreach ($Einzelsendung in $Auswahl) {
        #Check if a Search entry requires manual filename setting
        if ($Einzelsendung.DownloadInfos.AskForFileName -eq $true) {
            Write-Host "Sender : $($Einzelsendung.channel)"
            Write-Host "Topic  : $($Einzelsendung.topic)"
            Write-Host "Titel  : $($Einzelsendung.title)"
            $Einzelsendung.DownloadInfos.NewFileName = Read-Host -Prompt "Test"
            $RenameJobs += $Einzelsendung
        }
        #Check if the entry should be renamed automatically
        if ($Einzelsendung.DownloadInfos.AutoRename -eq $true) {
            $Einzelsendung.DownloadInfos.NewFileName = ""
            foreach ($RenamePart in $Einzelsendung.DownloadInfos.AutoRenameString) {
                if ($RenamePart -eq "timestamp") {
                    $timestamp = [datetime]($Einzelsendung.$RenamePart)
                    $Einzelsendung.DownloadInfos.NewFileName += $timestamp.ToString("yyMMdd_HHmm_")
                }
                else {
                    $Einzelsendung.DownloadInfos.NewFileName += $Einzelsendung.$RenamePart + "_"
                }
            }
            $Einzelsendung.DownloadInfos.NewFileName = $Einzelsendung.DownloadInfos.NewFileName.TrimEnd("_")
            $Einzelsendung.DownloadInfos.NewFileName += ".mp4"
            #Now Cleanup characters from replacetable, that are not handled correctly by synology API
            $CharacterReplaceTable.GetEnumerator() | foreach-object { $Einzelsendung.DownloadInfos.NewFileName = $Einzelsendung.DownloadInfos.NewFileName.Replace($_.Key, $_.Value) }
            $RenameJobs += $Einzelsendung
        }
    }
    #endregion Now check all entries for Manual Rename or Autorename

    #begin Try to Wakeup NAS
    $Proto, $url, $port = $SynologyURI -split ":" -replace "/"
    if ($IsLinux) {
        if (-Not (Test-Connection -TargetName $url -TcpPort $port)) {
            Write-Host "Warning! Synology cannot be reached!!! Trying to wake it up!" -ForegroundColor Red
            WakeUpNAS -Mac $SynologyMacAddress -BroadcastIP $SynologyWakeUpBroadcastAddress
        }
        else {
            Write-Host "Reached Synology, all ok" -ForegroundColor Red
        }
    }
    else {
        if (-Not (Test-NetConnection -ComputerName $url -Port $port)) {
            Write-Host "Warning! Synology cannot be reached!!! Trying to wake it up!" -ForegroundColor Red
            WakeUpNAS -Mac $SynologyMacAddress -BroadcastIP $SynologyWakeUpBroadcastAddress
        }
        else {
            Write-Host "Reached Synology, all ok" -ForegroundColor Red
        }
    }
    #endregion

    #region Query API URLS and Versions from the Synology
    $TryCounter = 1 # Try $MaxTries Times
    $MaxTries = 50
    $Reached = $false
    while ($TryCounter -le $MaxTries -and -Not $Reached) {
        try {
            Write-Host "Trying to reach the NAS via API ..."
            $InfoArgs = @{
                api     = "SYNO.API.Info"
                version = "1"
                method  = "query"
                query   = "SYNO.API.Auth,SYNO.FileStation.,SYNO.DownloadStation."
            }
            $APIInfos = Invoke-RestMethod -Uri "$SynologyURI/webapi/query.cgi" -Body $InfoArgs
            #Now check if all services have values
            if ($APIInfos.data.'SYNO.DownloadStation.Task'.path -and $APIInfos.data.'SYNO.FileStation.List'.path -and $APIInfos.data.'SYNO.FileStation.Rename'.path -and $APIInfos.data.'SYNO.FileStation.CreateFolder'.path) {
                $Reached = $true
            }
            else {
                Write-Host "Lets wait a little bit, as the last request did not give us all needed Service-URLs!"
                Start-Sleep -Seconds 5
            }
        }
        catch {
            Write-Host "Could not reach the NAS. Trying again (Try# $TryCounter) after 5 Seconds"
            Start-Sleep -Seconds 5
            $TryCounter++
        }
    }
    if ($TryCounter -gt $MaxTries) {
        Write-Error "NAS did not wakeup in time, exiting!"
        break
    }
    $SynoApiAuthPath = $APIInfos.data.'SYNO.API.Auth'.path
    $SynoDownloadStationTaskPath = $APIInfos.data.'SYNO.DownloadStation.Task'.path
    $SynoFileStationListPath = $APIInfos.data.'SYNO.FileStation.List'.path
    $SynoFileStationRenamePath = $APIInfos.data.'SYNO.FileStation.Rename'.path
    $SynoFileStationCreateFolderPath = $APIInfos.data.'SYNO.FileStation.CreateFolder'.path
    #endregion Query API URLS and Versions from the Synology

    #region Authenticate to the NAS
    $AuthArgs = @{
        api     = "SYNO.API.Auth"
        version = "6"
        method  = "login"
        account = $SynologyUserName
        passwd  = $SynologyPassword
        session = "DownloadStation"
    }
    $Authentication = Invoke-RestMethod -Uri "$SynologyURI/webapi/$SynoApiAuthPath" -Body $AuthArgs
    if ($Authentication.success) {
        Write-Host "Task-Authentication stated this answer: $($Authentication.success)"
    }
    else {
        Write-Host "Task-Authentication stated this answer: $($Authentication.success) Errorcode: $($Authentication.error.code) = $($SynoErrorCodes.Authentication.$($Authentication.error.code.ToString()))"
        break
    }
    #Remember SID for all future actions
    $SID = $Authentication.data.sid
    #endregion Authenticate to the NAS
    
    #region Get the current tasklist to eventually delete a task from same URI
    $RunCounter = 1
    do {
        $TaskList = $Null
        try {
    $TaskListArgs = @{
        api        = "SYNO.DownloadStation.Task"
        version    = "1"
        method     = "list"
        additional = "detail,transfer"
        _sid       = $SID
    }
    $TaskList = Invoke-RestMethod -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $TaskListArgs
}
catch {
    Write-Host "$([datetime]::Now.ToString('HH:mm:ss')):Error on getting Task-List, will retry (Try:$RunCounter of $MaxRestRetries)" -ForegroundColor Red
    $RunCounter++
}
} while ($RunCounter -lt $MaxRestRetries -and -Not $TaskList)
#endregion Get the current tasklist to eventually delete a task from same URI

    #region Ask to delete all finished jobs
    $FinishedIds = ($TaskList.data.tasks | where-object { $_.status -eq "finished" }).id
    $NonFinishedIds = ($TaskList.data.tasks | where-object { $_.status -ne "finished" }).id
    Write-Host "Found $($FinishedIds.Count) Finished Tasks and $($NonFinishedIds.Count) Not-Finished Tasks (Error,Downloading or any other state), which will not be handled!" -ForegroundColor Red
    if ($FinishedIds.Count -ge $MaxFinishedBeforeDeleteQuestion) {
        <#$title = "Remove old Download-Jobs"
        $msg = "Do you want delete $($FinishedIds.Count) finished jobs ?"
        $options = '&Yes', '&No'
        $default = 0  # 0=Yes, 1=No
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)#>
        $response = TimedPrompt -Prompt "Do you want delete $($FinishedIds.Count) finished jobs ? (*y/n)" -SecondsToWait 5 -PossibleChars "ynYNzZ" -DefaultChar "y"

        #if ($response -eq 0) {
        if ($response -eq "y") {
            $JobIds = $FinishedIds -join ','
            $DelTaskArguments = @{
                api            = "SYNO.DownloadStation.Task"
                version        = "1"
                method         = "delete"
                id             = $JobIds
                force_complete = $false
                _sid           = $SID
            }
            $TaskDelete = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $DelTaskArguments
            Write-Host "Deleted all old tasks that are finished with the following State: $($TaskDelete.success)" -ForegroundColor Red
            #And now reget the tasklist, as we deleted some:
            $RunCounter = 1
            do {
                $TaskList = $Null
                try {
                    $TaskListArgs = @{
                        api        = "SYNO.DownloadStation.Task"
                        version    = "1"
                        method     = "list"
                        additional = "detail,transfer"
                        _sid       = $SID
                    }
                    $TaskList = Invoke-RestMethod -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $TaskListArgs
                }
                catch {
                    Write-Host "$([datetime]::Now.ToString('HH:mm:ss')):Error on getting Task-List, will retry (Try:$RunCounter of $MaxRestRetries)" -ForegroundColor Red
                    $RunCounter++
                }
            } while ($RunCounter -lt $MaxRestRetries -and -Not $TaskList)
        }
    }
    #endregion Ask to delete all finished jobs

    #region Now start the Download-Jobs
    foreach ($Job in $Auswahl) {
        if ($Job.url_video -in $TaskList.data.tasks.additional.detail.uri) {
            #remove previous download-job
            $JobIds = ($TaskList.data.tasks | Where-Object { $_.additional.detail.uri -eq $Job.url_video }).id -join ','
            $DelTaskArguments = @{
                api            = "SYNO.DownloadStation.Task"
                version        = "1"
                method         = "delete"
                id             = $JobIds
                force_complete = $false
                _sid           = $SID
            }
            $TaskDelete = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $DelTaskArguments
            Write-Host "Deleted old task for job $($Job.topic) - $($Job.title) from $($Job.timestamp) with the following State: $($TaskDelete.success)" -ForegroundColor Red
        }
        
        #Now check if download is possible
        try {
            $Null = Invoke-WebRequest -Method Head -Uri $Job.url_video
        }
        catch {
            $Job.DownloadInfos.DownloadStatus = "skipped"
            Write-Host "File $($Job.DownloadInfos.NewFileName) download error, so download will be skipped" -ForegroundColor Red
            continue
        }

        #Now check if the folder exists and if not, create the folder
        $FolderCheckArgs = @{
            api         = "SYNO.FileStation.List"
            version     = "2"
            method      = "list"
            folder_path = "/$($Job.DownloadInfos.Destination)"
            _sid        = $SID
        }
        $FolderCheck = Invoke-RestMethod -Uri "$SynologyURI/webapi/$SynoFileStationListPath" -Body $FolderCheckArgs
        if (-Not $FolderCheck.Success) {
            Write-Host "Folder $($FolderCheckArgs.folder_path) does not exist!"
        }
        if ($FolderCheck.Success -eq $false) {
            $FolderCreateArgs = @{
                api         = "SYNO.FileStation.CreateFolder"
                version     = "1"
                method      = "create"
                folder_path = (Split-Path $FolderCheckArgs.folder_path)
                name        = (Split-Path $FolderCheckArgs.folder_path -Leaf)
                _sid        = $SID
            }
            $FolderCreate = Invoke-RestMethod -Uri "$SynologyURI/webapi/$SynoFileStationCreateFolderPath" -Body $FolderCreateArgs
            if ($FolderCreate.Success) {
                Write-Host "Created the folder $($FolderCreateArgs.name) in $($FolderCreateArgs.folder_path)"
            }
            else {
                Write-Host "Error creating the folder $($FolderCreateArgs.name) in $($FolderCreateArgs.folder_path) Error $($FolderCreate.error.code):$($SynoErrorCodes.FileStation.$($FolderCreate.error.code.ToString()))"
            }
        }
        
        #region Now check if the file already exist
        $FileListArgs = @{
            api         = "SYNO.FileStation.List"
            version     = "2"
            method      = "list"
            folder_path = "`"/$($Job.DownloadInfos.Destination)`""
            _sid        = $SID
        }
        $FileList = Invoke-RestMethod -Uri "$SynologyURI/webapi/entry.cgi" -Body $FileListArgs
        if ($FileList.data.files.name -contains $Job.DownloadInfos.NewFileName) {
            #file already exists, we will skip
            $Job.DownloadInfos.DownloadStatus = "skipped"
            Write-Host "File $($Job.DownloadInfos.NewFileName) does already exist, so download will be skipped" -ForegroundColor Red
        }
        else {
            #File does not exist, so download
            Write-Host "Downloading $($Job.topic) - $($Job.title) from $($Job.timestamp) to $($Job.DownloadInfos.Destination) Size: $($Job.size / 1MB) MB"
            $CreateTaskArguments = @{
                api         = "SYNO.DownloadStation.Task"
                version     = "3"
                method      = "create"
                uri         = $Job.url_video
                destination = $Job.DownloadInfos.Destination
                _sid        = $SID
            }
            $TaskCreate = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $CreateTaskArguments
            if ($TaskCreate.success) {
                Write-Host "Task-Create stated this answer: $($TaskCreate.success)"
            }
            else {
                Write-Host "Task-Create stated this answer: $($TaskCreate.success) with errorcode $($TaskCreate.error.code) = $($SynoErrorCodes.Tasks.$($TaskCreate.error.code.ToString()))"
                $Job.DownloadInfos.DownloadStatus = "createerror"
            }
        }
        #endregion Now check if the file already exist

    }
    #endregion Now start the Download-Jobs

    #region If rename is active, wait for the jobs that have a rename waiting
    if ($RenameJobs.Count -gt 0) {
        do {
            $JobsFinished = 0
            $RunCounter = 1
            do {
                $TaskList = $Null
                try {
            $TaskListArgs = @{
                api        = "SYNO.DownloadStation.Task"
                version    = "1"
                method     = "list"
                additional = "detail,transfer"
                _sid       = $SID
            }
            $TaskList = Invoke-RestMethod -uri "$SynologyURI/webapi/$SynoDownloadStationTaskPath" -Body $TaskListArgs
        }
        catch {
            Write-Host "$([datetime]::Now.ToString('HH:mm:ss')) : NAS Did not answer due to high-cpu? Will repeat after a wait"
            $RunCounter++
            Start-Sleep -Seconds 2
        }
    } while ($RunCounter -lt $MaxRestRetries -and -Not $TaskList)
    foreach ($Job in $RenameJobs) {
                #find Task
                if ($Job.DownloadInfos.DownloadStatus -ne "skipped" -and $Job.DownloadInfos.DownloadStatus -ne "createerror") {
                    $CurrentTask = $TaskList.data.tasks | where-object { $_.additional.detail.URI -eq $Job.url_video }
                    $Job.DownloadInfos.DownloadStatus = $CurrentTask.status
                    $Job.DownloadInfos.DownloadFileName = $CurrentTask.title
                }
                if ($CurrentTask.status -eq "finished" -or $CurrentTask.status -eq "error" -or $Job.DownloadInfos.DownloadStatus -eq "skipped" -or $Job.DownloadInfos.DownloadStatus -eq "createerror") {
                    $JobsFinished++
                }
            }
            if ($JobsFinished -ne $RenameJobs.Count) {
                #Do not check too frequently as the NAS has a lot work at the moment
                Start-Sleep -Seconds 10
            } 
            Write-Host "$([datetime]::Now.ToString('HH:mm:ss')) : Waiting for Jobs: $JobsFinished from $($RenameJobs.Count) to be finished to rename"
        } until ($JobsFinished -eq $RenameJobs.Count)
        #Now rename
        Write-Host "-----------------------------------------------------------------------------------------"
        Write-Host "Now renaming"
        foreach ($Job in $RenameJobs) {
            if ($Job.DownloadInfos.DownloadStatus -eq "finished" -and $Job.DownloadInfos.NewFileName -ne "") {
                Write-Host "Renaming $($Job.DownloadInfos.Destination)/$($Job.DownloadInfos.DownloadFileName) to $($Job.DownloadInfos.NewFileName)"
                $GetArgs = @{
                    api     = "SYNO.FileStation.Rename"
                    version = "2"
                    method  = "rename"
                    path    = "[`"/$($Job.DownloadInfos.Destination)/$($Job.DownloadInfos.DownloadFileName)`"]"
                    name    = "[`"$($Job.DownloadInfos.NewFileName)`"]"
                    _sid    = $SID
                }
                $TaskRename = Invoke-RestMethod -Method Get -uri "$SynologyURI/webapi/$SynoFileStationRenamePath" -Body $GetArgs
                if (-Not $TaskRename.success) {
                    Write-Host "Task-Rename stated this answer: $($TaskRename.success) Error $($TaskRename.error.code):$($SynoErrorCodes.FileStation.$($TaskRename.error.code.ToString())) Errors-Object: $($TaskRename.error.errors.code):$($SynoErrorCodes.FileStation.$($TaskRename.error.errors.code.ToString()))"
                    
                }
            }
        }
    }
    #endregion If rename is active, wait for the jobs that have a rename waiting


    #region Now logoff from NAS
    $AuthArgs = @{
        api     = "SYNO.API.Auth"
        version = "1"
        method  = "logout"
        session = "DownloadStation"
    }
    $Logout = Invoke-RestMethod -Uri "$SynologyURI/webapi/$SynoApiAuthPath" -Body $AuthArgs
    Write-Host "-----------------------------------------------------------------------------------------"
    Write-Host "Logout returned: $($Logout.success)"
    #endregion Now logoff from NAS
}
#endregion Main Download Code
break
#region Produce HTML
sudo mkdir /mnt/synology
sudo mount -t cifs //synology.fritz.box/videostation /mnt/synology -o user=$SynologyUserName, pass=$SynologyPassword
Get-ChildItem /mnt/synology -File -Recurse | Select-Object @{Name = "Name"; Expression = { $_.FullName.Replace('/mnt/synology', '') } }, Length, CreationTime | Sort-Object Name | ConvertTo-Html | Out-File /home/pi/synology.html -Force
sudo umount /mnt/synology


#endregion
