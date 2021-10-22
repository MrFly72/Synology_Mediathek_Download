#region Global Settings
$future = $true # Search for future airings ?
$NumberOfDaysBack = 365 # Number of days to search back in Mediathekviewweb
$MinimumSize = 100000 # Minimum Size of the MP4 file, trying to remove stupid sizes
$MinimumLength = "00:15:00" # Minimum length of the Airing in HH:MM:SS
$MaxReturnEntries = 100 #Maximum entries, that will be returned by Mediathekwebview
$ForceQueryRerunMinutes = 60 # Check fo LastRunTime and if it is less then this Minutes, dont ask the Mediathek again. Only Works if PS Session stays active.
$MaxFinishedBeforeDeleteQuestion = 5
$SaveMediathekResultToFile = $true
# Replace with your URI, can be internal or external URI.
# Standard Ports: 5000 : HTTP, 5001 : HTTPS (strongly recommended!!!)
# If you are using SSL make sure the SSL Cert matches!
$SynologyURI = "https://mysynology.home.net:5001" 

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
    "topic"
    "title"
    "timestamp"
    "duration"
    "size"
)
#endregion

#region Character Replace Table
# German Umlauts have to be replaced and the table lists them with charvalues, as text format conversion happens too often
# We have to replace umlauts as the Syno-API are not consistent in handling umlauts!
# Additionally we are replacing some characters which will not work in some filesystems. If you find additional ones add them here!
$CharacterReplaceTable = @{
    '|'               = '_'
    ':'               = '_'
    '/'               = '_'
    '?'               = '_'
    '&'               = 'und'
    'á'               = 'a'
    '"'               = "_"
    [string][char]252 = 'ue'
    [string][char]228 = 'ae'
    [string][char]246 = 'oe'
    [string][char]223 = 'ss'
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
        400 = "File upload failed"
        401 = "Max number of tasks reached"
        402 = "Destination denied"
        403 = "Destination does not exist"
        404 = "Invalid task id"
        405 = "Invalid task action"
        406 = "No default destination"
        407 = "Set destination failed"
        408 = "File does not exist"
    }
    Authentication = @{
        400 = "No such account or incorrect password"
        401 = "Account disabled"
        402 = "Permission denied"
        403 = "2-step verification code required"
        404 = "Failed to authenticate 2-step verification code"
    }
}
#endregion Synology Errorcodes

#endregion Global Settings

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

#region Script State initialization
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
    $ScriptState | Export-Clixml "$PSScriptRoot\$ScriptFileNamePlain.xml" -Force -Encoding utf8
    #$LastMediathekSearch = $ScriptState.LastMediathekSearch.AddMinutes(0 - $ForceQueryRerunMinutes - 1) #Force Run as we init
}
#Take Last Query from Filetime of the cachefile
$FileInfo=Get-Item -Path "$PSScriptRoot\$ScriptFileNamePlain-QueryResult.xml" -ErrorAction SilentlyContinue
if ($FileInfo) {
    $LastMediathekSearch=$FileInfo.LastWriteTimeUtc
}
else {
    $LastMediathekSearch=(Get-Date).AddMinutes(0 - $ForceQueryRerunMinutes - 1).ToUniversalTime()
}
#endregion Script State initialization


#region Password Initialization
$SynologyUserName = $Credentials.Username
$SynologyPassword = $Credentials.GetNetworkCredential().Password
#endregion Password Initialization

#region Reload from Mediathek Query
if ($LastMediathekSearch) {
    if ((New-TimeSpan -Start $LastMediathekSearch -End (Get-date).ToUniversalTime()).TotalMinutes -le $ForceQueryRerunMinutes -and $SaveMediathekResultToFile) {
        $title = "Rerun Mediathek Search?"
        $DeltaTime = [Math]::Round((New-TimeSpan -Start $LastMediathekSearch -End (Get-Date).ToUniversalTime()).TotalMinutes, 2)
        $msg = "Last Mediathek Search was $DeltaTime Minutes ago. Rerun?"
        $options = '&Yes', '&No'
        $default = 1  # 0=Yes, 1=No
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
        if ($response -eq 1) {
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
    $FullList = @()

    foreach ($MediathekEntry in $MediathekDownload) {
        if ($Null -eq $MediathekEntry.Enabled -or $MediathekEntry.Enabled -eq $true) {
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
            $AntwortConverted = @($Antwort.result.results | Select-Object Channel, topic, title, @{Label = "timestamp"; Expression = { ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($_.timestamp).ToLocalTime() } }, @{Label = "duration"; Expression = { [timespan]::FromSeconds($_.duration) } }, @{Label = "filmlisteTimestamp"; Expression = { ([datetime] '1970-01-01Z').ToUniversalTime().AddSeconds($_.filmlisteTimestamp).ToLocalTime() } }, size, description, url_website, url_video, @{Label = "DownloadInfos"; Expression = { $DownloadInfos.Clone() } })
            Write-Host "Mediathekquery: totalResults: $($Antwort.result.queryInfo.totalResults) Returned: $($Antwort.result.queryInfo.resultCount) Filmliste Timestamp: $((Get-Date '01/01/1970').ToLocalTime().AddSeconds($Antwort.result.queryInfo.filmlisteTimestamp)) Oldest: $($AntwortConverted[-1].timestamp)"
            if (!$AntwortConverted) {
                continue
            }
            if ($AntwortConverted.Count -eq $MediathekEntry.MediathekQuery.size) { #$MaxReturnEntries
                Write-Host "Found $($AntwortConverted.Count) entries WARNING Max entries reached!!!" -ForegroundColor Yellow
                if ((New-TimeSpan -Start $AntwortConverted[-1].timestamp -End (Get-Date)).TotalDays -gt $NumberOfDaysBack) {
                    Write-Host "But all is safe, as all elements with date limit are downloaded!" -ForegroundColor Green
                }
                else {
                    Write-Host "Could not get all elements inside of date limit!!!! Oldest entry is:$($AntwortConverted[-1].timestamp)" -ForegroundColor Red
                }
            }
            $FullList += $AntwortConverted | where-object { (New-TimeSpan -Start $_.timestamp -End (Get-Date)).TotalDays -lt $NumberOfDaysBack }
        }
        else {
            Write-Host "Mediathek search DISABLED for: $($MediathekEntry.MediathekQuery.queries.query -join ',')"
        }
    }

    #Now filter the output by some criterias

    #Skip if Array with Keywords is empty
    if ($ExcludeTitlesKeywords.Count -gt 0) {
        $FilteredList = $FullList | where-object { $_.title -notmatch ($ExcludeTitlesKeywords -join "|") }
    }
    else {
        $FilteredList = $FullList
    }
    $FilteredList = $FilteredList | where-object { $_.size -gt $MinimumSize -and $_.duration -gt $MinimumLength } 
    $FilteredList = $FilteredList | Sort-Object -Property timestamp -Descending 
    #Will now put an Index in every entry to make it possible to show less elements
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
    $AuswahlIndex = $FilteredList | select-object $DisplayInformationsConsole | Out-ConsoleGridView -Title "Bitte Sendungen zum Download auswaehlen" -OutputMode Multiple
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

    #region Authenticate to the NAS
    $AuthArgs = @{
        api     = "SYNO.API.Auth"
        version = "2"
        method  = "login"
        account = $SynologyUserName
        passwd  = $SynologyPassword
        session = "DownloadStation"
    }
    $Authentication = Invoke-RestMethod -Uri "$SynologyURI/webapi/auth.cgi" -Body $AuthArgs
    if ($Authentication.success) {
        Write-Host "Task-Authentication stated this answer: $($Authentication.success)"
    }
    else {
        Write-Host "Task-Authentication stated this answer: $($Authentication.success) Errorcode: $($Authentication.error.code) = $($SynoErrorCodes.Authentication.$($Authentication.error.code))"
        break
    }
    #Remember SID for all future actions
    $SID = $Authentication.data.sid
    #endregion Authenticate to the NAS
    
    #region Get the current tasklist to eventually delete a task from same URI
    $TaskListArgs = @{
        api        = "SYNO.DownloadStation.Task"
        version    = "1"
        method     = "list"
        additional = "detail,transfer"
        _sid       = $SID
    }
    $TaskList = Invoke-RestMethod -uri "$SynologyURI/webapi/DownloadStation/task.cgi" -Body $TaskListArgs
    #endregion Get the current tasklist to eventually delete a task from same URI

    #region Ask to delete all finished jobs
    $FinishedIds = ($TaskList.data.tasks | where-object { $_.status -eq "finished" }).id
    $NonFinishedIds = ($TaskList.data.tasks | where-object { $_.status -ne "finished" }).id
    Write-Host "Found $($FinishedIds.Count) Finished Tasks and $($NonFinishedIds.Count) Not-Finished Tasks (Error,Downloading or any other state), which will not be handled!" -ForegroundColor Red
    if ($FinishedIds.Count -ge $MaxFinishedBeforeDeleteQuestion) {
        $title = "Remove old Download-Jobs"
        $msg = "Do you want delete $($FinishedIds.Count) finished jobs ?"
        $options = '&Yes', '&No'
        $default = 0  # 0=Yes, 1=No
        $response = $Host.UI.PromptForChoice($title, $msg, $options, $default)
        if ($response -eq 0) {
            $JobIds = $FinishedIds -join ','
            $DelTaskArguments = @{
                api            = "SYNO.DownloadStation.Task"
                version        = "1"
                method         = "delete"
                id             = $JobIds
                force_complete = $false
                _sid           = $SID
            }
            $TaskDelete = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/DownloadStation/task.cgi" -Body $DelTaskArguments
            Write-Host "Deleted all old tasks that are finished with the following State: $($TaskDelete.success)" -ForegroundColor Red
   
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
            $TaskDelete = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/DownloadStation/task.cgi" -Body $DelTaskArguments
            Write-Host "Deleted old task for job $($Job.topic) - $($Job.title) from $($Job.timestamp) with the following State: $($TaskDelete.success)" -ForegroundColor Red
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
            $TaskCreate = Invoke-RestMethod -Method Post -uri "$SynologyURI/webapi/DownloadStation/task.cgi" -Body $CreateTaskArguments
            if ($TaskCreate.success) {
                Write-Host "Task-Create stated this answer: $($TaskCreate.success)"
            }
            else {
                Write-Host "Task-Create stated this answer: $($TaskCreate.success) with errorcode $($TaskCreate.error.code) = $($SynoErrorCodes.Tasks.$($TaskCreate.Error.code))"
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
            $TaskListArgs = @{
                api        = "SYNO.DownloadStation.Task"
                version    = "1"
                method     = "list"
                additional = "detail,transfer"
                _sid       = $SID
            }
            $TaskList = Invoke-RestMethod -uri "$SynologyURI/webapi/DownloadStation/task.cgi" -Body $TaskListArgs
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
            Write-Host "Waiting for Jobs: $JobsFinished from $($RenameJobs.Count) to be finished to rename"
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
                $TaskRename = Invoke-RestMethod -Method Get -uri "$SynologyURI/webapi/entry.cgi" -Body $GetArgs
                Write-Host "Task-Rename stated this answer: $($TaskRename.success)"
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
    $Logout = Invoke-RestMethod -Uri "$SynologyURI/webapi/auth.cgi" -Body $AuthArgs
    Write-Host "-----------------------------------------------------------------------------------------"
    Write-Host "Logout returned: $($Logout.success)"
    #endregion Now logoff from NAS
}
#endregion Main Download Code
