# Synology_Mediathek_Download
Helps downloading from MediathekviewWeb with help of Synology NAS

1. Query Mediathekviewweb API for all airings matching the given search criteria
2. Filter by:
   1. Number of days back that should be presented
   2. Exclude airings that match the ExcludeTitlesKeywords List
   3. Airings that are under MinimumSize or under MinimumLength
3. Sort the list descending and use Out-Gridview to present the user with the choice
4. If the user has selected some airings, the script will continue
5. Now airing by airing will be checked if:
   1. Filename is requested to be set manual –> User will be requested for a name for each
   2. Autorename is choosen for the title (strong recommended for all Configurations)
      1. New Filename will be built by the configured setting AutoRenameString, Timestamp is „yyMMdd_HHmm_“
      2. Replace Character as of CharacterReplaceTable to prevent filesystem problems (eg. /|:)
6. All files that need a rename after download will be added to a RenameTaskList
7. Authenticate to NAS
8. Start Download Jobs, only if File with same filename is not already there. Cleanup NAS-History of Downloadjobs of the same URL, so we get the right status
9. Wait for the Downloadjobs that need a rename until they are downloaded. Check NAS every 10 Seconds to not overload
10. Rename the downloaded files to the wished name
11. Logoff from NAS


Currently find some information here:
https://www.lambrecht.de/?p=155

This script should be compatible with PS5.1 and PS7.x although it is usually tested on PS5.1.

Version History:
Version 1.2
- Added functionality to ask the user if the last query was below $ForceQueryRerunMinutes if a query should be rerun anyhow
Version 1.1
- Password will now be saved to XML File in the Script Directory. On Windows it is encrypted with DPAPI, on Linux it is not really encrypted.
- Password: If you leave Password blank you will be asked on every run of the script (If you want to change this behaviour, delete the xml file, to start from scratch)
- If more then x finished Downloadjobs are in the Download Manager you will be asked if you want to delete it (for x see parameter $MaxFinishedBeforeDeleteQuestion)
- Fur multiple downloads after each other, the List of airings can be cached. The minutes it will be cached can be configured with $SkipQueryMinutes. If you want to requery, reset variable $LastMediathekSearch=$Null or restart the PS Console
- To make the script compatible with linux PWSH, it will try to use Out-ConsoleGridView for the choosing of airings to download. If neither Out-GridView or Out-ConsoleGridView are present the script will break. Get Out-ConsoleGridView with the module "Microsoft.PowerShell.ConsoleGuiTools" from the PSGallery
- To make the Gridview more readable, i changed to download IDs and so the Columns can be defined with:
  $DisplayInformationsDesktop for the desktop Out-GridView
  $DisplayInformationsConsole for the Console Out-ConsoleGridView
Known Issue:
- If you delete all download tasks when asked and a downloadjob is a redownload, the script will additionally try to delete the single download task from the finished list, altough the list is empty. This is not a real problem and cosmetic.


Version 1.0
First Github start, elementary functionality.

