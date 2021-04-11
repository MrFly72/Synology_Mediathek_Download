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
