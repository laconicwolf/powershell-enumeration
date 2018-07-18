Function Get-RecentItems {
<#
.SYNOPSIS
    Retrieves a listing of Recent Items from a specified user or all users.
    Author: Jake Miller (@LaconicWolf)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
.DESCRIPTION
    Get-RecentItems outputs the filepaths contained in a user's recent items 
    folder. It first checks the filepath of the '.lnk' files within the recent 
    items folder, then verifies whether the file exists before writing the path
    to the terminal. 
.PARAMETER Username
    Specifies the username for which the recent items will be returned. By default,
    Get-RecentItems checks all users.
.EXAMPLE
    Get-RecentItems -Username Jake
    Description
    -----------
    Retrieves the recently opened items from the user Jake.
.EXAMPLE
    Get-RecentItems
    Description
    -----------
    Attempts to retrieve the recently opened items from all users.
.EXAMPLE
    Get-RecentItems | Sort-Object -Property LastAccessTime -Descending
    Description
    -----------
    Attempts to retrieve the recently opened items from all users, sorting
    the items by the last time they were accessed.
.LINK
    https://laconicwolf.com/
#>
    [cmdletbinding()]
    Param(
        $Username='All'
    )

    if ($Username -ne 'All') {
        $RecentPath = @("$env:SystemDrive\Users\$UserName\AppData\Roaming\Microsoft\Windows\Recent\")
        if (-not(Test-Path $RecentPath)) {
            Write-Error "Username $Username not found."
        }
    }
    $Username = Get-ChildItem "$env:SystemDrive\Users" | select -ExpandProperty Name

    # Loop through each user, extracting all 'lnk' files from recent items
    foreach($User in $Username) {
        $RecentPath = "$env:SystemDrive\Users\$User\AppData\Roaming\Microsoft\Windows\Recent\"
        if (-not(Test-Path $RecentPath -ErrorAction SilentlyContinue)) { continue }
        $RecentFileLinks = Get-childItem $RecentPath
        
        $ShortcutLinks = @()
        foreach($LinkFile in $RecentFileLinks){
            $Linkpath = $RecentPath + $LinkFile

            # There were a few items that were not a 'lnk'. We can ignore those
            if (-not($Linkpath.EndsWith('lnk'))) { continue }
            $ShortcutLinks += $Linkpath
        }
    }
    
    # Initilize a WScript object to extract the target of the 'lnk' file.
    $RecentFilePaths = @()
    $WSShellObj = New-Object -ComObject WScript.Shell
    foreach($Link in $ShortcutLinks) {
        $RecentFilePath = $WSShellObj.CreateShortcut($Link).TargetPath

        # Skip the file if it is empty, doesn't exist, or if it is a directory
        if (-not($RecentFilePath)) { continue }
        if (-not(Test-Path $RecentFilePath)) { continue }
        if ((Get-Item $RecentFilePath) -is [System.IO.DirectoryInfo]) { continue }

        $RecentFilePaths += $RecentFilePath
    }

    # Perform a GCI on the path to obtain metadata.
    $RecentFileData = @()
    foreach($RecentFile in $RecentFilePaths) {
        if (-not(Test-Path $RecentFile)) { continue }
        $RecentFileData += Get-ChildItem $RecentFile
    }
    $RecentFileData
}
Get-RecentItems