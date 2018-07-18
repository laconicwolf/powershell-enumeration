Function Find-InterestingFileNames {
<#
.SYNOPSIS
    Recursively searches the file system for files that contain part of a
    specific string (defined in the cmdlet).
    Author: Jake Miller (@LaconicWolf)
.DESCRIPTION
    Find-InterestingFilenames calls GCI recursively, and attempts to match on specific
    file globs. For any matches, the full filepath is returned. 
.PARAMETER StartDirectory
    Specifies the location where the recursive searching will start. Defaults to 
    the current directory.
.EXAMPLE
    Find-InterestingFilenames -StartDirectory C:\Users\Jake\
    Description
    -----------
    Will recursively search the filesystem starting at C:\Users\Jake\.
.LINK
    https://laconicwolf.com/
#>

    [cmdletbinding()]
    Param(
        $StartDirectory = '.'
    )
 
    if (-not(Test-Path $StartDirectory)) {
        throw "Invalid StartDirectory! Exiting." 
    }

    $FilePaths = Get-ChildItem -Path $StartDirectory -Force -Recurse -File -Include '*pass*',
                                 '*cred*', 'user*', '*.conf', '*ssh', '*.ssh', '*key', '*git', 
                                 '*.xml', '*.properties', '*.ear', '*.war' -ErrorAction SilentlyContinue |
                                 select Name, FullName, LastAccessTime, LastWriteTime, Length
    
    $FilePaths
}
Find-InterestingFilenames -StartDirectory C:\users\jake\.aws