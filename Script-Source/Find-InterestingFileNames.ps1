Function Find-InterestingFileNames {
<#
.SYNOPSIS
    Recursively searches the file system for files that contain part of a
    specific string (defined in the cmdlet or with a list supplied to the 
    -WordList parameter).
    Author: Jake Miller (@LaconicWolf)
    License: BSD 3-Clause
.DESCRIPTION
    Find-InterestingFilenames calls GCI recursively, and attempts to match on specific
    file globs. For any matches, the full filepath is returned. 
.PARAMETER StartDirectory
    Specifies the location where the recursive searching will start. Defaults to 
    the current directory.
.PARAMETER WordList
    Provide a filepath for a file that specifies the strings (seperated by new lines) to search.
.EXAMPLE
    Find-InterestingFilenames -StartDirectory C:\Users\Jake\ | 
    select FullName, LastAccessTime, LastWriteTime, Length
    Description
    -----------
    Will recursively search the filesystem starting at C:\Users\Jake\, displaying files containing 
    the strings specified in the cmdlet.
.EXAMPLE
    Find-InterestingFilenames -Wordlist filter.txt | 
    select FullName, LastAccessTime, LastWriteTime, Length
    Description
    -----------
    Will recursively search the filesystem starting in the current directory, displaying files 
    containing the strings specified in the supplied wordlist.
.LINK
    https://laconicwolf.com/
#>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateScript({ if (-not(Test-Path $_)) { Throw "Invalid path given: $_" } return $True })]
        [string]$StartDirectory = '.',

        [Parameter(Mandatory = $False)]
        [ValidateScript({ if (-not(Test-Path $_)) { Throw "Invalid path given: $_" } return $True })]
        [string]$WordList
    )
    if ($WordList) {
        $SearchWords = Get-Content $WordList
    }
    else {
        $SearchWords = "*pass*","*cred*", "user*", "*.conf", "*ssh",
                       "*.ssh", "*key", "*git", "*.xml", "*.properties", 
                       "*.ear", "*.war"
    }
    Get-ChildItem -Path $StartDirectory -Force -Recurse -File -Include $SearchWords -ErrorAction SilentlyContinue 
}
