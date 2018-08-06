Function Get-ProcessFileMappings {
<#
.SYNOPSIS
    Enumerates the filename associated with specific processes, such as winword
    Author: Jake Miller (@LaconicWolf)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
.DESCRIPTION
    Get-ProcessFileMappings.Grabs the main title window for Office documents
    or other documents specified in the script.
.EXAMPLE
    Get-ProcessFileMappings

    FileName                                                                       
    --------                                                                       
    lab.docx - Word                                                                
    encrypted_data.xlsx - Excel                                                    
    {hello.txt - Notepad, hello2.txt - Notepad}    
.LINK
    https://laconicwolf.com/
#>

    [cmdletbinding()]
    Param()

    $ProcsOfInterest = @('winword', 'excel', 'notepad', 'notepad++')

    $ProcessInformation = @()
    foreach ($Proc in $ProcsOfInterest) {
        $ProcessData = Get-Process $Proc -ErrorAction SilentlyContinue
        if ($ProcessData -eq $null) { continue }
        $ProcessInformation += New-Object -TypeName PSObject -Property @{
                                        "ProcessId" = $ProcessData.Id
                                        "FileName" = $ProcessData.MainWindowTitle
                                        }
    }
    $ProcessInformation
}