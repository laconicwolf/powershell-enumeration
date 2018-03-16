Function Parse-NetUser {
    <#
    .SYNOPSIS
        Parses the net user command output into a single list.
        Author: Jake Miller (@LaconicWolf)

    .DESCRIPTION
        Accepts the output of net user via the pipeline and parses into a 
        single list.

    .EXAMPLE        
        PS C:\> net user | Parse-NetUser
        
        Users                       
        ------
        Administrator
        DefaultAccount
        Dwight
        Guest
        Jake
        WDAGUtilityAccount
    #>

    foreach ($item in $input) {
        if ($item -eq ""){
            continue
        }
        if ($item -match 'User accounts for') {
            continue
        }
        elseif ($item -match '----') {
            continue
        }
        elseif ($item -match 'The command completed') {
            continue
        }
        $contentArray = @()
        foreach ($line in $item) {
            while ($line.Contains("  ")){
                $line = $line -replace '  ',' '
            }
            $contentArray += $line.Split(' ')
        }
 
        foreach($content in $contentArray) {
            $content = $content -replace '"',''
            if ($content.Length -ne 0) {
                New-Object -TypeName PSObject -Property @{"Users" = $content.Trim()}
            }
        }
    }
}


Function Parse-NetGroupMembers {
    <#
    .SYNOPSIS
        Parses the net group <group> command output into a single list.
        Author: Jake Miller (@LaconicWolf)

    .DESCRIPTION
        Accepts the output of net group via the pipeline and parses into a 
        single list.

    .EXAMPLE        
        PS C:\> net user | Parse-NetGroupMembers
        
        Group Members
        -------------
        Administrator
        Dwight       
        Jake         
    #>

    foreach ($item in $input) {
        if ($item -eq ""){
            continue
        }
        elseif ($item -match 'Alias name') {
            continue
        }
        elseif ($item -match 'Comment') {
            continue
        } 
        elseif ($item -match 'Group name') {
            continue
        }
        elseif ($item -match 'Members') {
            continue
        }
        elseif ($item -match '----') {
            continue
        }
        elseif ($item -match 'The command completed') {
            continue
        }
        $contentArray = @()
        foreach ($line in $item) {
            while ($line.Contains("  ")){
                $line = $line -replace '  ',' '
            }
            $contentArray += $line.Split(' ')
        }
 
        foreach($content in $contentArray) {
            $content = $content -replace '"',''
            if ($content.Length -ne 0) {
                New-Object -TypeName PSObject -Property @{"Group Members" = $content.Trim()}
            }
        }
    }
}


Function Parse-NetGroup {
    <#
    .SYNOPSIS
        Parses the net group command output into a single list.
        Author: Jake Miller (@LaconicWolf)

    .DESCRIPTION
        Accepts the output of net group via the pipeline and parses into a 
        single list.

    .EXAMPLE        
        PS C:\> net user | Parse-Netuser
        
        Groups                       
        ------                       
        __vmware__                   
        Administrators               
        Distributed COM Users        
        Event Log Readers            
        Guests           
    #>

    foreach ($item in $input) {
        if ($item -eq ""){
            continue
        }
        elseif ($item -match 'Aliases') {
            continue
        }
        elseif ($item -match 'Group Accounts for') {
            continue
        }
        elseif ($item -match '----') {
            continue
        }
        elseif ($item -match 'The command completed') {
            continue
        }
        $group = $item.Trim('*')
        New-Object -TypeName PSObject -Property @{"Groups" = $group.Trim()}
    }
}
