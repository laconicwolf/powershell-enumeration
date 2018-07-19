Function Find-InterestingFiles {
<#
.SYNOPSIS
    Recursively searches the file system for files that contain part of a
    specific string (defined in the function or with a list supplied to the 
    -WordList parameter).
    Author: Jake Miller (@LaconicWolf)
    License: BSD 3-Clause
    Credit: ice3man (https://ice3man.me/) for the search signatures
.DESCRIPTION
    Find-InterestingFiles calls Get-ChildItem recursively, using the -Include
    parameter to filter on an array of words designed to match interesting files
    containing credentials or sensitive information. The call to GCI uses the -Force
    option, so it does look for hidden files.
.PARAMETER StartDirectory
    Specifies the location where the recursive searching will start. Defaults to 
    the current directory.
.PARAMETER WordList
    Provide a filepath for a file that specifies the strings (seperated by new lines) to search.
.EXAMPLE
    Find-InterestingFiles -StartDirectory C:\Users\Jake\ | 
    select FullName, LastAccessTime, LastWriteTime, Length
    Description
    -----------
    Will recursively search the filesystem starting at C:\Users\Jake\, displaying files containing 
    the strings specified in the function.
.EXAMPLE
    Find-InterestingFiles -Wordlist filter.txt | 
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
        # Adapted from https://github.com/Ice3man543/hawkeye/blob/master/core/signatures.go
        $SearchWords = "settings.py", "user.txt", "*.kwallet", "terraform.tfvars", "recentservers.xml",
                       "*.functions", "*.log", "*.env", "configuration.user.xpl", "..pem", "*._rsa.pub", 
                       "*credentials", "*.tpm", "*.exports", "*.bek", "knife.rb", "*.sqlite", "credential", 
                       "secret_token.rb", "*.asc", "*.trc", "*._ed25519.pub", "credentials.xml", "journal.txt", 
                       "*._dsa", "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml", "*.extra", 
                       "*.gnucash", "*._dsa.pub", "*.ovpn", "proftpdpasswd", "*.htpasswd", "*.rdp", "*.p12", 
                       "*.pgpass", "*._rsa", "*.jks", "*._ecdsa", "*.pfx", "sftp-config.json", "otr.private_key", 
                       "*.pcap", "ventrilo_srv.ini", "*.cscfg", "keys.db", "*.muttrc", "sqldump", "*.pem", 
                       "*.dockercfg", "*.tugboat", "*.npmrc", "filezilla.xml", "LocalSettings.php", "database.yml", 
                       "*password*", "config.inc.php", "*.mysql_history", "root.txt", "kdbx", "*config", "*.fve", 
                       "shadow", "servlist_.conf", "config.yaml", "keypair", "accounts.xml", "*.tblk", "*._ed25519", 
                       "*.mdf", "*.pkcs12", "*.agilekeychain", "*.dayone", "*.sdf", "*.irb_history", "*.gitconfig", 
                       "*._ecdsa.pub", "Favorites.plist", "*.dbeaver-data-sources.xml", "*.psql_history", 
                       "config/hub", "*.s3cfg", "carrierwave.rb", "passwd", "*.psafe3", "*.keychain", "omniauth.rb", 
                       "robomongo.json"
    }
    Get-ChildItem -Path $StartDirectory -Force -Recurse -File -Include $SearchWords -ErrorAction SilentlyContinue 
}
