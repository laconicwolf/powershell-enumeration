Function Find-SubDomains {
    <#
    .SYNOPSIS
        Tool for enumerating sub-domains.
        Author: Jake Miller (@LaconicWolf)
        Credit: Sublist3r v1.0 By Ahmed Aboul-Ela - twitter.com/aboul3la

    .DESCRIPTION
        Accepts a domain name and uses Invoke-WebRequests to attempt to visit 
        various sites (crt.sh, virustotal.com, dnsdumpster.com, etc) in order 
        to enumerate sub-domains.

    .PARAMETER Domain
        Mandatory. The domain you would like to check for sub-domains.

    .PARAMETER Proxy
        Optional. Send requests through a specified proxy. 
        Example: -Proxy http://127.0.0.1:8080

    .EXAMPLE        
        PS C:\> Find-SubDomains -Domain github.com

        [+] Getting subdomains for github.com from crt.sh
        [+] Getting subdomains for github.com from dnsdumpster.com
        [+] Getting subdomains for github.com from virustotal.com
        [+] Getting subdomains for github.com from threatcrowd.com
        [+] Getting subdomains for github.com from searchdns.netcraft.com

        SubDomains
        ----------
        *.branch.github.com
        *.github.com
        *.hq.github.com
        *.id.github.com
        *.registry.github.com
        *.review-lab.github.com
        *.rs.github.com
        *.smtp.github.com
        *.stg.github.com
        3scale.github.com
        4simple.github.com
        5509.github.com
        6pac.github.com
        aanoaa.github.com
        abc.github.com
        abedra.github.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, 
                   ValueFromPipeline = $true)]
        [string]$Domain,
    
        [Parameter(Mandatory = $false)]
        [string]$Proxy
    )

# ignore HTTPS certificate warnings
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


    Function Get-RandomAgent {
        <#
        .DESCRIPTION
            Returns a random user-agent.
        #>

        $num = Get-Random -Minimum 1 -Maximum 5
        if($num -eq 1) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
        } 
        elseif($num -eq 2) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
        }
        elseif($num -eq 3) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
        }
        elseif($num -eq 4) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Opera
        }
        elseif($num -eq 5) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Safari
        }
        return $ua
    }



    Function Get-CrtSubDomains {
        <#
            .DESCRIPTION
                Navigates to the crt.sh site and looks up subdomains, then returns
                an array of subdomains
        #>

        Param(
            [Parameter(Mandatory = $true)]
            [string]$Domain,

            [Parameter(Mandatory = $False)]
            [switch]$Proxy
        )

        $URL = "https://crt.sh/?q=%25.$Domain"

        Write-Host "[+] Getting subdomains for $Domain from crt.sh"

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }

        $SubDomains = @()
        $td = ($Response.AllElements | Where-Object {($_.TagName -eq "td")}).innerHtml
    
        foreach ($item in $td) { 
            if ($item -like "*$Domain*" -and $item -notmatch '<TD>' -and $item -notmatch '%') {
                $SubDomains += New-Object -TypeName PSObject -Property @{"SubDomains" = $item.Trim()}
            }
        }

        return $SubDomains | Sort-Object -Property SubDomains -Unique
    }


    Function Get-DnsDumpsterSubDomains {
        <#
            .DESCRIPTION
                Navigates to https://dnsdumpster.com/ and looks up subdomains, then returns
                an array of subdomains
        #>

        Param(
            [Parameter(Mandatory = $true)]
            [string]$Domain,

            [Parameter(Mandatory = $False)]
            [switch]$Proxy
        )

        $URL = "https://dnsdumpster.com/"

        Write-Host "[+] Getting subdomains for $Domain from dnsdumpster.com"

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -SessionVariable session -Method Get -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -SessionVariable session -Method Get -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }

        $csrfmiddlewaretoken = $session.Cookies.GetCookies($url).value

        $PostData = @{"csrfmiddlewaretoken"=$csrfmiddlewaretoken; "targetip"=$Domain}

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -WebSession $session -UserAgent $user_agent -Method Post -Body $PostData -Headers @{"Referer" = $URL} -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -WebSession $session -UserAgent $user_agent -Method Post -Body $PostData -Headers @{"Referer" = $URL} -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
    

        $SubDomains = @()

        Try {
            $td = ($Response.ParsedHtml.getElementsByTagName('TD') | Where-Object {$_.getAttributeNode('class').Value -eq "col-md-4"}).outerText
        }
        Catch {
            Write-Host "[-] Error parsing DNSDumpster response. You can try to check manually at $URL. Skipping." -ForegroundColor Yellow
        }
        foreach ($item in $td) { 
            if ($item -like "*$Domain*") {
                $item = $item -replace "`n|`r"
                $items = $item.Split()
                foreach ($i in $items) {
                    if ($i -like "*$Domain*") {
                        $SubDomains += New-Object -TypeName PSObject -Property @{"SubDomains" = $i.Trim()}
                    }
                }
            }
        }

        return $SubDomains | Sort-Object -Property SubDomains -Unique
    }


    Function Get-VirusTotalSubDomains {
        <#
            .DESCRIPTION
                Navigates to the https://www.virustotal.com/en/domain/$Domain/information/ and 
                looks up observed subdomains, then returns an array of subdomains
        #>

        Param(
            [Parameter(Mandatory = $true)]
            [string]$Domain,

            [Parameter(Mandatory = $False)]
            [switch]$Proxy
        )

        $URL = "https://www.virustotal.com/en/domain/$Domain/information/"

        Write-Host "[+] Getting subdomains for $Domain from virustotal.com"

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Either unable to connect with VirusTotal, or they are requesting a CAPTCHA. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Either unable to connect with VirusTotal, or they are requesting a CAPTCHA. Skipping." -ForegroundColor Yellow
                return
            }
        }

        $SubDomains = @()
        $subDiv = ($Response.ParsedHtml.getElementsByTagName('div') | Where-Object { $_.getAttributeNode('class').Value -eq 'enum ' }).innerText
    
        foreach ($item in $subDiv) { 
            if ($item -like "*$Domain*") {
                $SubDomains += New-Object -TypeName PSObject -Property @{"SubDomains" = $item.Trim()}
            }
        }

        return $SubDomains | Sort-Object -Property SubDomains -Unique
    }


    Function Get-ThreatCrowdSubDomains {
        <#
            .DESCRIPTION
                Navigates to https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$Domain and 
                looks up observed subdomains, then returns an array of subdomains
        #>

        Param(
            [Parameter(Mandatory = $true)]
            [string]$Domain,

            [Parameter(Mandatory = $False)]
            [switch]$Proxy
        )

        $URL = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$Domain"

        Write-Host "[+] Getting subdomains for $Domain from threatcrowd.com"

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }

        $SubDomains = @()
        $threatcrowdSubdomains = ($Response | ConvertFrom-Json).subdomains
    
        foreach ($item in $threatcrowdSubdomains) { 
            if ($item -like "*$Domain*") {
                $SubDomains += New-Object -TypeName PSObject -Property @{"SubDomains" = $item.Trim()}
            }
        }

        return $SubDomains | Sort-Object -Property SubDomains -Unique
    }


    Function Get-NetCraftSubDomains {
        <#
            .DESCRIPTION
                Navigates to https://searchdns.netcraft.com/?restriction=site+ends+with&host=$Domain and 
                looks up observed subdomains, then returns an array of subdomains
        #>

        Param(
            [Parameter(Mandatory = $true)]
            [string]$Domain,

            [Parameter(Mandatory = $False)]
            [switch]$Proxy
        )

        $URL = "https://searchdns.netcraft.com/?restriction=site+ends+with&host=$Domain"

        Write-Host "[+] Getting subdomains for $Domain from searchdns.netcraft.com"

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -TimeoutSec 10
            }
            Catch {
                Write-Host "[-] Unable to connect to $URL. Skipping." -ForegroundColor Yellow
                return
            }
        }

        $SubDomains = @()
        $links = $Response.Links.outerText
    
        foreach ($item in $links) { 
            if ($item -like "*$Domain*") {
                $SubDomains += New-Object -TypeName PSObject -Property @{"SubDomains" = $item.Trim()}                                                                     
            }
        }

        return $SubDomains | Sort-Object -Property SubDomains -Unique
    }

    Write-Host ""

    # If the input is coming from the pipeline
    if ($input) {
        foreach($DomainName in $input) {
            $UserAgent = Get-RandomAgent
    
            $Data = @()

            $Data += Get-CrtSubDomains -Domain $DomainName
            $Data += Get-DnsDumpsterSubDomains -Domain $DomainName
            $Data += Get-VirusTotalSubDomains -Domain $DomainName
            $Data += Get-ThreatCrowdSubDomains -Domain $DomainName
            $Data += Get-NetCraftSubDomains -Domain $DomainName

            Write-Host ""

            $Data | Sort-Object -Property SubDomains -Unique
        }
    }
    else {
        $Data = @()

        $Data += Get-CrtSubDomains -Domain $Domain
        $Data += Get-DnsDumpsterSubDomains -Domain $Domain
        $Data += Get-VirusTotalSubDomains -Domain $Domain
        $Data += Get-ThreatCrowdSubDomains -Domain $Domain
        $Data += Get-NetCraftSubDomains -Domain $Domain

        Write-Host ""

        $Data | Sort-Object -Property SubDomains -Unique
    }
}


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


Function Get-WebsiteInfo {
    <#
    .SYNOPSIS
        Tool for enumerating basic information from websites.
        Author: Jake Miller (@LaconicWolf)

    .DESCRIPTION
        Accepts a single URL or reads a text file of URLs (one per line) and uses 
        Invoke-WebRequests to attempt to visit the each URL. Returns information 
        regarding any redirect, the site Title (if <title> tags are present), and 
        Server type (if the server header is present). For multiple hosts, 
        I recommend piping to Export-Csv to save the data.  
         
    .PARAMETER UrlFile
        Semi-optional. The file path to the text file containing URLs, one per line.

    .PARAMETER Url
        Semi-optional. The URL you would like to test.

    .PARAMETER Proxy
        Optional. Send requests through a specified proxy. 
        Example: -Proxy http://127.0.0.1:8080
        
    .PARAMETER Threads
        Optional. Specify number of threads to use. Default is 1.
        
    .PARAMETER Info
        Optional. Increase output verbosity. 

    .EXAMPLE
        PS C:\> Get-WebsiteInfo -UrlFile .\urls.txt -Threads 5
        
        [*] Loaded 6 URLs for testing
        [*] All URLs tested in 1.0722 seconds
        Title                    URL                        Server   RedirectURL            
        -----                    ---                        ------   -----------            
        LAN                      http://192.168.0.1                                         
        LAN                      https://192.168.0.1/                                       
        LaconicWolf              http://www.laconicwolf.net AmazonS3 http://laconicwolf.net/
        Cisco - Global Home Page https://www.cisco.com/     Apache       

    .EXAMPLE  
        PS C:\> Get-WebsiteInfo -UrlFile .\urls.txt -Info | Export-Csv -Path results.csv -NoTypeInformation
        [*] Loaded 6 URLs for testing
        [+] http://192.168.0.1  LAN 
        [-] Site did not respond
        [+] https://192.168.0.1/  LAN 
        [-] Site did not respond
        [+] http://www.laconicwolf.net http://laconicwolf.net/ LaconicWolf AmazonS3
        [+] https://www.cisco.com/  Cisco - Global Home Page Apache
        [*] All URLs tested in 2.5457 seconds
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        $UrlFile,
    
        [Parameter(Mandatory = $false)]
        $Url,
    
        [Parameter(Mandatory = $false)]
        $Proxy,

        [Parameter(Mandatory = $false)]
        $Threads=1,

        [Parameter(Mandatory = $false)]
        [switch]
        $Info
    )

    if (-not $URL -and -not $UrlFile) {
        Write-Host "`n[-] You must specify a URL or a URLfile`n" -ForegroundColor Yellow
        return
    }

    if ($UrlFile) {
        if (Test-Path -Path $UrlFile) { 
            $URLs = Get-Content $UrlFile 
        }
        else {
            Write-Host "`n[-] Please check the URLFile path and try again." -ForegroundColor Yellow
            return
        }
    }
    else {
        $URLs = @($Url)
    }


    Function Process-Urls {
        <#
        .DESCRIPTION
            Checks an array of URLs and transforms them into the following
            format: http(s)://addr:port
        #>
        Param(
            [Parameter(Mandatory = $True)]
            [array]$URLs
        )

        $HttpPortList = @('80', '280', '81', '591', '593', '2080', '2480', '3080', 
                  '4080', '4567', '5080', '5104', '5800', '6080',
                  '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                  '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                  '8530', '8887', '9000', '9080', '9090', '16080')                    
        $HttpsPortList = @('832', '981', '1311', '7002', '7021', '7023', '7025',
                   '7777', '8333', '8531', '8888')

        $ProcessedUrls = @()
        
        foreach ($Url in $URLs) {
            if ($Url.startswith('http')) {
                if ($Url -match '\*') {
                    $Url = $Url -replace '[*].',''
                }
                $ProcessedUrls += $Url
                continue
            }
            if ($Url -match ':') {
                $Port = $Url.split(':')[-1]
                if ($Port -in $HttpPortList) {
                    $ProcessedUrls += "http://$Url"
                    continue
                }
                elseif ($Port -in $HttpsPortList) {
                    $ProcessedUrls += "https://$Url"
                    continue
                }
                else {
                    $ProcessedUrls += "http://$Url"
                    $ProcessedUrls += "https://$Url"
                    continue
                }
            }
            if ($Url -match '\*') {
                $Url = $Url -replace '[*].',''
                $ProcessedUrls += "http://$Url"
                $ProcessedUrls += "https://$Url"
                continue
            }
        }
        return $ProcessedUrls
    }

    # accept all cookies to avoid popups
    # https://stackoverflow.com/questions/31720519/windows-10-powershell-invoke-webrequest-windows-security-warning
    $msg = reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /t REG_DWORD /v 1A10 /f /d 0

    $URLs = Process-Urls -URLs $URLs

    Write-Host ""
    Write-Host "[*] Loaded" $URLs.Count "URLs for testing"

    $StartTime = Get-Date

    # script that each thread will run
    $ScriptBlock = {
        Param (
            $Url,
            $Proxy
        )

    # ignore HTTPS certificate warnings
    # https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # To prevent 'Could not create SSL/TLS secure channel.' errors
    # https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
    [Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls11, Tls, Ssl3"

    
    Function Get-RandomAgent {
        <#
        .DESCRIPTION
            Helper function that returns a random user-agent.
        #>

        $num = Get-Random -Minimum 1 -Maximum 5
        if($num -eq 1) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
        } 
        elseif($num -eq 2) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
        }
        elseif($num -eq 3) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
        }
        elseif($num -eq 4) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Opera
        }
        elseif($num -eq 5) {
            $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Safari
        }
        return $ua
    }

    # initializes an empty array to store the site's data
    $SiteData = @()

    # sets a random user-agent
    $UserAgent = Get-RandomAgent

    # send request to url
    if ($Proxy) {
        $Response = Try {
            Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy -TimeoutSec 2 -UseBasicParsing
        }
        Catch {
            $_.Exception.Response
        }      
    }
    else {
        $Response = Try {
            Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -TimeoutSec 2 -UseBasicParsing
        }
        Catch {
            $_.Exception.Response
        }   
    }

    # Indicates a 2xx or 3xx response
    if ($Response.GetType().name -eq "BasicHtmlWebResponseObject") {

        # examine response to compare current url and requested url
        if ($Response.BaseResponse.ResponseUri.OriginalString.trim('/') -ne $URL.trim('/')) {
            $RedirectedUrl = $Response.BaseResponse.ResponseUri.OriginalString
        }
        else {
            $RedirectedUrl = ""
        }

        # finds title if available
        $Title = [regex]::match($Response.Content,'(?i)<title>(.*?)</title>').Groups[1].Value
        if (-not $Title) {
            $Title = ""
        }

        # examines response headers and extracts the server value if available
        if ($Response.BaseResponse.Server) {
            $Server = $Response.BaseResponse.Server
        }
        else {
            $Server = ""
        }
    }

    # indicates a 4xx or 5xx response
    elseif ($Response.GetType().name -eq "HttpWebResponse") {
        # examine response to compare current url and requested url
        if ($Response.ResponseUri.OriginalString.trim('/') -ne $URL.trim('/')) {
            $RedirectedUrl = $Response.ResponseUri.OriginalString
        }
        else {
            $RedirectedUrl = ""
        }

        # extracts the html 
        $Result = $Response.GetResponseStream()
        $Reader = New-Object System.IO.StreamReader($Result)
        $Reader.BaseStream.Position = 0
        $Reader.DiscardBufferedData()
        $ResponseBody = $Reader.ReadToEnd();

        # finds title if available
        $Title = [regex]::match($ResponseBody,'(?i)<title>(.*?)</title>').Groups[1].Value
        if (-not $Title) {
            $Title = ""
        }

        # examines response headers and extracts the server value if available
        if ($Response.Server) {
            $Server = $Response.Server
        }
        else {
            $Server = ""
        }
    }

    # creates an object with properties from the html data
    $SiteData += New-Object -TypeName PSObject -Property @{
                                    "URL" = $URL
                                    "RedirectURL" = $RedirectedUrl
                                    "Title" = $Title
                                    "Server" = $Server
                                    }

    return $SiteData
    }

    # concepts adapted from: https://www.codeproject.com/Tips/895840/Multi-Threaded-PowerShell-Cookbook
    # create the pool where the threads will launch
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $RunspacePool.Open()

    $Jobs = @()

    ForEach ($URL in $URLs) {

        # maps the command line options to the scriptblock
        if ($Proxy -and -not $Info) {
            $Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter("Url", $URL).AddParameter("Proxy", $Proxy)
        }
        else {
            $Job = [powershell]::Create().AddScript($ScriptBlock).AddParameter("Url", $URL)
        }
        
        # starts a new job for each url
        $Job.RunspacePool = $RunspacePool
        $Jobs += New-Object PSObject -Property @{
            RunNum = $_
            Job = $Job
            Result = $Job.BeginInvoke()
        }
    }

    # combine the return value of each individual job into the $Data variable
    $Data = @()
    ForEach ($Job in $Jobs) {
        $SiteData = $Job.Job.EndInvoke($Job.Result)
        $Data += $SiteData

        if ($Info) {
            if ($SiteData) {

                # transform hashhtable data into string without column header
                $SiteDataString = $SiteData | ForEach-Object {
                     "[+] {0} {1} {2} {3}" -f $_.URL,$_.RedirectURL,$_.Title,$_.Server 
                     }
                Write-Host "$SiteDataString"
            }
            else {
                Write-Host "[-] Site did not respond"
            }
        }
    }
    
    # display the returned data
    $Data

    $EndTime = Get-Date
    $TotalSeconds = "{0:N4}" -f ($EndTime-$StartTime).TotalSeconds
    Write-Host "[*] All URLs tested in $TotalSeconds seconds"
    Write-Host ""

    # remove the key set earlier
    reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1A10 /f
}
