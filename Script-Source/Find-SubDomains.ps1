﻿Function Find-SubDomains {
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