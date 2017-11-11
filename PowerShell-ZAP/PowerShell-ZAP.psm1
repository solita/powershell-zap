# PowerShell-ZAP
# Copyright (c) 2015 Solita Oy / Joona Immonen
#
# This is created against 2.4.2 OWASP-ZAP
# Purpose of the module is provide few easy to use functions
# for OWASP-ZAP to be used from powershell. 
# E.g. starting, stopping, spidering, scanning and saving results
# 
# More information about how to use ZAP API please visit your own zaps local API
# e.g. http://localhost:8084/UI/ and the documentation
# https://github.com/zaproxy/zaproxy/wiki/ApiGen_Index
#
#Requires -Version 4.0
$ErrorActionPreference = 'Stop'

# OWASP-ZAP is at default in 8084 port
$script:zapBaseAddress = "http://localhost:8084"
# OWASP-ZAP is at default installed under program files \OWASP\Zed Attack Proxy\
$script:zapLocation = "${env:ProgramFiles}\OWASP\Zed Attack Proxy\"
# Results can be by default stored in temp
$script:zapReportLocation = ($env:temp+"\zapresults.xml")
# Url to scan is the website to scan
$script:urlToScan = $null
# These are used for storing latest spidering and scanning
$script:currentSpiderId
$script:currentScanId

<#
.SYNOPSIS 
Sets the location of your OWASP ZAP

.DESCRIPTION
Sets the url location of your OWASP ZAP instance.

.EXAMPLE
C:\PS> Set-ZapAddress "http://localhost:8084"
#>
function Set-ZapAddress
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=1)][string]$zapUrl
    )

    $script:zapBaseAddress = $zapUrl
}

<#
.SYNOPSIS 
Sets the binary location of your ZAP

.DESCRIPTION
Sets the binary location of your ZAP. This is used for example in Start-ZAP.

.EXAMPLE
C:\PS> Set-ZapLocation "C:\Program Files (x86)\OWASP\Zed Attack Proxy\"
#>
function Set-ZapLocation
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=1)][string]$zapFolder
    )
    $script:zapLocation = $zapFolder
}

<#
.SYNOPSIS 
Sets where to save your ZAP report

.DESCRIPTION
Sets the store location for your OWASP-ZAP report file. 

.EXAMPLE
C:\PS> Set-ZapReportLocation "C:\Temp\zapresults.xml"
#>
function Set-ZapReportLocation
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=1)][string]$reportFile
    )
    $script:zapReportLocation = $reportFile
}

<#
.SYNOPSIS 
Sets the root of the website to scan

.DESCRIPTION
Sets the url for the website for vulnerability scanning. 

.EXAMPLE
Set-ZapUrlToScan "http://localhost"
#>
function Set-ZapUrlToScan
{
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=1)][string]$scanUrl
    )
    # if the url ends with / remove the last character
    $length = $scanUrl.Length
    if($scanUrl.Substring($length - 1) -eq "/")
    {
        Write-Verbose "Removing last / character from url $scanUrl"
        $scanUrl = $scanUrl.Substring(0,$scanUrl.Length-1)
    }
    $script:urlToScan = $scanUrl
}

<#
.SYNOPSIS 
Checks if the zap responses and tries to start it as daemon if it does not

.DESCRIPTION
Checks if the zap responses and tries to start it as daemon if it does not. 

.EXAMPLE
Start-ZAP
#>
function Start-Zap
{
    [CmdletBinding()]
    param()
    try 
    {
        $zapStatus = (Invoke-WebRequest $script:zapBaseAddress).StatusCode
    }
    catch
    {
        Write-Verbose "Zap daemon is not running, trying to restart"
        # Zap is not running, start it
        $tempLoc = Get-Location
        Set-Location $script:zapLocation
        $zapArgs = @("-daemon", "-config api.disablekey=true")
        $zapProc = Start-Process (Join-Path $script:zapLocation "zap.exe") -PassThru -Verb runAs -ArgumentList $zapArgs
        Write-Verbose ("Zap daemon started with process id: "+$zapProc.Id)
        Set-Location $tempLoc

        # wait for daemon to start
        Start-Sleep -s 10
    }
    # set-scan policies
    Set-ZapScanPolicies
}

<#
.SYNOPSIS 
Sets some predefined settings on in OWASP-ZAP

.DESCRIPTION
Enables all scanners, sets sitemapxml and robotstxt parsing to true.

.EXAMPLE
Set-ZapScanPolicies
#>
function Set-ZapScanPolicies
{
    [CmdletBinding()]
    param()
    
    # enable all scan policies
    $policyStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/ascan/action/enableAllScanners/?zapapiformat=JSON&scanPolicyName=")
    # let the spider parse sitemap and robots.txt
    $policyStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/spider/action/setOptionParseSitemapXml/?zapapiformat=JSON&Boolean=true")
    $policyStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/spider/action/setOptionParseRobotsTxt/?zapapiformat=JSON&Boolean=true")
}

<#
.SYNOPSIS 
Tells the OWASP ZAP to shutdown

.DESCRIPTION
Tells the OWASP ZAP to shutdown.

.EXAMPLE
Stop-Zap
#>
function Stop-Zap
{
    [CmdletBinding()]
    # Kill daemon
    $killStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/core/action/shutdown")
}

<#
.SYNOPSIS 
Starts spidering against the given url (ZapUrlToScan) and sets this as a current spider

.DESCRIPTION
Tells the owasp zap to start going through website and gather all the urls found in the website.

.EXAMPLE
Invoke-ZapSpidering
#>
function Invoke-ZapSpidering
{
    [CmdletBinding()]
    param()
    
    Test-ZAPUrlToScanIsValid
    
    $spiderId = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/spider/action/scan/?zapapiformat=JSON&url="+$script:urlToScan) | ConvertFrom-Json
    Write-Verbose ("Spidering invoked with message "+$spiderId)
    $spiderStatus = 0
    Do
    {
        $spiderStatus = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/spider/view/status?scanId="+$spiderId.scan) | ConvertFrom-Json | % { $_.Status }
        Write-Verbose "Status of spidering is: $spiderStatus"
        Start-Sleep -s 1 
    }
    While ($spiderStatus -ne 100)
    $script:currentSpiderId =  $spiderId.scan
}

<#
.SYNOPSIS 
Starts ajax spidering against the given url (ZapUrlToScan)

.DESCRIPTION
Tells the owasp zap to start going through website and gather all the urls foudn in the website. Does exactly same as normal spidering but is able to execut javascript also and is thus able to do more than normal spidering.

.EXAMPLE
Invoke-ZapAjaxSpidering
#>
function Invoke-ZapAjaxSpidering
{   
    [CmdletBinding()]
    param()
    
    Test-ZAPUrlToScanIsValid
    
    $ajaxStatus = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/ajaxSpider/action/scan/?zapapiformat=JSON&url="+$script:urlToScan) | ConvertFrom-Json
    Write-Verbose ("Ajax spidering started with message "+$ajaxStatus)
    $spiderStatus = 0
    Do
    {
        $spiderStatus = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/ajaxSpider/view/status/?zapapiformat=JSON") | ConvertFrom-Json | % { $_.Status }
        Write-Verbose "Status of ajax spidering is: $spiderStatus"
        Start-Sleep -s 1 
    }
    While ($spiderStatus -ne "stopped")
}

<#
.SYNOPSIS 
Starts scanning against the given url (ZapUrlToScan) and sets this as a current scan

.DESCRIPTION
Tells OWASP-ZAP to make vulnerability scan against set website (ZapUrlToScan).

.EXAMPLE
Invoke-ZapScanning
#>
function Invoke-ZapScanning
{
    [CmdletBinding()]
    param()
    
    Test-ZAPUrlToScanIsValid
    #scan
    $scanId = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/ascan/action/scan/?url="+$script:urlToScan) | ConvertFrom-Json
    Write-Verbose ("Scanning invoked with message "+$scanId)
    $scanStatus = 0
    Do
    {
        $scanStatus = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/JSON/ascan/view/status?scanId="+$scanId.scan) | ConvertFrom-Json | % { $_.Status }
        Write-Verbose "Status of scanning is: $scanStatus"
        Start-Sleep -s 1 
    }
    While ($scanStatus -ne 100)
    $script:currentScanId = $scanId.scan
}

<#
.SYNOPSIS 
Removes information of all spidering and scanning results

.DESCRIPTION
Removes information of all spidering and scanning results.

.EXAMPLE
Remove-ZapAllScans
#>
function Remove-ZapAllScans
{
    [CmdletBinding()]
    param()
    # remove spider
    $removeStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/spider/action/removeAllScans/?zapapiformat=JSON")
    Write-Verbose ("Removed all spiders with message "+$removeStatus)
    # remove scan
    $removeStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/ascan/action/removeAllScans/?zapapiformat=JSON")
    Write-Verbose ("Removed all scans with message "+$removeStatus)
}

<#
.SYNOPSIS 
Removes information of current scanning results

.DESCRIPTION
Removes information of current scanning results

.EXAMPLE
Remove-ZapAllScans
#>
function Remove-ZapCurrentScan
{
    [CmdletBinding()]
    param()
    # remove scan
    $removeStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/ascan/action/removeScan/?zapapiformat=JSON&scanId="+$script:currentScanId)
    Write-Verbose ("Removed a scan id ("+$script:currentScanId+") with message "+$removeStatus)
}

<#
.SYNOPSIS 
Removes information of current spidering results

.DESCRIPTION
Removes information of current spidering results

.EXAMPLE
Remove-ZapCurrentSpider
#>
function Remove-ZapCurrentSpider
{
    [CmdletBinding()]
    param()
    # remove spider
    $removeStatus = Invoke-WebRequest ($script:zapBaseAddress+"/JSON/spider/action/removeScan/?zapapiformat=JSON&scanId="+$script:currentSpiderId)
    Write-Verbose ("Removed a spider id ("+$script:currentSpiderId+") with message "+$removeStatus)
}

<#
.SYNOPSIS 
Gets information about all alerts with current ZapUrlToScan

.DESCRIPTION
Gets information about all alerts with current ZapUrlToScan

.EXAMPLE
Get-ZapAlerts
#>
function Get-ZapAlerts
{
    [CmdletBinding()]
    param()
    
    Test-ZAPUrlToScanIsValid
    
    #fetch the report
    [xml]$xmlReport = Invoke-WebRequest -Uri ($script:zapBaseAddress+"/OTHER/core/other/xmlreport/")
    $siteReport = $xmlReport.OWASPZAPReport.site | ? { $_.name -eq $script:urlToScan } | select alerts
    $siteReport.alerts.alertitem | % { $_ }
}

<#
.SYNOPSIS 
Gets the information about all alerts with current ZapUrlToScan and stores them to given ZapReportDestination as junit results

.DESCRIPTION
Gets the information about all alerts with current ZapUrlToScan and stores them to given ZapReportDestination as junit results

.EXAMPLE
Get-ZapAlerts
#>
function Save-ZapReport
{
    [CmdletBinding()]
    param()
    
    Test-ZAPUrlToScanIsValid
    
    $alerts = Get-ZapAlerts
    $alertMeasure = $alerts | measure 

    # Transform the report to testsuite xml supported by jenkins
    # Create a new XML File with config root node
    [System.XML.XMLDocument]$oXMLDocument=New-Object System.XML.XMLDocument
    # create testsuite node and add attribute 
    [System.XML.XMLElement]$oXMLRoot=$oXMLDocument.CreateElement("testsuite")
    $null = $oXMLDocument.appendChild($oXMLRoot)
    $null = $oXMLRoot.SetAttribute("tests",$alertMeasure.Count)
    # create dummy test, without atleast one test the jenkins plugin won't work
    [System.XML.XMLElement]$oXMLTestcase=$oXMLRoot.appendChild($oXMLDocument.CreateElement("testcase"))
    $null = $oXMLTestcase.SetAttribute("classname","Dummy")
    $null = $oXMLTestcase.SetAttribute("name","Dummy test")

    # create tests and failures 
    Foreach($alert in $alerts)
    {
        Foreach($instance in ($alert.instances.instance))
        {
            # create test
            [System.XML.XMLElement]$oXMLTestcase=$oXMLRoot.appendChild($oXMLDocument.CreateElement("testcase"))
            $null = $oXMLTestcase.SetAttribute("classname",$alert.riskdesc)
            $null = $oXMLTestcase.SetAttribute("name",$alert.alert)
            # create failure
            [System.XML.XMLElement]$oXMLTestFailure=$oXMLTestcase.appendChild($oXMLDocument.CreateElement("failure"))
            $null = $oXMLTestFailure.SetAttribute("type",$alert.alert)
            			# create a "stacktrace"
			[string]$stackTrace = 
@"
	Error at url: {0}
	{1}
"@ -f $instance.uri, $alert.solution
			#store stacktrace
            $null = $oXMLTestFailure.AppendChild($oXMLDocument.CreateTextNode($stackTrace))
        }
    }
    # Save File
    $oXMLDocument.Save($script:zapReportLocation)
    Write-Verbose ("Report saved to "+$script:zapReportLocation)
}

function script:Test-ZAPUrlToScanIsValid
{
    if($script:urlToScan -eq $null) 
    {
        throw "ZAP URL to scan was not set"
    }
    $urlToScanStatus = 500
    try 
    {
        $urlToScanStatus = (Invoke-WebRequest $script:urlToScan).StatusCode
    }
    catch
    {
        throw "ZAP URL to scan $urlToScanStatus could not be reached with error message $_.Exception.Message"
    }
    if($urlToScanStatus -ne 200)
    {
        throw "ZAP URL to scan $urlToScanStatus resulted unexpected status with code $urlToScanStatus"
    }
}