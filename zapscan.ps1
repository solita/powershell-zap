# Example script of how to use PowerShell-Zap module
# Script sets few variables, starts zap and scans it. 
# Finally results are saved to given location
$ErrorActionPreference = 'Stop'

Remove-Module PowerShell-ZAP
Import-Module .\PowerShell-ZAP\PowerShell-ZAP.psm1

# use this reportlocation for jenkins
# Set-ZapReportLocation ($env:WORKSPACE+"\test.xml")
$resultsLocation = ($env:temp+"\zapresults.xml")

# Configure our local variables
Set-ZapReportLocation $resultsLocation
Set-ZapUrlToScan "http://localhost/" -Verbose
Set-ZapAddress "http://localhost:8084"
Set-ZapLocation ((${env:ProgramFiles(x86)}, ${env:ProgramFiles} -ne $null)[0]+"\OWASP\Zed Attack Proxy\")

# Ensure that daemon is running
Start-Zap -Verbose
# Configure policies, this just enables all scanners atm
Set-ZapScanPolicies
# Do spidering against the url
Invoke-ZapSpidering  -Verbose
# Do ajax spidering against the url
Invoke-ZapAjaxSpidering -Verbose
# Do scanning against the url
Invoke-ZapScanning -Verbose
# Save report
Save-ZapReport -Verbose
# Destroy scans
#Remove-ZapAllScans
Remove-ZapCurrentSpider -Verbose
Remove-ZapCurrentScan -Verbose
# Kill daemon
Stop-Zap

# show results
CAT $resultsLocation

