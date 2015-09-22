Remove-Module PowerShell-ZAP
Import-Module .\PowerShell-ZAP\PowerShell-ZAP.psm1

# use this reportlocation for jenkins
# Set-ZapReportLocation ($env:WORKSPACE+"\test.xml")

# Configure our local variables
Set-ZapReportLocation "C:\Temp\zapresults.xml"
Set-ZapUrlToScan "http://localhost"

# Ensure that daemon is running
Start-Zap
# Configure policies, this just enables all scanners atm
Set-ZapScanPolicies
# Do spidering against the url
Invoke-ZapSpidering 
# Do ajax spidering against the url
Invoke-ZapAjaxSpidering
# Do scanning against the url
Invoke-ZapScanning
# Save report
Save-ZapReport
# Destroy scans
#Remove-ZapAllScans
Remove-ZapCurrentSpider
Remove-ZapCurrentScan 
# Kill daemon
Stop-Zap


