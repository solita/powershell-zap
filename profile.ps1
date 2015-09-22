#example profile file
$psdir=$PSScriptRoot
gci "${psdir}\*.psd1" -recurse | %{ Import-Module $_.FullName }
Write-Host  "Custom modules loaded" -ForeGroundColor "Yellow"