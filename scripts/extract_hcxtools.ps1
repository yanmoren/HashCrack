$src = 'c:\Users\13784\.trae-cn\attachments\6aa24c9c334801a1b1e7b8cf\61fad5d3-8bab-45cd-bce6-1ac658e78526_648e649f-285b-4802-b126-b6e64e042c04_hcxtools-7.1.2-win64.zip'
$dst = 'E:\hashcat_gui\dist\windows\hcxtools'
Expand-Archive -Path $src -DestinationPath $dst -Force
Write-Host "Extracted to: $dst"
Get-ChildItem $dst | Select-Object Name, Length | Format-Table -AutoSize
