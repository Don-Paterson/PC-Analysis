$dest = "$env:USERPROFILE\Desktop\Assess-UserFiles.ps1"
Invoke-RestMethod "https://raw.githubusercontent.com/Don-Paterson/PC-Analysis/main/Assess-UserFiles.ps1" |
    Out-File -FilePath $dest -Encoding UTF8 -NoNewline
pwsh -ExecutionPolicy Bypass -File $dest
