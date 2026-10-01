# Windows triage snippets. Run individual blocks; this is not meant to run top to bottom.
# The Active Directory blocks need the ActiveDirectory module.

######### AD users with password expiry dates #########
Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $false' `
    -Properties DisplayName, 'msDS-UserPasswordExpiryTimeComputed' |
  Select-Object DisplayName, SamAccountName,
    @{Name = "ExpiryDate"; Expression = { [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') }} |
  Sort-Object ExpiryDate |
  Export-Csv -Path .\password-expiry.csv -NoTypeInformation

######### Scheduled tasks outside the Microsoft folder #########
Get-ScheduledTask |
  Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
  Select-Object TaskName, TaskPath, State,
    @{Name = "Action"; Expression = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; " }}

######### Local administrators #########
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource

######### Startup programs #########
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User

######### Drivers that are not validly signed #########
Get-ChildItem C:\Windows\System32\drivers\*.sys |
  ForEach-Object { Get-AuthenticodeSignature $_.FullName } |
  Where-Object Status -ne "Valid" |
  Select-Object Path, Status

######### Established network connections with the owning process #########
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
    @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName }}

######### Failed logons (4625), last 2 days #########
Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4625; StartTime = (Get-Date).AddDays(-2)} |
  Select-Object TimeCreated,
    @{Name = "Account"; Expression = { $_.Properties[5].Value }},
    @{Name = "Source";  Expression = { $_.Properties[19].Value }},
    @{Name = "LogonType"; Expression = { $_.Properties[10].Value }}

######### New accounts (4720), last 7 days #########
Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4720; StartTime = (Get-Date).AddDays(-7)} |
  Select-Object TimeCreated,
    @{Name = "NewAccount"; Expression = { $_.Properties[0].Value }},
    @{Name = "CreatedBy";  Expression = { $_.Properties[4].Value }}
