#########################################
# Author  : Md. Abdullah Al Mamun
# Tool    : DFIRT (DFIR Tool)
# Version : 1.0
#########################################



#===============================
#       V A R I A B L E S       |
#===============================
$UserName = [System.Environment]::UserName
$CurrentPath = pwd | Select-Object | %{$_.ProviderPath}
$TheDate = Get-Date

#===============================
#          B A N N E R          |
#===============================
cls
Write-Host ""; Write-Host ""; Write-Host -BackgroundColor White "                                               "; Write-Host -BackgroundColor White "   " -NoNewline; Write-Host "                                         " -NoNewline; Write-Host -BackgroundColor White "   "; Write-Host -BackgroundColor White "   " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White "    " -NoNewline; Write-Host "    " -NoNewline; Write-Host -BackgroundColor White "      " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor White "    " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor White "    " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White "      " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White "   "; Write-Host "      " -NoNewline; Write-Host -BackgroundColor White "  " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor White " " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White "  " -NoNewline; Write-Host "       " -NoNewline; Write-Host -BackgroundColor White "  " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White " " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor White " " -NoNewline; Write-Host "    " -NoNewline; Write-Host -BackgroundColor White "  "; Write-Host "      " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor Yellow "      " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow "    " -NoNewline; Write-Host "     " -NoNewline; Write-Host -BackgroundColor Yellow "  "; Write-Host "      " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "       " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host " " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host "      " -NoNewline; Write-Host -BackgroundColor Yellow "  "; Write-Host -BackgroundColor White "   " -NoNewline; Write-Host "   " -NoNewline; Write-Host -BackgroundColor Yellow "    " -NoNewline; Write-Host "    " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "      " -NoNewline; Write-Host -BackgroundColor Yellow "    " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host "  " -NoNewline; Write-Host -BackgroundColor Yellow " " -NoNewline; Write-Host "     " -NoNewline; Write-Host -BackgroundColor Yellow "  " -NoNewline; Write-Host "     " -NoNewline; Write-Host -BackgroundColor White "   "; Write-Host -BackgroundColor White "   " -NoNewline; Write-Host "                                         " -NoNewline; Write-Host -BackgroundColor White "   "; Write-Host -BackgroundColor White "                                               "; Write-Host -ForegroundColor White "Author: Md. Abdullah Al Mamun  |  Version: 1.0"; Write-Host ""; Write-Host "";


#===============================
#        S T A R T I N G        |
#===============================
Write-Host "[+]  Hello, $UserName"
Write-Host -ForegroundColor Green "[+]  DFIRT is starting"
Start-Sleep -s 1

#===============================
#       E X E C U T I O N       |
#===============================
echo "========================================================`r`nDFIRT (DFIR Tool) Report`r`n$TheDate`r`n========================================================`r`n`r`n" > $CurrentPath\report.txt

####################################################################
# Get the Computer Name
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting computer name"
if (Test-Path -Path HKLM:"\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName") {
  $ThePCName = Get-ItemPropertyValue  HKLM:"\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName"
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nComputer Name              : $ThePCName"
} else {
    Write-Host -ForegroundColor Red "[-]  Could not find the Registry key!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nComputer Name              : Could not find the Registry key!"
  }
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

####################################################################
# Get user accounts list from SID
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting user accounts list from SID"
if (Test-Path -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") {
  Get-ChildItem -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | select pschildname > $CurrentPath\TEMP.txt
  $FileContent = [System.IO.File]::ReadAllText("$CurrentPath\TEMP.txt")
  $FileContent.Trim() > $CurrentPath\TEMP.txt
  $TrimmedContent = Get-Content $CurrentPath\TEMP.txt | Select-Object -Skip 2
  $TrimmedContent > $CurrentPath\TEMP.txt
  $Namex = ""
  Get-Content $CurrentPath\TEMP.txt | ForEach-Object {
    if ($_ -match "s") {
    $_ = $_ -replace '\s',''
    $ProfImgPath = Get-ItemPropertyValue  HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$_\" -Name "ProfileImagePath"
    $UserN = $ProfImgPath.split("\")[-1]
    $Namex = $Namex + "$UserN | "
    }
  }
  Add-Content -Path $CurrentPath\TEMP1.txt -Value $Namex
  $TEMPone = Get-Content $CurrentPath\TEMP1.txt
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nUser List                  : $TEMPone"
} else {
    Write-Host -ForegroundColor Red "[-]  Could not find the Registry key!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nUser List                  : Could not find the Registry key!"
  }

####################################################################
# Get the current build number
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting current build"
if (Test-Path -Path HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
  $CurrntBuild = Get-ItemPropertyValue  HKLM:"\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuild"
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nCurrent Build Number       : $CurrntBuild"
} else {
    Write-Host -ForegroundColor Red "[-]  Could not find the Registry key!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nCurrent Build Number       : Could not find the Registry key!"
  }
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

####################################################################
# Get the Computer ID
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Computer ID"
$CompStat = Get-MpComputerStatus
$ComputerID = '{0}' -f $CompStat.ComputerID
Add-Content -Path $CurrentPath\report.txt -Value "`r`nComputer ID                : $ComputerID"

####################################################################
# Check LastBootUpTime
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Getting the last boot up time"
$BootUpT = Get-CimInstance -Class CIM_OperatingSystem | Select-Object LastBootUpTime
$BootUpT | Out-File -filepath $CurrentPath\TEMP.txt
Get-Content $CurrentPath\TEMP.txt | ForEach-Object {
  if ($_ -match '[0-9]') {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nLast Boot Up Time          : $_"
  }
}

####################################################################
# Check Domain
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking if the computer is in domain or workgroup"
$DomainStat = systeminfo | findstr /b "Domain"
if ($DomainStat -match "WORKGROUP") {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nDomain                     : WORKGROUP"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nDomain                     : Part of a domain"
  }

####################################################################
# Check registry for EnableLUA
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking current Admin Approval Mode policy"
if (Test-Path -Path HKLM:"\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
  $EnableLUAvalue = Get-ItemPropertyValue  HKLM:"\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
  if ($EnableLUAvalue -match '1') {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nAdmin Approval Mode        : Enabled"
  } else {
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nAdmin Approval Mode        : Disabled"
    }
}

####################################################################
# Check Windows Defender Status
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking Windows Defender Status"
$WDStatus = Get-MpComputerStatus
$AVStatus = '{0}' -f $WDStatus.AntivirusEnabled
Add-Content -Path $CurrentPath\report.txt -Value "`r`nAnti Virus Enabled         : $AVStatus"
$RealTimeP = '{0}' -f $WDStatus.RealTimeProtectionEnabled
if ($RealTimeP -eq $true) {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nReal-Time Protection       : Enabled"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nReal-Time Protection       : Disabled"
  }
$AVSigVersion = '{0}' -f $WDStatus.AntivirusSignatureVersion
Add-Content -Path $CurrentPath\report.txt -Value "`r`nAV Signature Version       : $AVSigVersion"

####################################################################
# Check Safe DLL Mode
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking safe DLL search mode"
$SafeKeyStat = (Get-ItemProperty HKLM:"\SYSTEM\CurrentControlSet\Control\Session Manager").PSObject.Properties.Name -contains "SafeDllSearchMode"
if ($SafeKeyStat -eq $true) {
  $DllMode = Get-ItemPropertyValue HKLM:"\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode"
  if ($DllMode -eq '0') {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nSafe DLL Search Mode       : Disabled"
  } else {
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nSafe DLL Search Mode       : Enabled"
    }
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nSafe DLL Search Mode       : Couldn't determine if enabled or, disabled.`r`n                             Because, the registry key does not exist!"
  }

####################################################################
# Check Current User Language
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking current user language settings"
$n = 1
$UserLanguage = (Get-WinUserLanguageList).Autonym
$UserLanguage | ForEach-Object {
  if ($n -lt 2) {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nCurrent User Language      : $_"
    $n++
  } else {
      Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
    }
}

####################################################################
# Get the Network connectivity information
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting Internet connectivity information"
$NetStatus = [bool](Test-Connection www.google.com -Count 1 -ErrorAction SilentlyContinue)
if ($NetStatus -eq $true) {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nNetwork Status             : Connected to Internet"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nNetwork Status             : Not connected to Internet"
  }
$PrivIP = Test-Connection -ComputerName (hostname) -Count 1 | select -ExpandProperty IPV4Address 2>$null
$OnlyIP = $PrivIP.IPAddressToString 2>$null
if ($OnlyIP -match "[0-9]") {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nPrivate IP Address         : $OnlyIP"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nPrivate IP Address         : No IP address found!"
  }

####################################################################
# Check Free Spaces of Drives
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking free space of disk"
Add-Content -Path $CurrentPath\report.txt -Value "`r`nFree Disk Space            : Drive and free space-"
$DriveSpaces = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID,FreeSpace
$DriveSpaces | Out-File -filepath $CurrentPath\TEMP.txt
Get-Content $CurrentPath\TEMP.txt | ForEach-Object {
  if ($_ -match ":") {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
  }
}








####################################################################
# Check Network Related Running Services
####################################################################
$NetServices = Get-Service -Displayname "*net*" | Where-Object {$_.Status -eq "Running"} | Select-Object Name
$ServiceName =  $NetServices.Name
$ServiceNum = $ServiceName.length
if ($ServiceNum -gt 0) {
  if ($ServiceNum -gt 10) {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nRunning Network Services   : Found more than 10 services, related to network.`r`n                             Here is the list of first 10 services-"
    $ServiceName | ForEach-Object {
      Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
    }
  } elseif ($ServiceNum -eq 10) {
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nRunning Network Services   : Found 10 services, related to network.`r`n                             Here is the list of first 10 services-"
      $ServiceName | ForEach-Object {
        Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
      }
    }  else {
        if ($ServiceNum -lt 11) {
        Add-Content -Path $CurrentPath\report.txt -Value "`r`nRunning Network Services   : Found less than 10 services, related to network.`r`n                             Here is the list-"
        $ServiceName | ForEach-Object {
          Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
        }
      }
    }
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nRunning Network Services   : Nothing found"
  }

####################################################################
# Check event logs for any suspicious event ids
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking for suspicious Event ID"
Start-Sleep -s 1
echo "" > $CurrentPath\TEMP.txt
$EventIdArray = @(4648, 4964, 5025, 5031, 540, 4697, 4720, 1102, 4722, 4723, 4725, 4727, 4728, 4732, 4616, 4735, 4737, 4755, 4756, 4740, 4772, 4777, 4782, 4698, 4699, 4700, 4701, 4702, 4946, 4947, 4950, 4954, 5152, 5153, 5155, 5157, 5447)
$EventIdArray | ForEach-Object {
  $TempVal = Get-EventLog -LogName System -InstanceId $_ 2>&1>$null
  if ($? -match "True") {
    Add-Content -Path $CurrentPath\TEMP.txt -Value "$_`r`n"
  } 
}
Get-Content $CurrentPath\TEMP.txt | Get-Unique > $CurrentPath\TEMP1.txt
$EventListF = Get-Content $CurrentPath\TEMP1.txt
$EventListF = $EventListF.Trim()
[System.IO.File]::WriteAllText("$CurrentPath\TEMP1.txt", $EventListF)
$EventListF = Get-Content $CurrentPath\TEMP1.txt
if ($EventListF -match '[0-9]') {
  $EventListF = $EventListF -replace '\s','-'
  Write-Host -ForegroundColor Red "[+]  Found suspicious Event ID!"
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nSuspicious Event ID found  : $EventListF"
} else {
    Write-Host -ForegroundColor Green "[+]  No suspicious Event ID found"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nSuspicious Event ID found  : No"
  }

####################################################################
# Collect Non Default Program File's folders
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Collecting non default folders in Program File"
$DefaultPFiles = 'Common Files', 'Internet Explorer', 'Windows Defender Advanced Threat Protection', 'Microsoft Update Health Tools', 'ModifiableWindowsApps', 'Windows Defender', 'Windows Mail', 'Windows Media Player', 'Windows Multimedia Platform', 'Windows NT', 'Windows Photo Viewer', 'Windows Portable Devices', 'Windows Security', 'WindowsPowerShell', 'Uninstall Information', 'WindowsApps'
$NonDefaultDirs = @()
$PFiles = Get-ChildItem 'C:\Program Files'
$a = $PFiles | ? { $DefaultPFiles -notcontains $_ }
$a.Name > $CurrentPath\TEMP1.txt
Get-Content -Path $CurrentPath\TEMP1.txt | ForEach-Object {
  if ($_ -match '\w') {
    $NonDefaultDirs += $_
  }
}
$i = 1
if ($NonDefaultDirs.length -gt 0) {
    Write-Host -ForegroundColor Red "[+]  Found Such Folder!"
    if ($NonDefaultDirs.length -gt 10) {
      if ($i -lt 11) {
        $i++
        Add-Content -Path $CurrentPath\report.txt -Value "`r`nFolder In Program Files    : More than 10 folders found in Program Files directory,`r`n                             which might be for third party programs.`r`n                             Here is the list of 10 folders-"
        $NonDefaultDirs | ForEach-Object {
          Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
        }
      }
    } elseif ($NonDefaultDirs.length -eq 10) {
        if ($i -lt 11) {
          $i++
          Add-Content -Path $CurrentPath\report.txt -Value "`r`nFolder In Program Files    : 10 folders found in Program Files directory,`r`n                             which might be for third party programs.`r`n                             Here is the list-"
          $NonDefaultDirs | ForEach-Object {
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
          }
        }
      } else {
          if ($i -lt 11) {
          $i++
          Add-Content -Path $CurrentPath\report.txt -Value "`r`nFolder In Program Files    : Less than 10 folders found in Program Files directory,`r`n                             which might be for third party programs.`r`n                             Here is the list-"
          $NonDefaultDirs | ForEach-Object {
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
          }
        }
      }
} else {
    Write-Host -ForegroundColor Green "[+]  Not Found Such Folder!"
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nFolder In Program Files    : Searched in Program Files directory for third party programs.`r`n                             Nothing found!"
  }

####################################################################
# Check recently opened files
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking recently used files"
$a = 1
$UsrProfile = $ENV:USERPROFILE
if (Test-Path -Path "$UsrProfile\AppData\Roaming\Microsoft\Windows\Recent") {
  cd "$UsrProfile\AppData\Roaming\Microsoft\Windows\Recent"
  $RecentFiles = (Get-ChildItem .\ -file).FullName
  $RFLength = $RecentFiles.length
  if ($RFLength -gt 0) {
    if ($RFLength -gt 10) {
      Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Found more than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n                             Here is the list of 10 files-"
      $RecentFiles | ForEach-Object {
        if ($a -lt 11) {
          $LinkFileName = Get-ChildItem -Path $_ -Name
          Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $LinkFileName"
          $a++
        }
      }
    } elseif ($RFLength -eq 10) {
        Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
        Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Found more than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n                             Here is the list of 10 files-"
        $RecentFiles | ForEach-Object {
          if ($a -lt 11) {
            $LinkFileName = Get-ChildItem -Path $_ -Name
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $LinkFileName"
            $a++
          }
        }
      } else {
         Write-Host -ForegroundColor Green "[+]  Found Recent Files!"
         Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Found less than 10 files in $UsrProfile\AppData\Roaming\Microsoft\Windows\Recent`r`n                             Here is the list-"
         $RecentFiles | ForEach-Object {
          if ($a -lt 11) {
            $LinkFileName = Get-ChildItem -Path $_ -Name
            Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $LinkFileName"
            $a++
          }
         }
        }
  } else {
      Write-Host -ForegroundColor Red "[+]  Found Nothing!"
      Add-Content -Path $CurrentPath\report.txt -Value "`r`nRecent Files               : Nothing found"
    }
  cd $CurrentPath
}
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

####################################################################
# Check directly opened files directly from Windows Explorer
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking files, opened directly from Windows Explorer"
$key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
echo "" > $CurrentPath\TEMP1.txt
if (Test-Path -Path $key) {
  Get-Item $key | select -Expand property | % {
    $value = (Get-ItemProperty -Path $key -Name $_).$_
    $list = [System.Text.Encoding]::Default.GetString($value) -replace '[\x01-\x1F]'
    Add-Content -Path $CurrentPath\TEMP1.txt -Value "`r`n$list"
  }
}
$i = 1
$n = 0
Add-Content -Path $CurrentPath\report.txt -Value "`r`nDirectly Opened By Explorer: Here is the list of files (might contain some extra characters with file name)`r`n                             opened directly from Windows Explorer-"
Get-Content $CurrentPath\TEMP1.txt | ForEach-Object {
  if ($_ -match "[a-zA-Z0-9]") {
    if ($i -lt 20) {
      if ($n -lt 1) {
        Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
        $i++
        $n++
      } else {
          Add-Content -Path $CurrentPath\report.txt -Value "                             $_"
          $i++
        }
    }
  }
}

####################################################################
# Check Powershell History For All Session
####################################################################
Write-Host -ForegroundColor Yellow "[+]  Checking Powershell history for all session"
$CurrentPath = pwd | Select-Object | %{$_.ProviderPath}
$TheHistory = Get-Content -tail 30 (Get-PSReadlineOption).HistorySavePath
$HistArray = @()
$TheHistory > $CurrentPath\TEMP1.txt
Get-Content $CurrentPath\TEMP1.txt | ForEach-Object {
  if ($_ -match "[a-zA-Z0-9]") {
    $HistArray += $_
  }
}
$j = 0
$HistArrayLen = $HistArray.length
if ($HistArrayLen -lt 1) {
  Add-Content -Path $CurrentPath\report.txt -Value "`r`nPowershell History         : No history found!"
} else {
    Add-Content -Path $CurrentPath\report.txt -Value "`r`nPowershell History         : Last few Powershell commands-"
    $TheHistory | ForEach-Object {
      if ($j -lt 1) {
        Add-Content -Path $CurrentPath\report.txt -Value "`r`n                             $_"
        $j++
      } else {
          Add-Content -Path $CurrentPath\report.txt -Value "                             $_"
        }
    }
  }
Remove-Item $CurrentPath\TEMP.txt 2>&1>$null
Remove-Item $CurrentPath\TEMP1.txt 2>&1>$null

#===============================
#     E N D      P R O M P T    |
#===============================
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
$DFIRTForm = New-Object System.Windows.Forms.Form
$DFIRTForm.Text = "DFIRT (DFIR Tool)"
$DFIRTForm.Size = New-Object System.Drawing.Size(500,150)
$DFIRTForm.StartPosition = "CenterScreen"
Write-Host ""
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Size(5,5)
$label.Size = New-Object System.Drawing.Size(480,500)
$label.Text = "DFIRT completed its job successfully. Result has been saved in $CurrentPath\result.txt"
$DFIRTForm.Controls.Add($label)
$DFIRTForm.Topmost = $True
$DFIRTForm.Add_Shown({$DFIRTForm.Activate()})
[void] $DFIRTForm.ShowDialog()