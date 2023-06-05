![](https://komarev.com/ghpvc/?username=mamun-sec&color=blue&label=Total+Recent+Views) ![status](https://img.shields.io/badge/status-up-brightgreen)
<h1>:white_square_button: DFIRT (DFIR Tool)</h1>
<h4>Collect information of Windows PC when doing incident response.</h4>
<br>
:information_source: DFIRT is a Powershell script. It collects information of-
<br>
<ul>
  <li>recently used files,</li>
  <li>suspicious Event ID,</li>
  <li>Powershell history for all session,</li>
  <li>files opened directly from Windows Explorer,</li>
  <li>network related running services,</li>
  <li>free space of disk,</li>
  <li>Internet connectivity information,</li>
  <li>safe DLL search mode,</li>
  <li>last boot up time,</li>
  <li>user accounts list from SID,</li>
  <li>computer name, current build, ID,</li>
  <li>current user language settings,</li>
  <li>Windows Defender Status,</li>
  <li>current Admin Approval Mode policy,</li>
  <li>domain,</li>
  <li>non default folders in Program File.</li>
</ul> 
<br>
<h2>:beginner: How to use:</h2>
1. Download the dfirt.ps1 script.<br>
2. Start Windows Powershell.<br>
3. Go to the DFIR folder.<br>
4. Write <b>.\dfirt.ps1</b> and press Enter.<br>
5. Now, DFIRT will start collecting information and save those information in report.txt file.
<br>
<h2>:warning: Remember</h2>
When you will run the script, result will be saved in report.txt file. But, if you again run the script and there is still previously saved report.txt file in the DFIRT folder then, the file will be overwritten with new report.
<br>
<h2>:speech_balloon: A message to you:</h2>
I will try to continuously add new features to DFIRT. If you wish to add functionality, feel free to contribute here.
