[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Create temporary folder for the script files 
New-Item "$env:Systemdrive\SRE" -ItemType directory -ErrorAction SilentlyContinue

# Start logging
Start-Transcript -Path "$env:Systemdrive\SRE\InstallWebsite.log" -Force -Append -ErrorAction Stop

# Install KB for Windows Management Framework 5.1
if (!(Get-HotFix -id KB3191564)) {
    Write-Verbose "KB3191564 isn't installed"
    Write-Verbose "Downloading KB3191564" -Verbose
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=839516" -OutFile "$env:Systemdrive\SRE\KB3191564-x64.msu" -Verbose
    Write-Verbose "Installing KB3191564" -Verbose
    Start-Process -FilePath 'wusa' -ArgumentList "$env:Systemdrive\SRE\KB3191564-x64.msu /extract:$env:Systemdrive\SRE\KB" -wait -PassThru -Verbose
    Start-Process -FilePath 'dism' -ArgumentList "/online /add-package /PackagePath:$env:Systemdrive\SRE\KB /NoRestart /quiet" -wait -PassThru -Verbose
    Write-Verbose "Installation complete" -Verbose 
} 
else {
    Write-Verbose "KB3191564 is already installed"
}

# Add scheduler
$scriptPath = $MyInvocation.MyCommand.Path
$taskName ="ScheduledTaskTP"
$Trigger = New-ScheduledTaskTrigger -AtStartUp 
$User = "NT AUTHORITY\SYSTEM"
$Action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy ByPass -command $scriptPath"
if ((Get-ScheduledTask -TaskName "ScheduledTaskTP" -ErrorAction SilentlyContinue ).State -eq 'Ready') {
    Write-Verbose "Scheduled task already exist" -Verbose
}
else {
    Write-Verbose "Start Adding new Sceduled Task" -Verbose
    Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force 
    Write-Verbose "Schedulled task successfully added" -Verbose
}

# .NET framework configuration
$NetBuildVersion = 379893

if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | ForEach-Object { $_ -match 'Release' }) {
    [int]$CurrentRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
    if ($CurrentRelease -lt $NetBuildVersion) {
        Write-Verbose "Current .NET build version is less than 4.5.2 ($CurrentRelease)" -Verbose
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe" -OutFile "$env:Systemdrive\SRE\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" -Verbose
        Write-Verbose "Installation of .NET 4.5.2 is started. Instance will be rebooted after installation" -Verbose
        Start-Process "$env:Systemdrive\SRE\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" -ArgumentList "/q /forcerestart" -wait
        while ($CurrentRelease -lt $NetBuildVersion) {
            Write-Verbose "Waiting for reboot" -Verbose
            Start-Sleep -Seconds 10
        }
      }
      else {
        Write-Verbose "Current .NET build version is the same as or higher than 4.5.2 ($CurrentRelease)" -Verbose
      }
} 
else {
    Write-Verbose ".NET build version not recognised" -Verbose
}

# Downloading test application
if (!(Test-Path "$env:Systemdrive\SRE\master.zip")) {
    Write-Verbose "Downloading test application" -Verbose
    Invoke-WebRequest -Uri "https://github.com/TargetProcess/TestTaskSRE/archive/master.zip" -OutFile "$env:Systemdrive\SRE\master.zip" -Verbose
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory("$env:Systemdrive\SRE\master.zip", "$env:Systemdrive\SRE\TestTaskSRE-master")
}
elseif (Test-Path "$env:Systemdrive\SRE\master.zip") {
    Write-Verbose "Test application is already exists" -Verbose
}

# Installing package provider and module for Powershell DSC
if (!((Get-PackageProvider -ListAvailable).name -eq "NuGet")) {
    Write-Verbose "Installing NuGet package provider" -Verbose
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
} else {
    Write-Verbose "NuGet package is already installed" -Verbose
}

if (!((Get-InstalledModule).name -eq "xWebAdministration")) {
    Write-Verbose "Installing  xWebAdministration module" -Verbose
    Install-Module  xWebAdministration -Force -Verbose
} else {
    Write-Verbose "xWebAdministartion module is already installed" -Verbose
}

# DSC Powershell configuration for IIS
$dsc = @"
Configuration IISWebsite
{
    param(
        `$NodeName
    )
    Import-DscResource -Module PSDesiredStateConfiguration, xWebAdministration
    
    Node `$NodeName
    {
        WindowsFeature 'NetFramework45'
        {
            Name   = 'NET-Framework-45-Core'          
            Ensure = 'Present'
        }
        WindowsFeature IIS
        {
            Ensure = "Present"
            Name = "Web-Server"
        }
        WindowsFeature ASP
        {
            Ensure = "Present"
            Name = "Web-Asp-Net45"
        }
        WindowsFeature Web_Mgmt_Tool
        {
            Ensure = "Present"
            Name = "Web-Mgmt-Tools"
        }
        WindowsFeature WAS
        {
            Ensure = "Present"
            Name = "WAS"
        }
        File WebContent
        {
            Ensure = "Present"
            Type = "Directory"
            SourcePath = "C:\SRE\TestTaskSRE-master\TestTaskSRE-master"
            DestinationPath = "C:\inetpub\wwwroot\TestTaskSRE"
            Recurse = `$true
        }
        xWebSite 'TestTaskSRE2' 
        {
            Name = 'Default web Site'
            BindingInfo = @( MSFT_xWebBindingInformation
                {
                    Protocol = 'HTTP'
                    Port = 80
                    IPAddress = "*"
                }
            )
			AuthenticationInfo = MSFT_xWebAuthenticationInformation 
			    {
				    Anonymous = `$true
					Basic = `$false
					Digest = `$false
					Windows = `$false
				}
            PhysicalPath = 'C:\inetpub\wwwroot\'
            ApplicationPool = 'TestTaskSREPOOL2'
            DependsOn = '[xWebAppPool]DefaultTestTaskSRE2'
        }
        xWebAppPool 'DefaultTestTaskSRE2'
        {
            Name = 'TestTaskSREPOOL2'
            Ensure  = "Present"
            State = "Started"
        }
        xWebApplication App
        {
            Ensure = "Present"
            Name = "sretask"
            WebAppPool = "TestTaskSREPOOL2"
            Website = "Default Web Site"
            PhysicalPath = "C:\inetpub\wwwroot\TestTaskSRE"
            DependsOn = "[xWebAppPool]DefaultTestTaskSRE2"
        }
    }
} IISWebsite -NodeName "localhost" -OutputPath "`$env:Systemdrive\SRE"
"@

Write-Verbose "Creating configuration file" -Verbose
Set-Content -path "$env:Systemdrive\SRE\Configuration.ps1" -value $dsc -verbose
$ScriptToRun = "$env:Systemdrive\SRE\Configuration.ps1"
&$ScriptToRun
Write-Verbose "Applying a web server configuration" -Verbose
Start-DscConfiguration -Wait -Verbose -Path "$env:Systemdrive\SRE"

# Fix error in the application config
$webConfig = "$env:Systemdrive\inetpub\wwwroot\TestTaskSRE\Web.config"
if (Test-Path $webConfig) {
    (Get-Content $webConfig) | ForEach-Object {
    $_ -Replace '<system.web.>', '<system.web>' -Replace '<\?xml version="1.0" encoding="utf-8"\?>', '<?xml version="1.0"?>'
    } | Out-File $webConfig
}

# Site status check and slack web-hook
function CheckSite($site="http://localhost/sretask/Home/About") {
    try {
        (((Invoke-WebRequest $site -UseBasicParsing).Content -match "Your application description page") -and (Invoke-WebRequest $site -UseBasicParsing).statusCode -eq "200") 
    }
    catch {
        Write-Verbose "Could not complete the request: $_" -Verbose
    }
}

function SlackMessage($uriSlack="https://hooks.slack.com/services/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") {
    $payload = @{
        "icon_emoji" = ":bomb:";
        "text" = "Test application is ready. You can open it.";
    }
    try {
        if ((Invoke-WebRequest -Uri $uriSlack -Method "POST" -Body (ConvertTo-Json -Compress -InputObject $payload) -UseBasicParsing).StatusCode -eq "200") {
            Write-Verbose "Slack Message sent" -Verbose
            return $true
        }
        else {
            Write-Verbose "Error sending message to Slack" -Verbose
            return $false
        }
    }
    catch {
        Write-Verbose "Message send failed: $_" -Verbose
    }
}

if (CheckSite) {
    SlackMessage
}

Stop-Transcript
