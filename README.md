# This is powershell script for IIS installation and configuration
The details of the task are located here: https://github.com/TargetProcess/TestTaskSRE  
Example of usage:
```powershell
PS> .\SREtask.ps1
```  
This script will install necessary software, IIS and deploy the application on it. Verify the deployment by navigating to your server address in your preferred browser:
- ```http://localhost``` - should opened default IIS html page;
- ```http://localhost/sretask``` - should opened deployed application.
