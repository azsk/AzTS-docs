## Load remediation script to fix failed controls of Azure Tenant Security Solution - Step by Step
In this section, we will walk through the steps of loading remediation script.

**Note:** You can download remediation script present [here](../RemediationScripts)

Loading script in PowerShell session is divided into three steps:

**1. Validate prerequisites on machine**  
  i) Installation steps are supported using following OS options: 	

  - Windows 10
  - Windows Server 2019

  ii) PowerShell 5.0 or higher
  All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](PowerShellTips.md) to get basic understanding.
  Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.)
  If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).

  ![PowerShell Version](../../Images/00_PS_Version.png)

  **2. Download remediation script:**

  i) Open GitHub page from [here](https://github.com/azsk/AzTS-docs/tree/main/Scripts/RemediationScripts) to download remediation script to your local machine.

**3. Unblock downloaded remediation script:**

i) Unblock the content. Below command will help to unblock files

``` PowerShell
Get-ChildItem -Path "<Remediation script folder path>" -Recurse |  Unblock-File 
```

ii) Point current path to downloaded script folder location and load remediation script in PowerShell session
``` PowerShell
# Point current path to location where script is downloaded and load script from folder

CD "<RemediationScriptFilePath>"

# Load remediation script in session
. ".\<RemediationScriptFileName>.ps1"

# Note: Make sure you copy  '.' present at the start of line.

```