## Load remediation script to fix failed controls of Azure Tenant Security Solution - Step by Step
In this section, we will walk through the steps of loading remediation script.

**Note:** You can download remediation script present [here](../RemediationScripts)

Loading script in PowerShell session is divided into four steps:

### **Step 1 of 4. Validate prerequisites on machine**  

  i) Installation steps are supported using following OS options: 	

  - Windows 10
  - Windows Server 2019

  ii) PowerShell 5.0 or higher
  All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](PowerShellTips.md) to get basic understanding.
  Ensure that you are using Windows OS and have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.)
  If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).

  ![PowerShell Version](../../Images/00_PS_Version.png)

### **Step 2 of 4. Installing Az Modules:**

Az modules contains cmdlet to connect to az account.
Install Az PowerShell Modules using below command. 
For more details of Az Modules refer [link](https://docs.microsoft.com/en-us/powershell/azure/install-az-ps)

``` PowerShell
# Install Az Modules
Install-Module -Name Az.Accounts -AllowClobber -Scope CurrentUser -repository PSGallery
```
### **Step 3 of 4. Download and extract remediation package**
 
 Remediation package mainly contains:
 1. **RemediationScripts** which contains powershell scripts to remediate AzTS controls.

If you have already downloaded the remediation package zip, directly go to step (3.d).

3.a. Download remediation package zip from [here](../../TemplateFiles/RemediationScripts.zip?raw=1) to your local machine. </br>

3.b. Extract zip to local folder location. <br/>

3.c. Unblock the content. The below command will help to unblock files. <br/>

  ``` PowerShell
  Get-ChildItem -Path "<Extracted folder path>" -Recurse |  Unblock-File 
  ```

3.d. Point current path to downloaded script folder location and load remediation script in PowerShell session
``` PowerShell
# Point current path to location where script is downloaded and load script from folder

CD "<LocalExtractedFolderPath>\RemediationScripts"

# Before loading remediation script in current session, please connect to AzAccount
Connect-AzAccount

# Load remediation script in session
. ".\<RemediationScriptFileName>.ps1"

# Note: Make sure you copy  '.' present at the start of line.
```

**Step 4 of 4. Execute remediation scripts:**

After completing above mentioned steps, open remediation script in PowerShell and follow instructions as per comments present in each script.
