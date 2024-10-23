## **Prerequisites**

### **Validate prerequisites on machine**  
<br/>

  1.  Installation steps are supported using following OS options: 	

      - Windows 10 or higher
      - Windows Server 2019 or higher
  
  <br/>

  2. PowerShell 5.0 or higher:

      All setup steps will be performed with the help of PowerShell ISE console. If you are unaware of PowerShell ISE, refer [link](PowerShellTips.md) to get a basic understanding.
       Validate that you have PowerShell version 5.0 or higher by typing **$PSVersionTable** in the PowerShell ISE console window and looking at the PSVersion in the output as shown below.) 
      <br/>

      If the PSVersion is older than 5.0, update PowerShell from [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616). 
      
      ![PowerShell Version](../Images/00_PS_Version.png)

  <br/>

  3. PowerShell language mode FullLanguage:  

      To run AzTS MMA Removal Utility setup script, PowerShell language mode for the session must be FullLanguage.
      Ensure that you are using FullLanguage mode by typing **$ExecutionContext.SessionState.LanguageMode** in the PowerShell ISE console window. More details about PowerShell language mode can be found [here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?source=recommendations&view=powershell-7.3).  

      ![PowerShell Language Mode](../Images/00_PS_Language_Mode.png)  
    
  <br/>

  4. Bicep installation:  

      To run bicep-based deployment scripts as part of infra setup, a bicep installation is required. Verify if bicep is installed by running **bicep --version** and install if not already available:

      ![Bicep Version](../Images/00_PS_Bicep_Version.png)

        To install it via Powershell please refer to [install via powershell](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/install#azure-powershell) or to install manually refer to [install manually](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/install#windows).


[Back to top…](#prerequisites)

<br/>

### **Download and extract deployment package**
 
 Deployment package mainly contains:
- **Bicep templates** which contains resource configuration details that need to be created as part of the setup.
- **Deployment setup scripts** which provides the cmdlet to run installation. <br/>

Download and extract deployment package using the below steps.

1. Download deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/AzTSMMARemovalUtilityDeploymentFiles.zip) to your local machine. <br/>

2. Extract zip to local folder location. <br/>

3. Unblock the content. The below command will help to unblock files. <br/>

  ``` PowerShell
  Get-ChildItem -Path "<Extracted folder path>" -Recurse | Unblock-File 
  ```
[Back to top…](#prerequisites)

<br/>

