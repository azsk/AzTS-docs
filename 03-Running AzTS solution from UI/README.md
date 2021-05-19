
> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community..

</br>

# Running AzTS solution from UI

##  On this page:

- [Overview](README.md#overview)
- [Prerequisite](README.md#prerequisite)
- [Introduction to AzTS UI and video tutorial](README.md#introduction-to-azts-ui)
- [FAQ](README.md#frequently-asked-questions)

-----------------

## Overview

Tenant reader solution provides a UI-based tool that can be used to perform on-demand scans to verify your fixes sooner, check reasons for control failures and view latest scan results. This tool leverages you current subscription permissions to show you subscriptions that you have the ability to request scans for. 

## Prerequisite

1. Signed in user must have one of the following permission at subscription or resource group scope: Owner, Contributor, ServiceAdministrator, CoAdministrator, AccountAdministrator, Security Reader, Security Admin.
2. Subscription scan should have completed for the day. The steps to validate this has been specified under [this section](/01-Setup%20and%20getting%20started/README.md#steps-3-of-3-verify-azts-ui-is-working-as-expected).

> **Note:**
> 1. If you have been recently granted access, you either need to wait for the next scheduled scan to read the latest RBAC data or request an existing owner of a subscription to perform an ad hoc scan for the subscription using AzTS UI.
>

</br>

## Introduction to AzTS UI

The UI is fairly self-explanatory and also has a "Guided Tour" feature that should show you the basic usage workflow. Learn more about AzTS UI from the following video tutorial.

[![UI](../Images/04_UI_Overview.gif)](https://azsk-azts-cdn.azureedge.net/videosforpublicgithubdoc/Ext_Introduction_About_AzTS_UI.mp4)

## Video tutorials

Here are some additional video tutorials explaining the features provided by AzTS UI.

### **How to scan subscription manually**
[![UI](../Images/04_UI_SubmitForScan.gif)](https://azsk-azts-cdn.azureedge.net/videosforpublicgithubdoc/Ext_Scan_Subscription_Manually.mp4)

### **How to export control scan logs to local machine**
[![UI](../Images/04_UI_ExportToCSV.gif)](https://azsk-azts-cdn.azureedge.net/videosforpublicgithubdoc/Ext_Export_To_CSV.mp4)


### **Frequently Asked Questions**

</br>

**Q: Where can I find AzTS UI URL?**

Link to the AzTS UI is provided at the end of installation command ```Install-AzSKTenantSecuritySolution``` (as shown below).
&nbsp;&nbsp;![UI](../Images/13_TSS_UIUrlPrintMessageInPSOutput.png)