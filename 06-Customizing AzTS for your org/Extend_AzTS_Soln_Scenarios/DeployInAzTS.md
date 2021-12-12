# Deploy the Extended Project in AzTS Solution

You can deploy the org policy customized project in your running AzTS Solution using CICD pipeline. 

You can also deploy the Extended_AzTS function app project in your running AzTS Solution using the Visual Studio by following the below mentioned steps:

1. In **Solution Explorer**, right-click the **`Extended_AzTS`** project and select **Publish**.

2. For Target, choose Azure, which will publish your function app to the Microsoft Cloud.

3. For the Specific target, choose Azure Function App (Windows), which creates a function app that runs on Windows.

4. In Function Instance, choose your Host Subscription and select the AzSK-AzTS-WorkItemProcessor-xxxxx.

5. Select Finish, and on the Publish page, select Publish to deploy the package containing your project files in Azure.

After the deployment completes the root URL of the function app in Azure is shown in the Publish tab.