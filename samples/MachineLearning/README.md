# Create your own machine learning resources for Dynamics 365 Business Central (BC)

The following describes how to deploy your own machine learning resources in Azure for BC to use.

This involves building a container image, uploading the container image to an Azure Container Repository, creating an [Azure Machine Learning online endpoint](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-deploy-online-endpoints?view=azureml-api-2&tabs=cli) using the [custom container image](https://learn.microsoft.com/en-us/azure/machine-learning/how-to-deploy-custom-container?view=azureml-api-2&tabs=cli), and finally pointing your BC instance to the online endpoint.


## Prerequisites

- An Azure subscription in which Azure Machine Learning resources can be deployed
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed

## Steps

Log into the desired Azure subscription in a terminal:

```
az login
```

Deploy machine learning resources using the provided PowerShell script. In the following example, we are using the resource group `MyResourceGroup` in the Azure location `West US`. The resource group will be created if it does not exist. See the documentation in `DeployMachineLearningResources.ps1` for additional parameters.
```
.\DeployMachineLearningResources.ps1 -ResourceGroupName "MyResourceGroup" -Location "West US"
```

This should give an output similar to
```
Logged into subscription 'MySubscription'
Deploying Azure Machine Learning resources in resource group 'MyResourceGroup'.
Creating resource group 'MyResourceGroup' in location 'West US'.
Creating Azure Machine Learning workspace 'bcmlworkspace' in resource group 'MyResourceGroup'.
...
Building container image businesscentralml:latest for Azure Machine Learning model.
...
Creating Azure Machine Learning deployment 'bcmldeployment'.
...
Azure Machine Learning resources deployed successfully.
```

Go to [Azure Machine Learning Studio](https://ml.azure.com/) and locate the created workspace (`bcmlworkspace` if using the standard parameters). Under "Endpoints", go to the "Consume" tab and take a note of the REST endpoint URI and Primary key:

![Azure Machine Learning Studio](images/bcmlendpoint.png)

Finally, add the URI and key to appropriate BC configuration, e.g., to the Sales and Inventory forecast and Late Payment Prediction setups.