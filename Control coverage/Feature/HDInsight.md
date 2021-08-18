## HDInsight

| ControlId | Dependent Azure API(s) and Properties | Control spec |
|-----------|-------------------------------------|------------------|
| <b>ControlId:</b><br>Azure_HDInsight_Deploy_Supported_Cluster_Version<br><b>DisplayName:</b><br>HDInsight must have supported HDI cluster version<br><b>Description: </b><br> HDInsight must have supported HDI cluster version |<b> ARM API to lists all the HDInsight clusters under the subscription. </b> </br> /subscriptions/{0}/providers/Microsoft.HDInsight/clusters? <br> api-version=2018-06-01-preview <br><b>Properties:</b><br> properties.clusterVersion | <b>Passed: </b><br> Cluster version is greater or equal to minimum required version (e.g. 3.6.0). <br><b>Failed: </b><br> Cluster version is less than minimum required version. |
