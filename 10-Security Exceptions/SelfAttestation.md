# Self Attestation Exception

## Overview

Self-Attestation is acknowledgement that the security failure poses no security risk. For example, the team mitigated the risk through code implementation, or the control is expected to fail due to the design of application.

By default the self-attestation feature is not enabled for the AzTs setup. Self-Attestation feature could be enabled by following these [steps](SelfAttestation.md#1-how-to-enable-self-attestation-feature).

Once the self-attesttation feature is enabled, Kindly follow the [instructions](SelfAttestation.md#2-how-to-submit-a-self-attestation-exception) to submitt the self-attestation exception.

## 1. How to enable Self-Attestation feature

Enabling self-attestation involves following steps:
1. Create cosmos db account and table for exception management.
2. Create Key Vault specific to AzTS(If not already present).
3. Store the cosmos db connection string in the Key Vault as secret.
4. Update AzTS API's Key Vault reference identity to user assigned identity.
5. Update AzTS API's app settings to enable self-attestation feature.
6. Create password credential for AzTS UI AAD App.
7. Store AzTS UI AAD App password credential in Key Vault as secret.
8. Update AzTS Scanner's app settings to enable self-attestation feature.

## 2. How to Submit a Self-Attestation Exception

Below are the steps to submit a self-attestation exception
1. Navigate to the AzTS UI.
2. Select the "Exception Mode" toggle button.
3. Expand the subscription to view scan result and select the non-complaint control which has to be attested.
4. After selecting the control, select the 'Action' button in the right corner of the screen and then select 'Add/Renew Exceptions' from the drop down. This will open a pop-up window.
5. In the pop-up window, select the type of exception as 'Self Attestation' and provide a valid business justification.
6. Verify the entered details and select 'Confirm'.
7. Close the pop-up window and re-scan the subscription.

> **Warning** : When attesting controls, the highest level of discretion is required. Justification is required for each attested control in order to document the rationale for bypassing the security control. By attesting to this decision, you are confirming that you are prepared to take accountability for consequences that may occur due to security configurations not being correctly or fully constituted
