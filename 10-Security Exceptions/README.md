> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

# Security Exceptions in AzTS

## Overview

A security exception is a temporary acknowledgment/acceptance of risk associated with unresolved security control failures.
Some examples of when an exception may be appropriate as a last resort are as follows:
- Teams want to acknowledge the security risk behind the control failure while they need more time to fix the issue
- Remediation efforts are exhausted
- It is not possible to fix the issues until a future product update is delivered
- The business justification outweighs the investment cost to fix (i.e. fixing issues on legacy systems with a near-term retirement date)
- It is a known scenario for which exceptions are allowed

## Types of Exceptions

AzTS supports below exception as of now:
- [Self-Attestation Exceptions](/10-Security%20Exceptions/SelfAttestation.md)
