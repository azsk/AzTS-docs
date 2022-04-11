# CDN

**Resource Type:** Microsoft.Cdn/profiles



![Alt Text](http://i.stack.imgur.com/SBv4T.gif)
___ 

## Azure_CDN_DP_Enable_Https 

### Display Name 
CDN endpoints must use HTTPS protocol while providing data to the client browser/machine or while fetching data from the origin server 

### Rationale 
Use of HTTPS ensures server/service authentication and protects data in transit from network layer man-in-the-middle, eavesdropping, session-hijacking attacks. 

### Control Spec 

> **Passed:** 
One of the following conditions is met:
>- CDN endpoints are configured with HTTPS protocol only or HTTP to HTTPs redirection rule.
>- No CDN endpoints are present in the CDN profile.
> 
> **Failed:** 
> CDN endpoints are not configured with HTTPS protocol only or HTTP to HTTPs redirection rule.

<img src="https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/users/MSFT-Chirag/FeatureConfetti/Assets/Feature-Announcements/Secure-Templates.gif" width="100%" />
