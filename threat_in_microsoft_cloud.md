# Post-Compromise - Mictosoft Cloud

 [CISA](https://us-cert.cisa.gov/ncas/alerts/aa21-008a) and others have discussed this APTs attention to Microsoft Cloud observed from public and private sector victims. The nature of this type of threat is less frequently addressed in advisories; when compared to the attention given to internal network security. Here we will discuss some information and guidance primarily from Microsoft and CISA.


# Detection
Microsoft's cloud environments have built in detections for unusual activity. Additionally, many collect telemetry from Microsoft Graph or Audit APIs and ingest into a SIEM. Both of these can be reviewed for signs of abnormal activity.


__Monitor for App Registration and Service Principals__</br>
The adversary has been observed targeting Azure AD as a component of its lateral movement. As mentioned in readme, this is done with compromised administrative accounts or by forging SAML tokens with compromised signing tokens.[2][6]

__SAML__
- No associated account with token
- Impossible tokens: default is 1-hour token ttl; long lived tokens could indicate malicious activity.
- Tokens should be issues before use. An identical timestamp for both creation and use should not occur.

If you brought Azure AD data into a SIEM you can look for the following:</br>
_note: these queries will be in SPL; however, the same events can be searched for with other query languages in other products_

__Added Service Principal__ </br>
_sourcetype="azure:aad:audit" activityDisplayName="Add service principal credentials"_

__Permission or Role Assignment__ </br>
_sourcetype="azure:aad:audit" activityDisplayName="Add app role assignment to service principal" OR
activityDisplayName="Add delegated permission grant" OR activityDisplayName="Add application"_

__Multi Tenant Apps__ </br>
_sourcetype="azure:aad:audit" activityDisplayName="Update application" operationType=Update
result=success targetResources{}.modifiedProperties{}.displayName=AvailableToOtherTenants_


## CrowdStrikes Reporting Tool for Azure
CRT is a free community tool that will help organizations quickly and easily review excessive permissions in their Azure AD environments to help determine configuration weaknesses and provide advice to mitigate this risk.</br>
[CRT](https://www.crowdstrike.com/resources/community-tools/crt-crowdstrike-reporting-tool-for-azure/)

- look for non-interactive sign in for applications
- audit trust relationships with Azure AD
- look for new token validation tiem periods with long times

[CISA's Sparrow](https://github.com/cisagov/Sparrow) and Open Source [Hawk](https://github.com/T0pCyber/hawk) are also reccomended resources.

## Resources </br>
[1] [FireEye SolarWinds Supply Chain Blog](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

[2][Splunk Blog: Sunburst Backdoor](https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html)

[3][CROWDSTRIKE REPORTING TOOL FOR AZURE](https://www.crowdstrike.com/resources/community-tools/crt-crowdstrike-reporting-tool-for-azure/)
