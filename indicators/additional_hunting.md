## Post Compromise Detection Opportunities
In addition to observing the other indicators mentioned in this directory there are other indicators to hunt for that may help to
1. Also indicate a compromise
2. Provide additional insight into the scope
</br></br>

### The existence of netsetupsvc.dll
The presence of this file may indicate a compromise [1][2]

_file-path*: “c:\\windows\\syswow64\\netsetupsvc.dll" </br>
pid: 17900_

[ISC.SANS.EDU:SolarWinds Breach](https://isc.sans.edu/forums/diary/SolarWinds+Breach+Used+to+Infiltrate+Customer+Networks+Solarigate/26884/1)
</br></br>

## Endpoint
#### TEARDROP
TEARDROP is an in memory dropper that is believed to execute an augmented Cobalt Strike BEACON. It will read from a fake jpg and decodes embedded payload with roiling XOR algorithm to load in memory embedder payload.

[FireEye has two yara rules](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/TEARDROP/yara) to detect TEARDROP [2]

- read from file: 'gracious_truth.jpg'
- check HKU\SOFTWARE\Microsoft\CTF
</br></br>
## Network
#### BEACON
Many resources exist to detect malware beacons. This beacon will be augmented in manner. I would recommend checking out RomanEmelyanov's [CobaltStrikeForensic](https://github.com/RomanEmelyanov/CobaltStrikeForensic) repo and [ICS SANS: Quick Tip: Cobalt Strike Beacon Analysis](https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818). [3][4]

In addition, if you employee snort, or a technology that can use snort rules, FireEye has also provided signatures to detect this traffic: in the [fireeye\sunburst_countermeasures](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/BEACON/snort). [5]
</br></br>

#### URL Strings
After reviewing provided snort alerts release by FireEye [2], we noticed that there are some trigs that might still be good to examine for those without a Snort installation but access to Web logs.</br>

__url contains__ </br>
_/swip/upd/SolarWinds.CortexPlugin.Components.xml </br>
swip/Upload.ashx </br>
/swip/upd/_
</br></br>

## Cloud
#### Azure AD
Monitor for App Registration and Service Principals
The adversary has been observed targeting Azure AD as a component of its lateral movement. As mentioned in readme, this is done with compromised administrative accounts or by forging SAML tokens with compromised signing tokens.[2][6]

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


</br></br>

## OSINT
#### C2 Naming Convention
UNC2452 has been noted to use C2 infrastructure that matches victims hostnames. Consider using services like [RiskIQ/]Passive Total](https://community.riskiq.com/login) or [Shodan.io](Shodan.io) to search for internal hostnames. This could reveal infrastructure used against your company. [2]
</br></br>

##Resources </br>
[1] [ISC.SANS.EDU:SolarWinds Breach](https://isc.sans.edu/forums/diary/SolarWinds+Breach+Used+to+Infiltrate+Customer+Networks+Solarigate/26884/1)

[2] [FireEye SolarWinds Supply Chain Blog](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

[3] [CobaltStrikeForensic](https://github.com/RomanEmelyanov/CobaltStrikeForensic)

[4] [ICS SANS: Quick Tip: Cobalt Strike Beacon Analysis](https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818)

[5]  [fireeye\sunburst_countermeasures](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/BEACON/snort)

[6] [Splunk Blog: Sunburst Backdoor](https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html)
