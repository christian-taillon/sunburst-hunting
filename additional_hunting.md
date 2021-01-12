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
</br>

#### Named Pipe
FireEye noted in their port the existence of a consistent named pipe. If you are collecting these logs you can search for that named pipe __583da945-62af-10e8-4902-a8f205c72b2e__.

If you are using Splunk + Sysmon, the search would be: </br>
_index=$SYSMON_INDEX$ sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (17,18) PipeName=583da945-62af-10e8-4902-a8f205c72b2e_

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


</br></br>
## Exchange Management Shell
Validity is tracking this threat as __Dark Halo__ and believes that they have worked multiple incidents for this in late 2019 and 2020. They believe the attacker is familiar with exploiting Exchange to perform their domain recon and lateral movement.

Consider adding alert mechanisms to EDR solutions that can track use of the [Exchange Management Shell PowerShell cmdlets](https://github.com/christian-taillon/sunburst-hunting/blob/main/indicators/exchange_management_shell.txt).


</br></br>

## OSINT
#### C2 Naming Convention
UNC2452 has been noted to use C2 infrastructure that matches victims hostnames. Consider using services like [RiskIQ/]Passive Total](https://community.riskiq.com/login) or [Shodan.io](Shodan.io) to search for internal hostnames. This could reveal infrastructure used against your company. [2]

As noted in the [README.ME](https://github.com/christian-taillon/sunburst-hunting/blob/main/README.md), I am pulling form a lot of different resources to create [sunburst-hunting/indicators/uniq-hostnames.txt](https://github.com/christian-taillon/sunburst-hunting/blob/main/indicators/uniq-hostnames.txt)
You can use [RedDrip7's project](https://github.com/RedDrip7/SunBurst_DGA_Decode) to decode to see if your domains are on the list. The list of resources we are pulling from includes Passive Total, @bambenek's work, and partner lists.

**update: Now that many have posted publicly lists of targeted internal names, I am also publishing the output list.

A list of identified organizations can be found [here](https://github.com/christian-taillon/sunburst-hunting/blob/main/decoded_names_and_potential_organizations.csv)</br>
A list of decoded internal names can be found [here](https://github.com/christian-taillon/sunburst-hunting/blob/main/indicators/decoded-hostnames.csv)</br>

__:~$ cat /$github_dir$/sunburst-hunting/indicators/uniq-hos
tnames.txt | python decode.py | grep -E "domain1.com|domain2.org"__
</br></br>

##Resources </br>
[1] [ISC.SANS.EDU:SolarWinds Breach](https://isc.sans.edu/forums/diary/SolarWinds+Breach+Used+to+Infiltrate+Customer+Networks+Solarigate/26884/1)

[2] [FireEye SolarWinds Supply Chain Blog](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

[3] [CobaltStrikeForensic](https://github.com/RomanEmelyanov/CobaltStrikeForensic)

[4] [ICS SANS: Quick Tip: Cobalt Strike Beacon Analysis](https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818)

[5]  [fireeye\sunburst_countermeasures](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/BEACON/snort)

[6] [Splunk Blog: Sunburst Backdoor](https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html)
