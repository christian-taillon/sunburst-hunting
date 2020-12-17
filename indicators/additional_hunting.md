## Post Compromise Detection Opportunities
In addition to observing the other indicators mentioned in this directory there are other indicators to hunt for that may help to
1. Also indicate a compromise
2. Provide additional insight into the scope
</br></br>

### The existence of netsetupsvc.dll
The presence of this file may indicate a compromise [1][2]

file-path*: “c:\\windows\\syswow64\\netsetupsvc.dll </br>
pid: 17900

[ISC.SANS.EDU:SolarWinds Breach](https://isc.sans.edu/forums/diary/SolarWinds+Breach+Used+to+Infiltrate+Customer+Networks+Solarigate/26884/1)
</br></br>

## Endpoint
#### TEARDROP
TEARDROP is an in memory dropper that is eblieved to execute an augmented Cobalt Strike BEACON. It will read from a fake jpg and decodes embeded paylod with rollign XOR algorithm to load in memory embeeded payload.

[FireEye has two yara rules](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/TEARDROP/yara) to detect TEARDROP [2]

- read from file: 'gracious_truth.jpg'
- check HKU\SOFTWARE\Microsoft\CTF
</br></br>
## Network
#### BEACON
Many resources exist to detect malware beacons. This beacon will be augmented in manner. I would reccomend checking out RomanEmelyanov's [CobaltStrikeForensic](https://github.com/RomanEmelyanov/CobaltStrikeForensic) repo and [ICS SANS: Quick Tip: Cobalt Strike Beacon Analysis](https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818). [3][4]

In addition, if you employee snort, or a technology that can use snort rules, FireEye has also provided signatures to detect this traffic: in the [fireeye\sunburst_countermeasures](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/BEACON/snort). [5]
</br></br>

## OSINT
#### C2 Naming Convention
UNC2452 has been noted to use C2 infrastructure that matches victims hostnames. Consider using services like RiskIQ/Passive Total or Shodan.io to search for internal hostnames. This could reveal infrastructure used against your company. [2]
</br></br>

##Resources </br>
[1] [ISC.SANS.EDU:SolarWinds Breach](https://isc.sans.edu/forums/diary/SolarWinds+Breach+Used+to+Infiltrate+Customer+Networks+Solarigate/26884/1)

[2] [FireEye SolarWinds Supply Chain Blog](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

[3] [CobaltStrikeForensic](https://github.com/RomanEmelyanov/CobaltStrikeForensic)

[4] [ICS SANS: Quick Tip: Cobalt Strike Beacon Analysis](https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818)

[5]  [fireeye\sunburst_countermeasures](https://github.com/fireeye/sunburst_countermeasures/tree/main/rules/BEACON/snort)
