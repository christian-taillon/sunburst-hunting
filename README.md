# sunburst
This repository contains NBI and file hashes to help researchers detect SUNBURST. Many different organizations are providing hashes others aren't. This is just an attempt to compile all indicators and some analysis of the reports available for responders. 

The NBI are provided as is to help researchers and threat hunters and can be used as high confidence categorically.
The file hashes are known compromised, high confidence.

#### Attribution
FireEye is tracking this adversary as UNC2452, but some have attributed this activity to APT29 / Cozy Bear. At this time not enough information is available to confirm that APT29 is behind this attack.

#### Execution
Execution
The backdoor infected .dll in the SolarWinds install directory, when executed, installs the implant as a Windows service and .dll file in the following directories.

###### SolarWinds DLL in install folder
_PROGRAMFILES\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll_

###### Main implant
_WINDIR\System32\config\systemprofile\AppData\Local\Assembly\tmp\$varriable_folder_name$\SolarWinds.Orion.Core.BusinessLayer.dll._

#### Period of Dormancy
Period of Dormancy
After a dormant period of around two weeks, it executes commands, called Jobs, including various capabilities such as the ability to profile the system, reboot the machine, disable services, transfer files, and load additional malware. The malicious DLL communicates to avsvmcloud[dot]com using DGA subdomains to prepare possible second-stage malware, accomplish lateral movement, or exfiltrate data. It masquerades its network traffic as the Orion Improvement Program protocol. It stores obtained recon data in legitimate plug-in config files. Its actions all intend to mimic the activity expected from Orion.

#### Second-Stage Payloads
Along with SUNBURST, samples have been observed dropping a memory-only dropper called TEARDROP, which was used to deploy Cobalt Strike beacons, a popular tool by many of our adversaries.

#### Command and Control (C2)
As noted, the adversaries use domain generated algorithms (DGA) to build subdomains of the avsvmcloud[dot]com. This communication can be used for the additional payloads or to exfiltrate data. Hostnames have matched those found monitored by the victim’s Orion instance. It appears that the adversary will also use VPS infrastructure hosted in the same country as the victim.

### Security Advisories  
[SolarWinds Security Advisory - SUNBURST](https://www.solarwinds.com/securityadvisory) </br>
[Continually Updated SolarWinds Security Advisory](https://www.solarwinds.com/securityadvisory)</br>
[DHS - Emergency Directive 21-01](https://cyber.dhs.gov/ed/21-01/)

### Resources and Recognition
[FireEye White Paper: SUNBURST Backdoor](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)</br>
[Microsoft Customer Guidance SUNBURST](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks)</br>
[Threat Advisory: SolarWinds supply chain attack](https://blog.talosintelligence.com/2020/12/solarwinds-supplychain-coverage.html)</br>
[SolarWinds SUNBURST Backdoor](https://blog.rapid7.com/2020/12/14/solarwinds-sunburst-backdoor-supply-chain-attack-what-you-need-to-know/)</br>
[unit42: SolarStorm and SUNBURST Customer Coverage](https://unit42.paloaltonetworks.com/fireeye-solarstorm-sunburst/)

Special thanks to John Bambenek @bambenek who started with identifying NBI beyond initial scope of [FireEye published indicators](https://github.com/fireeye/sunburst_countermeasures).
