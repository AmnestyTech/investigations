# NSO Group Pegasus Indicator of Compromise

This repository contains network and device indicators of compromised related to NSO Group's Pegasus spyware. These indicators are a result of multiple investigations by the Amnesty International Security Lab and other partners. Additional technical information was collected as part of a collaborative investigation, the Pegasus Project coordinated by [Forbidden Stories](https://forbiddenstories.org/) and involving a global network of investigative journalists.

Amnesty International has released a [Technical Methodology report](https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/) which outlines how to use these indicators to hunt for Pegasus and other mobile spyware products. The Amnesty International Security Lab is also releasing an open-source tool, the [Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt). MVT can be used with the the pegasus.stix2 indicators to check a devices for potential signs of compromise with Pegasus spyware.

These indicators include:
* `domains.txt`: list of all Pegasus-related domains, with sub-files:
* `v2_domains.txt`: list of Pegasus Version 2 infrastructure. These domains were identifed and published previously by Citizen Lab
* `v3_domains.txt`: list of Pegasus Version 3 infrastructure
* `v4_domains.txt`: list of Pegasus Version 4 infrastructure
* `v4_validation_domains.txt`: list of Pegasus Version 4 validation/URL shortener domains

## All these domains were converted to a hosts file, so you can use it in applications like AdAway.
