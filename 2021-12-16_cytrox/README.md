# Cytrox Spyware Indicators of Compromise

This repository contains network and device indicators of compromised (IoCs) related to the IOS and Android spyware tools developed by the cyber-surveillance company Cytrox. These indicators were first published in December 2021 by Meta in their [Threat Report on the Surveillance-for-Hire Industry](https://about.fb.com/news/2021/12/taking-action-against-surveillance-for-hire/) and by Citizen Lab in their report [Pegasus vs. Predator - Dissident’s Doubly-Infected iPhone Reveals Cytrox Mercenary Spyware](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/). Additional indicators of compromise were identified by the Amnesty Tech Security Lab as part of an independent investigation.

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android phones and iPhones.

It includes the following files:
* `config_profiles.txt`: UUID of suspicious configuration profiles dropped by the Cytrox spyware
* `cytrox.stix2`: [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro.html) file containing all indicators
* `domains.txt`: list of Cytrox domains
* `file_paths.txt`: file paths for Cytrox payloads on disk in Android and iOS.
