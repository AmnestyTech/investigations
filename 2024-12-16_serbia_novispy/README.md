# NoviSpy Indicators of Compromise

This repository contains indicators of compromise (IoCs) related to the **NoviSpy** Android spyware used by Serbian authorities to target activists and journalists. The NoviSpy spyware has been covertly installed on target Android devices using physical access while at the offices of the Serbian Security Intelligence Agency or police. It is unclear if they spyware is also capable of targeting iPhones. NoviSpy appears to have been developed specifically for the Serbian security services.

These indicators were identified through forensic research by the Amnesty International [Security Lab](https://securitylab.amnesty.org/). More information about the Serbian **NoviSpy** spyware can be found in the Amnesty International's report ["A Digital Prison": Surveillance and the suppression of civil society in Serbia](https://securitylab.amnesty.org/latest/2024/12/serbia-a-digital-prison-spyware-and-cellebrite-used-on-journalists-and-activists/).

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android devices. It should be possible to detect this spyware in Android *bugreports*, and AndroidQF extractions.

It includes the following files:

* `domains.txt`: List of C2 IPs used in NoviSpy spyware samples
* `package_cert_hashes.txt`: Hashes of Android APK signing certificates used by NoviSpy.
* `package_names.txt`: Android package names used in NoviSpy samples.
* `sha256.txt`: Hashes of NoviSpy spyware samples