# Wintego Helios Indicators of Compromise

This repository contains network indicators of compromise (IoCs) related to the Helios spyware developed by cyber-surveillance company Wintego. The Helios spyware is designed to target and compromise Android devices. It is unclear if they spyware is also capable of targeting iPhones. Not the Wintego Helios spyware is unrelated to the *Predator spyware* from Intellexa which has also at times been marketed as *Helios*.

These indicators were identified through internet scanning and other research efforts by the Amnesty International [Security Lab](https://securitylab.amnesty.org/). More information about Wintego and their spywareproducts can be found in the [A Web of Surveillance](https://securitylab.amnesty.org/latest/2024/05/a-web-of-surveillance/) report which is wider investigation into the sales of [spyware and surveillance products to Indonesia](https://securitylab.amnesty.org/latest/2024/05/global-a-web-of-surveillance-unravelling-a-murky-network-of-spyware-exports-to-indonesia/).

The STIX2 file can be used with the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) to look for potential signs of compromise on Android phones and iPhones.

It includes the following files:

* `domains.txt`: list of Wintego Helios spyware domains
