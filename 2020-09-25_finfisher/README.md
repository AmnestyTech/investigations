# Technical Report

This repository contains indicators of compromise and scripts related to the report [German-made FinSpy spyware found in Egypt, and Mac and Linux versions revealed ](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/) published by Amnesty Tech in September 2019.

Indicators:

* `domains.txt` : domains identified
* `ips.txt` : IPv4 addresses identified
* `sha256.csv` : sha256 of samples identified
* `rules.yar` : Yara rules

Tools in the script folder:

* `decode_modules.py` : decode encrypted modules of Linux and MacOs
* `read_config.py` : read FinSpy configuration
* `android/extract_config.py` : extract configuration from FinSpy Android samples
* `android/java_parser.py` : extract obfuscated strings from decompiled java code
* `android/string_decoder.py` : decode obfuscated strings
* `linux/extract_config.py` : extract configuration files from a Linux FinSpy installer
* `cobaltstrike/cobaltstrike_config.py`: extract the configuration of a Cobalt Strike payload
* `cobaltstrike/cobaltstrike_decode.py`: decode an obfuscated Cobalt Strike payload

Additional files:

* `android_tlv_list.csv` : list of TLV values extracted from the Android sample
