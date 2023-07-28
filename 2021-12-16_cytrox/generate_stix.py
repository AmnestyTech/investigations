import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("cytrox.stix2"):
        os.remove("cytrox.stix2")

    with open("config_profiles.txt") as f:
        configs = list(set([a.strip() for a in f.read().split()]))


    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("file_paths.txt") as f:
        filepaths = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="Predator", is_family=False, description="IOCs for Cytrox Predator")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for f in filepaths:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:path='{}']".format(f), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for c in configs:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[configuration-profile:id='{}']".format(c), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("cytrox.stix2", "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("cytrox.stix2 file created")
