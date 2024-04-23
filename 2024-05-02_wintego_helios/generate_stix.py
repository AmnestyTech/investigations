import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("wintego_helios.stix2"):
        os.remove("wintego_helios.stix2")

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="Wintego Helios", is_family=False, description="IOCs related to the Wintego Helios spyware")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("wintego_helios.stix2", "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("wintego_helios.stix2 file created")
