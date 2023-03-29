import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("malware.stix2"):
        os.remove("malware.stix2")

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("file_paths.txt") as f:
        filepaths = list(set([a.strip() for a in f.read().split()]))

    with open("android_properties.txt") as f:
        properties = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="AndroidMalware", is_family=False, description="Targeted Android Malware")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for f in filepaths:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:path='{}']".format(f), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for p in properties:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[android-property:name='{}']".format(p), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("malware.stix2", "w+") as f:
        f.write(bundle.serialize(indent=4))
    print("malware.stix2 file created")
