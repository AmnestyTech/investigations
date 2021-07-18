import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("pegasus.stix2"):
        os.remove("pegasus.stix2")

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("files.txt") as f:
        filenames = list(set([a.strip() for a in f.read().split()]))

    with open("processes.txt") as f:
        processes = list(set([a.strip() for a in f.read().split()]))

    with open("emails.txt") as f:
        emails = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="Pegasus", is_family=False, description="IOCs for Pegasus")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for p in processes:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[process:name='{}']".format(p), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for f in filenames:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:name='{}']".format(f), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for e in emails:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[email-addr:value='{}']".format(e), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("pegasus.stix2", "w+") as f:
        f.write(str(bundle))
    print("pegasus.stix2 file created")
