import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle)


from stix2 import CustomObservable

# @CustomObservable('x-new-observable-2', [
#     ('a_property', properties.StringProperty(required=True)),
#     ('property_2', properties.IntegerProperty()),
# ], [
#     'a_property'
# ])
# class NewObservable2():
#     pass

def hash_format(hash):
    if len(hash) == 32:
        return "md5"
    elif len(hash) == 40:
        return "sha1"
    elif len(hash) == 64:
        return "sha256"
    else:
        return None

if __name__ == "__main__":
    stix2_file_name = "novispy.stix2"
    if os.path.isfile(stix2_file_name):
        os.remove(stix2_file_name)

    with open("domains.txt") as f:
        domains = list(set([a.strip() for a in f.read().split()]))

    with open("package_names.txt") as f:
        package_names = list(set([a.strip() for a in f.read().split()]))

    with open("package_cert_hashes.txt") as f:
        package_cert_hashes = list(set([a.strip() for a in f.read().split()]))

    with open("sha256.txt") as f:
        sha256_hashes = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="NoviSpy", is_family=False, description="IOCs for Serbian NoviSpy Android spyware")
    res.append(malware)
    for d in domains:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[domain-name:value='{}']".format(d), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for package_name in package_names:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[app:id='{}']".format(package_name), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for cert_hash in package_cert_hashes:
        hash_type = hash_format(cert_hash)
        if not hash_type:
            raise ValueError("Unknown hash type for {}".format(cert_hash))

        i = Indicator(indicator_types=["malicious-activity"], pattern=f"[app:cert.{hash_type}='{cert_hash}']", pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for sha256_hash in sha256_hashes:
        if not hash_format(sha256_hash) == "sha256":
            raise ValueError("File hash is not in SHA256 format: {}".format(sha256_hash))
        i = Indicator(indicator_types=["malicious-activity"], pattern=f"[file:hashes.sha256='{sha256_hash}']", pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))


    bundle = Bundle(objects=res)
    with open(stix2_file_name, "w+") as f:
        f.write(bundle.serialize(pretty=True, indent=4))
    print("{} file created".format(stix2_file_name))
