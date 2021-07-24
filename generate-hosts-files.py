import os
from os import listdir
from os.path import isfile, join

'''
    - Lookup all not-hidden folders and sub-folders
    - Check for domains files
    - Generate hosts file for them
'''


def list_public_folders_in(directory):
    sub_folders = [x[0] for x in os.walk(directory)]
    return filter(lambda folder: "./." not in folder, sub_folders)


def find_domains_file_in_folder(folder):
    only_files = [join(folder, f) for f in listdir(folder) if isfile(join(folder, f))]
    domains = filter(lambda file: "domains.txt" in file, only_files)

    return domains


def transform_domains_to_hosts(domains_file_path):
    hosts_file_path = domains_file_path.replace("domain", "host")
    with open(hosts_file_path, 'w') as hosts_file:
        with open(domains_file_path, 'r') as domains_file:
            domain_lines = domains_file.readlines()
            for line in domain_lines:
                if "#" not in line and "//" not in line and len(line) > 2:
                    hosts_file.writelines("127.0.0.1\t" + line)


def generate_hosts_files(root):
    public_folders = list_public_folders_in(root)
    for directory in public_folders:
        domains = find_domains_file_in_folder(directory)
        for domains_file_path in domains:
            transform_domains_to_hosts(domains_file_path)


generate_hosts_files('.')
