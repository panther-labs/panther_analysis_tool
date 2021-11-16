#!/usr/bin/env python3

import re
import sys

def get_current_version():
    with open ("../setup.py", "r") as file:
        for line in file.readlines():
            if 'version=' in line:
                current_ver = str(re.findall("[+-]?\d+\.\d+\.\d+", line)[0])
                print (current_ver)
                return current_ver

def update_version(current_ver, new_ver):
    files_to_update = [ '../setup.py', '../panther_analysis_tool/main.py']
    for file in files_to_update:
        with open(file, "r") as old_file:
            filedata = old_file.read()
            filedata = filedata.replace(current_ver, new_ver)
            with open(file, "w") as new_file:
                new_file.write(filedata)

def main():
    if len(sys.argv) == 1:
        print("Usage: version_bump.py <new version>")
        print("Example: version_bump.py 10.2.4")
        sys.exit(1)
    new_ver = sys.argv[1]
    old_ver = get_current_version()

    print(f"The current version is {old_ver}, you are about to create a new version: {new_ver}.")
    confirm = input("Continue? ")
    if confirm == "y":
        update_version(old_ver, new_ver)
    else:
        print("Cancelled")
        sys.exit(1)

main()
