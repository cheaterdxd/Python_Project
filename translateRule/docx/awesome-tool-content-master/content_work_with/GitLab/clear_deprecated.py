import os
import sys
import argparse
"""
vcs-mitre-att-ck-version-2
awesome-tool-content
└──content_work_with
    └──GitLab
        └──clear_deprecated.py
"""
prefix_path = lambda  a: a.replace('/', '\\') if os.name != 'posix' else a


def get_args():
    parser = argparse.ArgumentParser(description="Convert rule Offline")
    parser.add_argument("-p", "--platform", dest="platform", help="EDR/SIEM")
    parser.add_argument("-r", "--root", dest="root", help="VCS Mitre ATT&CK Version 2 root path")
    return parser.parse_args()

def main():
    ROOT_PATH = '../../../'
    args = get_args()
    if args.root != None:
        ROOT_PATH = args.root
    ROOT_PATH.replace('\\', '/')
    if ROOT_PATH[-1] != '/':
        ROOT_PATH += '/'
    path = {
        'deprecated_rule_path' : ROOT_PATH + 'vcs-mitre-att-ck-version-2/deprecated/rules',
        'guides_path' : ROOT_PATH + 'vcs-mitre-att-ck-version-2/guides',
        'rules_path' : ROOT_PATH + 'vcs-mitre-att-ck-version-2'
    }

    deprecated_path = prefix_path(os.path.abspath(path['deprecated_rule_path'] + '/' + args.platform))
    try:
        list_deprecated_rule = os.listdir(deprecated_path)
        for item in list_deprecated_rule:
            file_path = prefix_path(path['rules_path'] + '/' + args.platform + '/' + item)
            if os.path.exists(file_path):
                os.remove(file_path)
                print (f"[o] Removed {file_path}")

            file_name = item.replace('.zip', '.md')
            docs_path = prefix_path(path['guides_path'] + '/' + args.platform + '/' + file_name)
            if os.path.exists(docs_path):
                os.remove(docs_path)
                print (f"[o] Removed {docs_path}")
                
    except Exception as e:
        print (e, file=sys.stderr)

main()
