import requests
import warnings
import os
import sys
sys.path.insert(1,(os.getcwd()+'/../SIEM'))
from siem_rule import get_access_token

warnings.filterwarnings('ignore')


def debug(event=None, access_token=None, cookie=None, server = "https://siem.staging.vcs.vn"):
    dbg = requests.post(
        server + "/cymapi/v1/correl/test", 
        json = {"list_log": [event]},
        verify = False,
        headers = {"Authorization":"Bearer "+get_access_token(cookie, server, "read%3Atool_test_correl")}
    )
    return dbg.json()