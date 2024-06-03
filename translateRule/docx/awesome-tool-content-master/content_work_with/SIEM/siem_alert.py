import json
import requests
import time
import warnings
warnings.filterwarnings('ignore')

RAW_ALERT_SEARCH = {
    "from":0,
    "sort":"-timestamp",
    "size":100,
    "query":"(rule_id = \"\")",
    "counting":True,
    "time_from":0,
    "time_to":0,
    "aggs":"[]",
    "tenants":""
}

def search_alert(rule_id= "", query="", cookie = None, access_token = None, server = "https://siem.staging.vcs.vn"):
    rule_session = requests.post(
        server + "/oauth/authorize?scope=read%3Aalerts&client_id=cym_portal&audience=cym_alert_api&response_type=code&redirect_uri=https%3A%2F%2Fsiem.staging.vcs.vn&include_granted_scope=false",
        verify = False,
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Cookie": cookie,
            "Referer": "https://siem.staging.vcs.vn/alert-management/alerts",
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )

    referer = rule_session.history[0].headers["Location"]

    code = referer.replace(server + "?code=", "")
    rule_session = requests.post(
        server+"/oauth/token",
        verify = False,
        headers = {"Cookie":cookie, "Referer":"https://siem.staging.vcs.vn/alert-management/alerts"},
        data = {"code":code, "client_id":"cym_portal", "grant_type":"authorization_code", "redirect_uri":"https%3A%2F%2Fsiem.staging.vcs.vn", "audience":"cym_alert_api"}
    )
    access_token = rule_session.json()["access_token"]

    #access_token = get_access_token (cookie, "cym_alert_api")
    current_time = time.time()*1000
    time_from = int(current_time-2592000000)
    time_to = int(current_time)

    TMP = RAW_ALERT_SEARCH
    if rule_id != "":
        TMP["query"] = '(rule_id = \"{}\")'.format(rule_id)
    else:
        TMP["query"] = query
    TMP["time_from"] = time_from
    TMP["time_to"] = time_to
    #print (TMP)

    req = requests.post(
        server + "/cymalertapi/v1/alerts/search",
        verify = False,
        headers = {
            "Referer": "https://siem.staging.vcs.vn/alert-management/alerts",
            "Content-Type": "application/json",
            "Authorization": "Bearer " + access_token,
            "Cookie": cookie
            },
        json = TMP
    )
    # alert_list = json.loads(req)
    # return alert_list
    return req.json()