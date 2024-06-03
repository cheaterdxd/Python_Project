import json
import warnings
import requests
warnings.filterwarnings('ignore')


RAW_ALERT_QUERY = {
    "search_query_str":"rule_id = \"\"",
    "since":0,
    "limit":50,
    "sort":{
        "field":"timestamp_create",
        "direction":"desc"
    },
    "last_seconds":2592000,
    "from_timestamp":0,"to_timestamp":0,
    "is_use_last_seconds":True 
}

def search_alert(rule_id=None, query=None, cookie=None, access_token=None, server = "https://10.255.251.153"):
    if rule_id != None:
        query = f"rule_id = \"{rule_id}\""
    RAW_ALERT_QUERY.update({"search_query_str" : query})
    
    #RAW_ALERT_QUERY
    list_alert = requests.post(
        server + "/msalert/Search",
        json = RAW_ALERT_QUERY,
        verify = False,
        headers = {"Cookie":cookie, "Authorization": "Bearer "+access_token}
    )
    return list_alert.json()

def query_alert(query=None, cookie=None, access_token=None, server = "https://10.255.251.153"):
    RAW_ALERT_QUERY.update({"search_query_str" : query})
    #RAW_ALERT_QUERY
    list_alert = requests.post(
        server + "/msalert/Search",
        json = RAW_ALERT_QUERY,
        verify = False,
        headers = {"Cookie":cookie, "Authorization": "Bearer "+access_token}
    )
    return list_alert.json()