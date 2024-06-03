import requests
import warnings
warnings.filterwarnings('ignore')

def debug(event= None, access_token=None, cookie=None, server = "https://10.255.251.153/"):
    dbg =  requests.post(
        server + "correlation/DebugTest", 
        verify = False,
        headers = {"Authorization": "Bearer "+access_token},
        json = event
    )
    return dbg.json()