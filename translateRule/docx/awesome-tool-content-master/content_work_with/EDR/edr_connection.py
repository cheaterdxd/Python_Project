#!/usr/bin/env python3
import requests


def login(username=str, password=str, server = "https://10.255.251.153"):
    session = requests.Session()
    session.get(server, verify=False)
    cookie = "token_duration=okay; "+"X-CSRFToken="+session.cookies['X-CSRFToken']+ "; JSESSIONID="+session.cookies['JSESSIONID']
    login_session = requests.post(
        server+"/authentication/SignIn/",
        verify = False, 
        json = {"username":username,"password":password}, 
        headers={"Cookie":cookie}
        )
    access_token = login_session.json()["access_token"]
    cookie +="; access_token="+access_token
    requests.get(server, verify=False, headers={"Cookie":cookie})
    return cookie, access_token

