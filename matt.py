import json
import sys
import requests
import getpass
import urllib3
urllib3.disable_warnings()

menu = {}
menu["1"]="-- Display a list of all the FTD hostnames and IPs" 
menu["2"]="-- Display the entire JSON object returned natively from the FMC API"

while True: 
    options=menu.keys()
    
    print("\n" * 100)
    print("\n\n")
    print("      #################################################")
    print("      ###                                           ###")
    print("      ###  MATT'S AWESOME FIREPOWER SCRIPTY THINGY  ###")
    print("      ###                                           ###")
    print("      #################################################\n\n")

    for entry in options: 
        print(entry, menu[entry])

    selection=input("\nSelect an option: ")
    
    if selection in menu:
        break
       
server_start = "https://"
server_main = input("\nEnter the IP or FQDN of your FMC: https://")
server = server_start + server_main

username = input("Username: ")
password = getpass.getpass("Password: ")

print("\nQuerying the FMC API, please wait....", end ="")

orig_stdout = sys.stdout
sys.stdout = open('output.txt', 'w')

r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path

try:
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    auth_domain = auth_headers.get('DOMAIN_UUID', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token 

api_path = "/api/fmc_config/v1/domain/" + auth_domain + "/devices/devicerecords?expanded=true&limit=1000"

url = server + api_path

if (url[-1] == '/'):
    url = url[:-1]
 
try:
    r = requests.get(url, headers=headers, verify=False)
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        json_resp = json.loads(resp)
    else:
        r.raise_for_status()
        print("Error occurred in GET --> "+resp)

except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err)) 

finally:
    if r : r.close()
    
if selection == "1":
    print("Hostname\t\tIP Address")
    print("========\t\t==========")
    for FTD in json_resp['items']:
        print(FTD['name'] + " \t" + FTD['hostName'])
elif selection == "2":
    print(json.dumps(json_resp['items'],indent=3, separators=(',', ': ')))
else:
    sys.exit()
    
sys.stdout = orig_stdout
print("DONE!\n\nLook for a file called output.txt in the same directory this script executed from.\n")
input("Press <Enter> to close this window.")
