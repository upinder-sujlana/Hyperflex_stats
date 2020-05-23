#!/usr/bin/python

import json
import requests
import math
import os
import subprocess
import shlex
import sys
import traceback
import getpass

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests.exceptions import ConnectionError

__author__     = 'Upinder Sujlana'
__copyright__  = 'Copyright 2020, HX Performance and stats info using REST API'
__version__    = '1.0.4'
__maintainer__ = 'Upinder Sujlana'
__status__     = 'prod'

#---------------------------------------------------------------------------------------------------
def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])
#----------------------------------------------------------------------------------------------------
def getAccessToken(cmip,user,pwd):
    try:
        url="https://{}/aaa/v1/auth?grant_type=password".format(cmip)
        payload={"username": user, "password": pwd ,"client_id": "HxGuiClient","client_secret": "Sunnyvale","redirect_uri": "http://localhost:8080/aaa/redirect"}
        data=json.dumps(payload)
        headers={'content-type':'application/json'}
        try:
            response = requests.post(url, data, auth=(user, pwd),headers=headers,verify=False)
        except KeyError:
            print ("\nIssue getting the access token. Please make sure you have not run the script too many times in a 15 minute period"+ "\nAlso verify the username, password and cluster management IP supplied. Exiting.\n")
            sys.exit(1)
        except ConnectionError:
            print ("\nIssue getting the access token. Please make sure you have not run the script too many times in a 15 minute period"+ "\nAlso verify the cluster management IP supplied. Exiting.\n")
            sys.exit(1)
        except Exception as e:
            print ("getAccessToken. A. Error getting the Access Token. Exiting the Script.")
            print (traceback.format_exc())
            sys.exit(1)

        if response.status_code:
            return  response.json()
        else:
            print ("getAccessToken. B. Error getting the Access Token. Exiting the Script.")
            sys.exit(1)
    except Exception as e:
        print ("getAccessToken. C. Something went wrong getting the access token.")
        print (traceback.format_exc())
#---------------------------------------------------------------------------------------------------
def getClusterDetails(access_token,cmip):
    try:
        headers = {'Accept': 'application/json','Authorization':access_token}
        url="https://{}/coreapi/v1/clusters".format(cmip)
        response = requests.get(url, headers=headers, verify=False)
        if response:
            return response.json()[0]['uuid']
        else:
            return
    except Exception as e:
        print ("getClusterDetails: Something went wrong in getting cluster details")
        print (traceback.format_exc())
#--------------------------------------------------------------------------------------------------
def getClusterVersion(access_token,cuuid,cmip):
    try:
        headers = {'Accept': 'application/json','Authorization':access_token}
        url="https://{}/coreapi/v1/clusters/{}/about".format(cmip,cuuid)
        response = requests.get(url, headers=headers,verify=False)
        if response.status_code:
            if response.json()['hypervisor']=="ESX":
                print ("================================================================")
                print ("\n"+"Cluster OS type         :- " + response.json()['hypervisor'] +"i")
            else:
                print ("================================================================")
                print ("\n"+"Cluster OS type         :- " + response.json()['hypervisor'])
            print ("Server type(s)          :- " + response.json()['modelNumber'])
            print ("Server SN(s) in cluster :- " + response.json()['serialNumber'])
            print ("HXDP version            :- " + response.json()['displayVersion']+"\n")
        print ("================================================================")
    except Exception as e:
        print ("getClusterVersion: Something went wrong in getting cluster version")
        print (traceback.format_exc())
#---------------------------------------------------------------------------------------------------
def getStats(access_token,cuuid,cmip):
    try:
        headers={'Authorization': access_token}
        url="https://{}/coreapi/v1/clusters/{}/stats".format(cmip,cuuid)
        response = requests.get(url, headers=headers,verify=False)
        if response.status_code:
            return response.json()
    except Exception as e:
        print ("getStats(): Something went wrong getting the stats.")
        print (traceback.format_exc())
#---------------------------------------------------------------------------------------------------
def printStats(clusterstats):
    print ("\nCluster UUID         :- " + clusterstats["uuid"])
    print ("Total Capacity       :- " + convert_size(clusterstats["totalCapacityInBytes"]) )
    print ("Used  Capacity       :- " + convert_size(clusterstats["usedCapacityInBytes"])  )
    print ("Free  Capacity       :- " + convert_size(clusterstats["freeCapacityInBytes"])  )
    print ("Dedup Saving         :- " + str(clusterstats["deduplicationSavings"])[:5] + " %")
    print ("Compression Saving   :- " + str(clusterstats["compressionSavings"])[:5] + " %")
    print ("Storage state        :- " + clusterstats["enospaceState"])
#--------------------------------------------------------------------------------------------------
def getClusterDetail(access_token,cuuid,cmip):
    try:
        headers={'Authorization': access_token}
        url="https://{}/coreapi/v1/clusters/{}/detail".format(cmip,cuuid)
        response = requests.get(url, headers=headers,verify=False)
        if response.status_code:
            print ("\nCluster Name             :- " + response.json()['name'])
            print ("All Flash Cluster        :- " + str(response.json()['allFlash']))
            print ("Replication Factor       :- " + response.json()['dataReplicationFactor'])
            print ("No. of Nodes in Cluster  :- " + str(response.json()['numNodesConfigured']))
            print ("No. of Nodes Online      :- " + str(response.json()['numNodesOnline']))
            print ("Cluster Access Policy    :- " + response.json()['clusterAccessPolicy'])
            print ("\n================================================================")
    except Exception as e:
        print ("getClusterDetail(): Something went wrong getting the stats.")
        print (traceback.format_exc())
#--------------------------------------------------------------------------------------------------
def getNodes(access_token,cuuid,cmip):
    try:
        headers={'Authorization': access_token, 'Accept': 'application/json'}
        url="https://{}/coreapi/v1/clusters/{}/nodes".format(cmip,cuuid)
        response = requests.get(url, headers=headers,verify=False)
        if response.status_code:
            for x in response.json():
                for key,value in x.items():
                    key=str(key)
                    if key=='ctlVmIdentity':
                        print ("\nSCVM UUID  :- " + value['uuid'])
                    if key=='name':
                        print ("eth1 ip    :- " + str(value))
                    if key=='master':
                        print ("CRM Master :- " + str(value))
                    if key=='disks':
                        print ("Disks      :-")
                        for i in value:
                            for k in i:
                                if k=='uuid':
                                    print ("              " + i[k])
        print ("\n================================================================")
    except Exception as e:
        print ("getNodes(): Something went wrong getting the stats.")
        print (traceback.format_exc())
#---------------------------------------------------------------------------------------------------
def getDatastores(access_token,cuuid,cmip):
    try:
        headers={'Authorization': access_token, 'Accept': 'application/json'}
        url="https://{}/coreapi/v1/clusters/{}/datastores".format(cmip,cuuid)
        response = requests.get(url, headers=headers,verify=False)
        if response.status_code:
            for d in response.json():
                print ("\n"+"Datastore Name :- " + d["dsconfig"]["name"])
                print ("Datastore size :- " + str(convert_size(d["dsconfig"]["provisionedCapacity"])) )
                print ("Free capacity  :- " + str(convert_size(d["freeCapacityInBytes"])) )
                if "mountSummary" in d.keys():
                    print ("Mount Status   :- " + d["mountSummary"])
                for x in d["hostMountStatus"]:
                    print ("Host - " + x["hostName"] + " - mounted - "+ str(x["mounted"]) )
        print ("\n"+"================================================================")
    except Exception as e:
        print ("getDatastores(): Something went wrong getting the stats.")
        print (traceback.format_exc())
#--------------------------------------------------------------------------------------------------
def revoke_token_v2(entire_auth, cmip):
    cmd = """curl -k -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{"access_token": "%s", "refresh_token": "%s","token_type": "Bearer"}' 'https://%s/aaa/v1/revoke'""" % (entire_auth['access_token'], entire_auth['refresh_token'], cmip)
    proc = subprocess.Popen(shlex.split(cmd), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    cmd_output, cmd_error = proc.communicate()
    cmd_output = cmd_output.decode(sys.stdout.encoding if sys.stdout.encoding else 'UTF8')
    if cmd_output =="{}":
        print ("\n"+"================================================================")
        print ("\n" +"All data collected. Good Bye.!!!")
        print ("\n"+"================================================================")
    else:
        print ("\n"+"================================================================")
        print ("Had issues revoking token. Please run the script again after 5 minutes. Thanks.")
        print ("\n"+"================================================================")
#---------------------------------------------------------------------------------------------------
def main():
    #Get the username, password and CMIP
    if sys.version < "3":
        USERNAME=raw_input("Cluster username:")
    else:
        USERNAME=input("Cluster username:")

    PASSWD=getpass.getpass("Password for " + USERNAME + ":")
    if sys.version < "3":
        CMIP=raw_input("Cluster management IP:")
    else:
        CMIP=input("Cluster management IP:")


    #Step -1 - Get Token
    entire_auth = getAccessToken(CMIP,USERNAME,PASSWD)
    try:
        access_token= "Bearer " + entire_auth['access_token']
        refresh_token= entire_auth['refresh_token']
    except KeyError:
        print ("\nIssue getting the access token. Please make sure you have not run the script too many times in a 15 minute period"+ "\nAlso verify the username, password and cluster management IP supplied. Exiting.\n")
        sys.exit(1)

    #Step - 2 - get cluster cuuid
    CUUID = getClusterDetails(access_token,CMIP)

    #Step -3 - Lets Print the cluster version etc details
    getClusterVersion(access_token,CUUID,CMIP)

    #Step -4 - Get the cluster details
    getClusterDetail(access_token,CUUID,CMIP)

    #Step -5 - Get Node, disk and CRM master info
    getNodes(access_token,CUUID,CMIP)

    #Step - 6 - Get Datastores
    getDatastores(access_token,CUUID,CMIP)

    #Step - 7 - get the cluster stats
    clusterstats={}
    if CUUID.strip():
        clusterstats=getStats(access_token,CUUID,CMIP)
        printStats(clusterstats)


    #End of the script. Revoking the token to clean up behind.
    revoke_token_v2(entire_auth, CMIP)
#----------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
