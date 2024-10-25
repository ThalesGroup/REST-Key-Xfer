# key-rest-cmds
#
# definition file of assorted REST Commands for communicating
# with the source and destination servers
#
######################################################################
import  requests
from    urllib3.exceptions import InsecureRequestWarning
import  json
from    kerrors import *
from    krestenums import *

import  enum
import  re

# ---------------- CONSTANTS -----------------------------------------------------
STATUS_CODE_OK      = 200
STATUS_CODE_CREATED = 201

HTTPS_PORT_VALUE    = 443

SRC_REST_PREAMBLE   = "/SKLM/rest/v1/"
DST_REST_PREAMBLE   = "/api/v1/"

APP_JSON            = "application/json"

MANAGED_OBJECT      = "managedObject"


def makeHexStr(t_val):
# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

def printJList(t_str, t_jList):
# -------------------------------------------------------------------------------
# A quick subscript that makes it easy to print out a list of JSON information in
# a more readable format.
# -------------------------------------------------------------------------------    
    print("\n ", t_str, json.dumps(t_jList, skipkeys = True, allow_nan = True, indent = 3))

def listToDict(t_list):
# -------------------------------------------------------------------------------
# Simple routine to take a string of word followed by values and turn them
# into a dictionary of string values.  Note that we need to clean up
# leading and trailing spaces
# -------------------------------------------------------------------------------
    t_dict = {}

    for i in range(0, len(t_list), 2):
        t_key = t_list[i]
        t_key = t_key.strip()
        t_value = t_list[i + 1]
        t_value = t_value.strip()
        t_dict[t_key] = t_value

    return t_dict


def bracketsToDict(t_stringWithBrackets):
# -------------------------------------------------------------------------------
# Simple routing that changes a string of "[[Idx 0] [Type Text] [Value 12345]]"
# to a dictionary of {"Idx": "0", "Type":"Text", "Value":"12345"}
# into a dictionary of string values.  Note that we need to clean up
# leading and trailing spaces
# -------------------------------------------------------------------------------
    t_dict  = {}     # create now to return later

    t_nameStr = t_stringWithBrackets.strip()    # remove leading and trailing spaces
    t_nameStr = t_nameStr.strip('[[')           # remove leading and trailing spaces
    t_nameStr = t_nameStr.strip(']]')           # remove leading and trailing spaces
    t_nameStr = t_nameStr.replace(' [', ', [')  # Replace spaces before brackets with commas for easier parsing
    t_nameStr = t_nameStr.replace('] ', '], ')  # Replace spaces before brackets with commas for easier parsing
    t_nameStr = t_nameStr.replace(' [', '')     # Remove leading brackets
    t_nameStr = t_nameStr.replace(']', '')      # Remove trailing brackets

    t_nameStrList = t_nameStr.split(',') # create a list of the elements in the string.  Note elements are separated by a comma

    for element in t_nameStrList:
        t_split     = element.split()
        t_key       = t_split[0]
        t_value     = t_split[1]
        t_dict[t_key]  = t_value

    return t_dict

def createSrcAuthStr(t_srcHost, t_srcPort, t_srcUser, t_srcPass):
# -----------------------------------------------------------------------------
# REST Assembly for Src LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the src host in return for a AUTHORIZATION STRING (token)
# that is used for authentication of other commands
# -----------------------------------------------------------------------------
    t_srcRESTLogin          = SRC_REST_PREAMBLE + "ckms/login"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTLogin)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON}
    t_srcBody               = {"userid":t_srcUser, "password":t_srcPass}

    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that GKLM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the userID and password.
    r = requests.post(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("createSrcAuthStr", r)
        exit()

    # Extract the UserAuthId from the value of the key-value pair of the JSON reponse.
    t_srcUserAuthID         = r.json()['UserAuthId']
    t_srcAuthStr            = "SKLMAuth UserAuthId="+t_srcUserAuthID 

    return t_srcAuthStr

def getSrcObjList(t_srcHost, t_srcPort, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading List of Src Cryptographic Objects 
#
# The objective of this section is to querry a list of cryptographic
# objects current stored or managed by the src host.

# Returns a list of cryptographic objects
# -----------------------------------------------------------------------------
    t_srcRESTListObjects    = SRC_REST_PREAMBLE + "objects"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcObjList", r)
        exit()

    t_srcObjList           = r.json()[MANAGED_OBJECT]

    return t_srcObjList

def getSrcObjData(t_srcHost, t_srcPort, t_srcObjList, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Object Data 
#
# Using the getSrcObjList API above, the src host delivers all BUT the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------
    t_srcRESTListObjects        = SRC_REST_PREAMBLE + "objects"
    t_ListLen = len(t_srcObjList)

    t_srcObjData    = [] # created list to be returned later

    for obj in range(t_ListLen):
        t_srcObjID          = t_srcObjList[obj][GKLMAttributeType.UUID.value]
        t_srcHostRESTCmd    = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects, t_srcObjID)
        t_srcHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcObj", r)
            exit()

        t_data   = r.json()[MANAGED_OBJECT]
        t_srcObjData.append(t_data)     # Add data to list
        
    return t_srcObjData

def getSrcKeyList(t_srcHost, t_srcPort, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key List 
#
# Using the keys API, the src host delivers all material EXCEPT for the actual
# key block of keys.  Once we have this information (especially the UUID), we can
# retrieve the key block material
#
# Returns a list of keys, but no key material
# -----------------------------------------------------------------------------
    t_srcRESTListKeys       = SRC_REST_PREAMBLE + "keys"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListKeys)

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcKeyList", r)
        exit()

    t_srcKeyList           = r.json()

    return t_srcKeyList

def getSrcKeyDataList(t_srcHost, t_srcPort, t_srcKeyList, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Key Data 
#
# Using the getSrcKeyList API above, this routine queries the src and returns
# the KEYBLOCK for each key.
#
# NOTE that this call exports the key into an encrypted file on GKLM....
# -----------------------------------------------------------------------------
    t_srcRESTGetKeys        = SRC_REST_PREAMBLE + "keys/export"
    t_ListLen               = len(t_srcKeyList)

    t_srcKeyDataList        = [] # created list to be returned later

    for obj in range(t_ListLen):
        t_srcKeyAlias       = t_srcKeyList[obj][GKLMAttributeType.ALIAS.value]
        t_srcHostRESTCmd    = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTGetKeys, t_srcKeyAlias)
        
        t_srcHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print(r)
            # kPrintError("getSrcKeyDataList", r)
            exit()

        t_data          = r.json()
        t_srcKeyDataList.append(t_data)     # Add data to list

        print("Src Key ", obj, " Alias:", t_srcKeyDataList[obj][GKLMAttributeType.ALIAS.value])
        
    return t_srcKeyDataList


def getSrcObjDataListByClient(t_srcHost, t_srcPort, t_srcAuthStr, t_suuid, t_objectType, t_client):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific Data via OBJECT
#
# SKLM will allow KMIP clients to create keys without associating them to an SKLM User.
# When we attempt to retrieve any key that is not associated with a user, we get
# error message.  HOWEVER, if we specify the client name in the request, the 
# error is avoided.
# -----------------------------------------------------------------------------
    
    if len(t_client) > 0:
        t_srcRESTObjects = SRC_REST_PREAMBLE + "objects?objectType=" + t_objectType + "&clientName=" + t_client
    else:
        t_srcRESTObjects = SRC_REST_PREAMBLE + "objects?objectType=" + t_objectType

    t_srcObjDataList = [] # created list to be returned later

    t_srcHostRESTCmd = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTObjects)
    t_srcHeaders    = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    # now that everything is organized, go get the list of key objects from SKLM
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcObjDataListByClient", r)
    else:
        # Note that the keyObjects do NOT include key blocks.  We will get that later.
        t_Objects   = r.json()[MANAGED_OBJECT]  

        # For SYMMETRIC KEYS, go through the list of objects and retrieve the key material AND key block.
        # The key block can ONLY be obtained by explicity specifing the UUID of the key from the REST
        # endpoint.  Therefore, you need to retreive EACH key by its UUID.
        if t_objectType == GKLMAttributeType.SYMMETRIC_KEY.value:
            t_srcObjDataList = getSrcKeyObjDetailList(t_srcHost, t_srcPort, t_srcAuthStr, t_Objects, t_suuid, t_client)

        elif t_objectType == GKLMAttributeType.SECRET_DATA.value:
            t_srcObjDataList = getSrcSecretObjDetailList(t_srcHost, t_srcPort, t_srcAuthStr, t_Objects, t_suuid, t_client)

    # printJList("srcKeyObjDataList:", t_srcObjDataList)
    return t_srcObjDataList

def getSrcKeyObjDetailList(t_srcHost, t_srcPort, t_srcAuthStr, t_srcObj, t_suuid, t_client):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific SYMMETRIC KEY Data via OBJECT
# -----------------------------------------------------------------------------
    
    t_srcKeyObjDetailList   = []
    t_ListLen               = len(t_srcObj)
    t_srcRESTObjectDetail = SRC_REST_PREAMBLE + "objects"

    for obj in range(t_ListLen):

        t_srcObjID      = t_srcObj[obj][GKLMAttributeType.UUID.value]
        t_kt            = str(t_srcObj[obj][GKLMAttributeType.KEY_TYPE.value])
        t_srcObjAlias   = t_srcObj[obj][GKLMAttributeType.ALIAS.value]

        t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTObjectDetail, t_srcObjID)
        t_srcHeaders    = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcKeyObjDetailList", r)
            break   # stop processing the objects.

        elif len(t_suuid) == 0: # add data unless a specific UUID is specified
            t_data   = r.json()[MANAGED_OBJECT]
            t_data[GKLMAttributeType.CLIENT_NAME.value] = t_client # save associated client name
            t_srcKeyObjDetailList.append(t_data)     # Add data to list
                
        elif t_suuid in t_srcObjID: # only append data if the specified UUID is a match (or submatch) of the t_srcObjID
            t_data   = r.json()[MANAGED_OBJECT]
            t_data[GKLMAttributeType.CLIENT_NAME.value] = t_client # save associated client name
            t_srcKeyObjDetailList.append(t_data)     # Add data to list

    # printJList("t_srcKeyObjDetailList:", t_srcKeyObjDetailList)
    return t_srcKeyObjDetailList

def getSrcSecretObjDetailList(t_srcHost, t_srcPort, t_srcAuthStr, t_srcObj, t_suuid, t_client):
# -----------------------------------------------------------------------------
# REST Assembly for reading specific SECRET Data via OBJECT
# -----------------------------------------------------------------------------
    
    t_srcSecretObjDetailList   = []
    t_ListLen               = len(t_srcObj)
    t_srcRESTObjectDetail = SRC_REST_PREAMBLE + "objects"

    for obj in range(t_ListLen):

        t_srcObjID      = t_srcObj[obj][GKLMAttributeType.UUID.value]

        t_srcHostRESTCmd = "https://%s:%s%s/%s" %(t_srcHost, t_srcPort, t_srcRESTObjectDetail, t_srcObjID)
        t_srcHeaders    = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

        r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            kPrintError("getSrcSecretObjDetailList", r)
            break   # stop processing the objects.

        elif len(t_suuid) == 0: # add data unless a specific UUID is specified
            t_data   = r.json()[MANAGED_OBJECT]
            t_data[GKLMAttributeType.CLIENT_NAME.value] = t_client # save associated client name
            t_srcSecretObjDetailList.append(t_data)     # Add data to list
                
        elif t_suuid in t_srcObjID: # only append data if the specified UUID is a match (or submatch) of the t_srcObjID
            t_data   = r.json()[MANAGED_OBJECT]
            t_data[GKLMAttributeType.CLIENT_NAME.value] = t_client # save associated client name
            t_srcSecretObjDetailList.append(t_data)     # Add data to list

    # printJList("t_srcSecretObjDetailList:", t_srcSecretObjDetailList)
    return t_srcSecretObjDetailList

def printSrcKeyList(t_srcKeyList):
# -----------------------------------------------------------------------------
# Display the contents of a srcKeyList
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_srcKeyList)

    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  
        # Python gets confused if they are all converted as part of the string assembly of tmpStr
        
        t_alias = str(t_srcKeyList[obj][GKLMAttributeType.ALIAS.value])
        t_uuid  = str(t_srcKeyList[obj][GKLMAttributeType.UUID.value])
        t_ksn   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_NAME.value])
        t_ksu   = str(t_srcKeyList[obj][GKLMAttributeType.KEY_STORE_UUID.value])
        t_usage = str(t_srcKeyList[obj][GKLMAttributeType.USAGE.value])
        t_kt    = str(t_srcKeyList[obj][GKLMAttributeType.KEY_TYPE.value])
        
        tmpStr =    "\nSrc Key List Info: %s Alias: %s UUID: %s"    \
                    "\n  Key Store Name: %s Key Store UUID: %s"  \
                    "\n  Usage: %s Key Type: %s" \
                    %(obj, t_alias, t_uuid, t_ksn, t_ksu, t_usage, t_kt)

        print(tmpStr)
    return t_success

def convertGKLMHashToString(t_GKLMHash):
# -----------------------------------------------------------------------------
# GKLM stores the has a string that looks like:
#  [[INDEX 0] [HASH SHA256] [VALUE xcc,x43,xd9,x72,xd8,x0f,x57,xb7,x5a,x01,xf4,x42,x16,x42,x0a,x90,x63,xf3,xf0,xd7,x46,x6a,x58,x56,x18,x4d,x04,xad,xac,xf0,x9d,x10] [DIGESTED_KEY_FORMAT RAW]]
#
# But this is onweildly.  This routine trims out all of the brackets, commas, x's
# and leading and  trailing block information.
#
# This routine uses a couple of temporary string variables to trim down the string
# -----------------------------------------------------------------------------

    t_Header    = "[VALUE "     # string that preceeds the hash value
    t_sizeH     = len(t_Header)
    t_Trailer   = " [DIGESTED"  # first few characters of string at end of hash value
    t_chars     = "[^0-9a-f]"          # only characters that need to be kept
    
    t_startPos  = t_GKLMHash.find(t_Header)
    t_endPos    = t_GKLMHash.find(t_Trailer)
    
    tmpStr1     = t_GKLMHash[t_startPos+t_sizeH:t_endPos]
    tmpStr2     = re.sub(t_chars, "", tmpStr1)
        
    return tmpStr2

def printSrcKeyObjDataList(t_srcKeyObjDataList):
# -----------------------------------------------------------------------------
# Display the contents of a srcKeyObjDataList
# -----------------------------------------------------------------------------
    
    t_success           = True
    t_ListLen           = len(t_srcKeyObjDataList)
        
    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  
        # Python gets confused if they are all converted as part of the string assembly of tmpStr.  tmpStr.strip("[]")
        
        t_alias     = str(t_srcKeyObjDataList[obj][GKLMAttributeType.ALIAS.value])
        t_uuid      = str(t_srcKeyObjDataList[obj][GKLMAttributeType.UUID.value])
        t_kt        = str(t_srcKeyObjDataList[obj][GKLMAttributeType.KEY_TYPE.value])
        t_hv        = str(t_srcKeyObjDataList[obj][GKLMAttributeType.DIGEST.value])
        t_client    = str(t_srcKeyObjDataList[obj][GKLMAttributeType.CLIENT_NAME.value])
        
        tmpStr =    "\nSrc Key Obj: %s" \
                    "\n  Alias: %s"   \
                    "\n  UUID: %s"              \
                    "\n  Client Name: %s"       \
                    "\n  Key Type: %s "         \
                    "\n  Hash: %s"              \
                    %(obj, t_alias.strip("[]"), t_uuid, t_client, t_kt, convertGKLMHashToString(t_hv))

        print(tmpStr)            
        
    return t_success

def printSrcSecretObjDataList(t_srcSecretObjDataList):
# -----------------------------------------------------------------------------
# Display the contents of a srcSecretObjDataList
# -----------------------------------------------------------------------------

    t_success           = True
    t_ListLen           = len(t_srcSecretObjDataList)
        
    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  
        # Python gets confused if they are all converted as part of the string assembly of tmpStr.  tmpStr.strip("[]")
        
        # t_alias     = str(t_srcSecretObjDataList[obj][GKLMAttributeType.ALIAS.value])
        t_uuid        = str(t_srcSecretObjDataList[obj][GKLMAttributeType.UUID.value])
        t_type        = str(t_srcSecretObjDataList[obj][GKLMAttributeType.TYPE.value])
        # t_hv        = str(t_srcSecretObjDataList[obj][GKLMAttributeType.DIGEST.value])
        t_client    = str(t_srcSecretObjDataList[obj][GKLMAttributeType.CLIENT_NAME.value])

        t_alias     = "alias"
        t_hv        = "hv"
        
        tmpStr =    "\nSrc Secret Obj: %s"      \
                    "\n  Alias: %s"             \
                    "\n  UUID: %s"              \
                    "\n  Client Name: %s"       \
                    "\n  Secret Type: %s "         \
                    "\n  Hash: %s"              \
                    %(obj, t_alias.strip("[]"), t_uuid, t_client, t_type, convertGKLMHashToString(t_hv))

        print(tmpStr)            
        
    return t_success

def createDstAuthStr(t_dstHost, t_dstPort, t_dstUser, t_dstPass):
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the dst host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------

    t_dstRESTTokens         = DST_REST_PREAMBLE + "auth/tokens/"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTTokens)    

    t_dstHeaders            = {"Content-Type":APP_JSON}
    t_dstBody               = {"name":t_dstUser, "password":t_dstPass}

    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that CM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the username and password.
    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_dstBody), headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("createDstAuthStr", r)
        exit()

    # Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
    t_dstUserBearerToken            = r.json()['jwt']
    t_dstAuthStr                    = "Bearer "+t_dstUserBearerToken

    return t_dstAuthStr

def getDstObjList(t_dstHost, t_dstPort, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for DESTINATION OBJECT READING KEYS
# 
# The objective of this section is to use the Dst Authorization / Bearer Token
# to query the dst hosts REST interface about keys.
# -----------------------------------------------------------------------------

    t_dstRESTKeyList        = DST_REST_PREAMBLE + "vault/keys2"
    t_dstHostRESTCmd        = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyList)   

    t_dstHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_dstAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getDstObjList", r)
        exit()

    t_dstObjList           = r.json()[CMAttributeType.RESOURCES.value]

    # print("\n         Dst Objects: ", t_dstObjList[0].keys())
    return t_dstObjList
    
def exportDstObjData(t_dstHost, t_dstPort, t_dstObjList, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for EXPORTING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

    t_dstRESTAPI            = DST_REST_PREAMBLE + "vault/keys2"
    t_dstRESTKeyExportFlag  = "export"
    
    t_dstObjData            = [] # created list to be returned later
    t_ObjCnt                = 0  # Initialize counter
    t_ListLen               = len(t_dstObjList)
    
    for obj in range(t_ListLen):
        dstObjID    = t_dstObjList[obj][CMAttributeType.ID.value]
        dstObjName  = t_dstObjList[obj][CMAttributeType.NAME.value]

        # If the object is not exportable, then an error code will be returned.  So, check for exportability prior to
        # attempting to export the key material from the DESTINATION.
        if t_dstObjList[obj][CMAttributeType.UNEXPORTABLE.value]==True:
            tmpStr ="Dst Obj: %s Name: %s *UNEXPORTABLE*" %(obj, dstObjName)
            # print(tmpStr)
            continue

        t_dstHostRESTCmd = "https://%s:%s%s/%s/%s" %(t_dstHost, t_dstPort, t_dstRESTAPI, dstObjID, t_dstRESTKeyExportFlag)
        t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            print("  Obj ID:", dstObjID)
            kPrintError("exportDstObjData", r)
            continue

        t_data      = r.json()        
        t_dstObjData.append(t_data)  #Add data to te list
        
        # tmpStr ="Dst Obj: %s Name: %s " %(obj, dstObjName)
        # print(tmpStr)
        
        t_ObjCnt += 1

    return t_dstObjData

def importDstDataKeyObject(t_dstHost, t_dstPort, t_dstUser, t_dstAuthStr, t_xKeyObj):
# -----------------------------------------------------------------------------
# REST Assembly for IMPORTING specific Key Object Data into DESTINATION HOST
#
# Using the VAULT/KEYS2 API, this code adds individual keys to the desitation.
# This routine needs to be called for EACH key that needs to be written.
#
# Note that an ERROR will occur if a key of the same name already exists in the 
# destination.
# -----------------------------------------------------------------------------

    t_dstRESTKeyCreate        = DST_REST_PREAMBLE + "vault/keys2"

    t_dstHostRESTCmd = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTKeyCreate)
    t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_xKeyObj), headers=t_dstHeaders, verify=False)

    t_success = True
    if(r.status_code == STATUS_CODE_CREATED):
        t_Response      = r.json()        
        # print("  ->Key Object Created: ", t_Response[CMAttributeType.NAME.value])
    else:
        kPrintError("importDstDataKeyObject", r)        
        t_success = False
        
    return t_success

def importDstDataSecretObject(t_dstHost, t_dstPort, t_dstUser, t_dstAuthStr, t_xSecretObj):
# -----------------------------------------------------------------------------
# REST Assembly for IMPORTING specific Secret Object Data into DESTINATION HOST
#
# Using the VAULT/SECRETS API, this code adds individual SECRETS to the desitation.
# This routine needs to be called for EACH secret that needs to be written.
#
# Note that an ERROR will occur if a secret of the same name already exists in the 
# destination.
# -----------------------------------------------------------------------------

    t_dstRESTCmd        = DST_REST_PREAMBLE + "vault/secrets"

    t_dstHostRESTCmd = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTCmd)
    t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_xSecretObj), headers=t_dstHeaders, verify=False)

    t_success = True
    if(r.status_code == STATUS_CODE_CREATED):
        t_Response      = r.json()        
        # print("  ->Secret Object Created: ", t_Response[CMAttributeType.NAME.value])
    else:
        kPrintError("importDstDataSecretObject", r)        
        t_success = False
        
    return t_success

def printDstKeyObjList(t_dstObjList):
# -----------------------------------------------------------------------------
# Display the contents of a dstKeyObjList
# -----------------------------------------------------------------------------
    t_ListLen           = len(t_dstObjList)

    t_success           = True
    for obj in range(t_ListLen):
        
        # Separate string conversions before sending.  Python gets confused if they are all converted as part of the string assembly of tmpStr.
        # Error checking added in case an attribute is missing (may happen with opaque objects)
        
        try:
            t_name  = str(t_dstObjList[obj][CMAttributeType.NAME.value])
            t_uuid  = str(t_dstObjList[obj][CMAttributeType.UUID.value])
            t_ot    = str(t_dstObjList[obj][CMAttributeType.OBJECT_TYPE.value])
            t_fp    = str(t_dstObjList[obj][CMAttributeType.SHA256_FINGERPRINT.value])
        
            tmpStr =    "\nDst Key Obj: %s Name: %s" \
            "\n  UUID: %s" \
            "\n  Key Type: %s" \
            "\n  Hash: %s" \
            %(obj, t_name, t_uuid, t_ot, t_fp)
            
        except Exception as e:
            t_success           = False
            tmpStr =    "\nDst Key Obj: %s Name: %s" \
            "\n  UUID: %s" \
            "\n  Key Type: %s" \
            %(obj, t_name, t_uuid, t_ot)

        print(tmpStr)
    return t_success

def printDstObjDataAndOwner(t_dstObjData, t_UserDict):
# -----------------------------------------------------------------------------
# Display the contents of a dstObjData
# -----------------------------------------------------------------------------
    t_ListLen   = len(t_dstObjData)

    t_success   = True
    for obj in range(t_ListLen):
     
        # Separate string conversions before sending.  Python gets confused if 
        # they are all converted as part of the string assembly of tmpStr.
        # Error checking added in case an attribute is missing (may happen with opaque objects)
        
        try:
            t_name  = str(t_dstObjData[obj][CMAttributeType.NAME.value])
            t_uuid  = str(t_dstObjData[obj][CMAttributeType.UUID.value])
            t_ot    = str(t_dstObjData[obj][CMAttributeType.OBJECT_TYPE.value])
            t_fp    = str(t_dstObjData[obj][CMAttributeType.SHA256_FINGERPRINT.value])
            t_meta  = str(t_dstObjData[obj][CMAttributeType.META.value])
            t_oID   = str(t_dstObjData[obj][CMAttributeType.META.value][CMAttributeType.OWNER_ID.value])
            t_alias = str(t_dstObjData[obj][CMAttributeType.ALIASES.value][0][CMAliasesAttribute.ALIAS.value])
            t_owner = t_UserDict[t_oID]
            
            tmpStr  = "\nDst Obj: %s Name: %s" \
            "\n  UUID: %s" \
            "\n  Key Type: %s" \
            "\n  Hash: %s" \
            "\n  OwnerID: %s (%s)" \
            "\n  Alias: %s" \
            %(obj, t_name, t_uuid, t_ot, t_fp, t_oID, t_owner, t_alias)
            # "\n  Meta: %s" \
            # %(obj, t_name, t_uuid, t_ot, t_fp, t_oID, t_owner, t_meta)
                    
        except Exception as e:
            t_success   = False
            tmpStr      = "\nDst ObjE: %s Name: %s" \
            "\n  UUID: %s" \
            "\n  Key Type: %s" \
            %(obj, t_name, t_uuid, t_ot)

        print(tmpStr)

    return t_success

def getDstUserSelf(t_dstHost, t_dstPort, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for collecting name, usernickname, and user_ID information
#
# Using the account that was used to authenticate to CM (hereto defined as 'self')
# collect the various names for the user, including name, username, and user_ID
# -----------------------------------------------------------------------------

    t_dstRESTUserMgmtSelf   = DST_REST_PREAMBLE + "usermgmt/users/self" #Note that the user 'self'
        
    t_dstHostRESTCmd    = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTUserMgmtSelf)
    t_dstHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("getDstUserSelf:", r)
        kPrintError("getDstUserSelf", r)
        exit() # bail

    t_userInfo = r.json()
    
    return t_userInfo

def getDstUsersAll(t_dstHost, t_dstPort, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for collecting name, usernickname, and user_ID information for
# all users on CM.
# -----------------------------------------------------------------------------

    t_dstRESTUserMgmtSelf   = DST_REST_PREAMBLE + "usermgmt/users" 
        
    t_dstHostRESTCmd    = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTUserMgmtSelf)
    t_dstHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("getDstUsersAll:", r)
        kPrintError("getDstUsersAll", r)
        exit()

    t_userInfo = r.json()
    
    return t_userInfo

def getDstGroupsAll(t_dstHost, t_dstPort, t_dstAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for collecting groups on CM.
# -----------------------------------------------------------------------------

    t_dstRESTURI   = DST_REST_PREAMBLE + "usermgmt/groups/?limit=1000" 
        
    t_dstHostRESTCmd    = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTURI)
    t_dstHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("getDstGroupAll:", r)
        kPrintError("getDstGroupAll", r)
        exit()

    t_Info = r.json()
    
    return t_Info

def createDstUsrGroup(t_dstHost, t_dstPort, t_dstAuthStr, t_usrGroup):
# -----------------------------------------------------------------------------
# REST Assembly for creating a new user group
# -----------------------------------------------------------------------------

    t_dstRESTURI   = DST_REST_PREAMBLE + "usermgmt/groups" 
        
    t_dstHostRESTCmd    = "https://%s:%s%s" %(t_dstHost, t_dstPort, t_dstRESTURI)
    t_dstHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    t_dstBody               = {"name":t_usrGroup}
    r = requests.post(t_dstHostRESTCmd, data=json.dumps(t_dstBody), headers=t_dstHeaders, verify=False)
    
    if(r.status_code != STATUS_CODE_CREATED):
        print("createDstUsrGroup:", r)
        kPrintError("createDstUsrGroup", r)
        exit()
    else:
        print(" ", t_usrGroup, "has been created.")

    t_Info = r.json()
    
    return t_Info

def addDstUsrToGroup(t_dstHost, t_dstPort, t_dstAuthStr, t_userName, t_userID, t_usrGroup):
# -----------------------------------------------------------------------------
# REST Assembly for creating a new user group
# -----------------------------------------------------------------------------

    t_dstRESTURI   = DST_REST_PREAMBLE + "usermgmt/groups" 
        
    t_grpAndUsrURIExt   = "/%s/users/%s" %(t_usrGroup, t_userID)
    t_dstHostRESTCmd    = "https://%s:%s%s%s" \
                        %(t_dstHost, t_dstPort, t_dstRESTURI, t_grpAndUsrURIExt)
        
    t_dstHeaders        = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    r = requests.post(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    
    if(r.status_code != STATUS_CODE_OK):
        print("addDstUsrToGroup:", r)
        kPrintError("addDstUsrToGroup", r)
        exit()
    else:
        print(" ", t_userName, "has been added to the", t_usrGroup, "group.")

    t_Info = r.json()
    
    return t_Info

def getDstKeyByName(t_dstHost, t_dstPort, t_dstAuthStr, t_dstKeyName):
# -----------------------------------------------------------------------------
# REST Assembly for READING specific Object Data from DESTINATION HOST
#
# Using the VAULT/KEYS2 API above, the dst host delivers all but the actual
# key block of object.  This section returns and collects the key block for 
# each object.
# -----------------------------------------------------------------------------

    t_dstRESTAPI               = DST_REST_PREAMBLE + "vault/keys2/?name="
    
    t_dstHostRESTCmd = "https://%s:%s%s%s" %(t_dstHost, t_dstPort, t_dstRESTAPI, t_dstKeyName)
    t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}

    # Note that REST Command does not require a body object in this GET REST Command
    r = requests.get(t_dstHostRESTCmd, headers=t_dstHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        print("  dstKeyNme:", t_dstKeyName)
        kPrintError("getDstKeyByName", r)

    t_data      = r.json()[CMAttributeType.RESOURCES.value][0]
    
    return t_data

def addDataObjectToGroup(t_dstHost, t_dstPort, t_dstGrp, t_dstAuthStr, t_xKeyObj):
# -----------------------------------------------------------------------------
# REST Assembly for Updating (Patch) a Data Object with group assignement
#
# This routine needs to be called for EACH key that needs to be added
# to the group.
# -----------------------------------------------------------------------------

    t_dstRESTAPI         = DST_REST_PREAMBLE + "vault/keys2"

    t_alias = str(t_xKeyObj[CMAttributeType.ALIASES.value][0][CMAliasesAttribute.ALIAS.value])
    t_keyID = str(t_xKeyObj[CMAttributeType.ID.value])
    
    t_dstHostRESTCmd = "https://%s:%s%s/%s?type=id" %(t_dstHost, t_dstPort, t_dstRESTAPI, t_keyID)
    t_dstHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_dstAuthStr}
    
    # In order to assign a key to a Group, you need to provide the key 
    # alias (which is the same thing as the name) and the Group name.
    

    # You need to update (patch) the object twice:  once to clear the 
    # alias (index 0) and a second time to re-add the alias along 
    # with the permissions (no index specified).
    
    t_keyEmptyAliasData = CMKeyEmptyAliasData()
    t_body              = t_keyEmptyAliasData.payload
    
    r = requests.patch(t_dstHostRESTCmd, data=json.dumps(t_body), headers=t_dstHeaders, verify=False)

    # If clearomg of the alias information is successful, then proceed
    # with redefining it along with the other meta data (which includes
    # group assignment)
    t_success = True
    if(r.status_code == STATUS_CODE_OK):
        t_Response      = r.json()        
        print("  ->Object Alias Data Cleared: ", t_alias)
        
        t_keyMetaData   = CMKeyNewMetaData(t_alias, t_dstGrp)
        t_body          = t_keyMetaData.payload

        r = requests.patch(t_dstHostRESTCmd, data=json.dumps(t_body), headers=t_dstHeaders, verify=False)

        t_success = True
        if(r.status_code == STATUS_CODE_OK):
            t_Response      = r.json()        
            print("  ->Object Added to Group: ", t_alias)
        else:
            kPrintError("addDataObjectToGroup-full", r)        
            t_success = False         
        
    else:
        kPrintError("addDataObjectToGroup-clear", r)        
        t_success = False
    
    return t_success

def getSrcClients(t_srcHost, t_srcPort, t_srcAuthStr):
# -----------------------------------------------------------------------------
# REST Assembly for obtaining a list of availabvle clients on the Source Server
# 
# This feature is helpful in determing which clients are available.
# -----------------------------------------------------------------------------

    t_srcRESTCmd            = SRC_REST_PREAMBLE + "clients"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTCmd)   

    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_srcAuthStr}

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_srcHostRESTCmd, headers=t_srcHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        kPrintError("getSrcClients", r)
        exit()

    t_clientList           = r.json()[GKLMAttributeType.CLIENT.value]
    
    return t_clientList

def assignSrcClientUsers(t_srcHost, t_srcPort, t_srcAuthStr, t_client, t_userList):
# -----------------------------------------------------------------------------
# REST Assembly for assigning a user to a KMIP Client 
# -----------------------------------------------------------------------------
    t_srcRESTListObjects    = SRC_REST_PREAMBLE + "clients/" + t_client + "/assignUsers"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)
    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    t_srcBody               = {"users":t_userList}

    t_success = True

    # Note that this REST Command is a PUT command
    r = requests.put(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("assignSrcClientUsers", r)
        exit()

    return t_success

def removeSrcClientUsers(t_srcHost, t_srcPort, t_srcAuthStr, t_client, t_userList):
# -----------------------------------------------------------------------------
# REST Assembly for removing a user to a KMIP Client 
# -----------------------------------------------------------------------------
    t_srcRESTListObjects    = SRC_REST_PREAMBLE + "clients/" + t_client + "/removeUsers"
    t_srcHostRESTCmd        = "https://%s:%s%s" %(t_srcHost, t_srcPort, t_srcRESTListObjects)
    t_srcHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_srcAuthStr}

    t_srcBody               = {"users":t_userList}

    t_success = True

    # Note that this REST Command is a PUT command
    r = requests.put(t_srcHostRESTCmd, data=json.dumps(t_srcBody), headers=t_srcHeaders, verify=False)
    if(r.status_code != STATUS_CODE_OK):
        kPrintError("assignSrcClientUsers", r)
        exit()

    return t_success