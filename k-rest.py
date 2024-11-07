#####################################################################################
#
# 	Name: k-rest.py
# 	Author: Rick R
# 	Purpose:  Python-based REST Key Transfer
#   Usage: py k-rest.py -srcHost <hostname or IP> -srcUser <username> -srcPass <password> 
#                   -dstHost <hostname or IP> -dstUser <username> -dstPass <password> 
#                   
#####################################################################################

import  argparse
import  binascii
import  codecs
import  hashlib
from pickle import TRUE
from tkinter.tix import TCL_ALL_EVENTS
from    kerrors import *
from    krestcmds import *
from    krestenums import *
from    netappfilters import *

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["9443"]
DEFAULT_DST_PORT    = ["443"]

# ################################################################################

# ----- INPUT PARSING BEGIN ------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="k-rest.py", description="REST Client Data Exchange")

# Src Information
parser.add_argument("-srcHost", nargs=1, action="store", dest="srcHost", required=True)
parser.add_argument("-srcPort", nargs=1, action="store", dest="srcPort", default=DEFAULT_SRC_PORT)
parser.add_argument("-srcUser", nargs=1, action="store", dest="srcUser", required=True)
parser.add_argument("-srcPass", nargs=1, action="store", dest="srcPass", required=True)

# Destination Information
parser.add_argument("-dstHost", nargs=1, action="store", dest="dstHost", required=True)
parser.add_argument("-dstPort", nargs=1, action="store", dest="dstPort", default=DEFAULT_DST_PORT)
parser.add_argument("-dstUser", nargs=1, action="store", dest="dstUser", required=True)
parser.add_argument("-dstPass", nargs=1, action="store", dest="dstPass", required=True)

# List only Flag - just list key material and do not change anything
parser.add_argument("-listOnly", nargs=1, action="store", dest="listOnly", required=False, 
                    choices=[listOnlyOption.NEITHER.value,
                             listOnlyOption.SOURCE.value,
                             listOnlyOption.DESTINATION.value,
                             listOnlyOption.BOTH.value
                            ],
                    default=[listOnlyOption.NEITHER.value] )

####################################################################################
# NOTE: The following OPTIONAL flags are commulative, meaning that only keys that satisfy ALL
# of the UUID and NetApp flags will be processed.
####################################################################################

# Added ability to specify a source UUID.  If populated, then the actions 
# specified (read or migrate) will only apply to the particular UUID
parser.add_argument("-srcuuid", nargs=1, action="store", dest="srcUuid", required=False)
srcUUID = ""   #set default to a zero length string

# Added ability to specify NetApp CUSTOME ATTRIBUTES.  If populated, then the actions 
# specified (read or migrate) will only apply to the those keys that satisfy the specified
# attribute requirements.
parser.add_argument("-netAppNodeID", nargs=1, action="store", dest="srcNANodeID", required=False)
srcNetAppNodeID = ""   #set default to a zero length string

parser.add_argument("-netAppClusterName", nargs=1, action="store", dest="srcNAClusterName", required=False)
srcNetAppClusterName = ""   #set default to a zero length string

parser.add_argument("-netAppVserverID", nargs=1, action="store", dest="srcNAVserverID", required=False)
srcNetAppVserverID = ""   #set default to a zero length string

parser.add_argument("-dstUserGroupName", nargs=1, action="store", dest="dstUserGroupName", required=False)
dstUserGroupName = ""   #set default to a zero length string

parser.add_argument("-srcClientName", nargs=1, action="store", dest="srcClientName", required=False)
srcClientName = ""   #set default to a zero length string

parser.add_argument("-listSrcClients", action="store_true", dest="listSrcClients", required=False)
listSrcClients = False   #set default to be false

parser.add_argument("-resolveSrcClientOwnership", action="store_true", dest="resolveSrcClientOwnership", required=False)
resolveSrcClientOwnership = False   #set default to be false

parser.add_argument("-includeSecrets", action="store_true", dest="includeSecrets", required=False)
includeSecrets = False   #set default to be false

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()



# Display results from inputs
print("\n ---- SRC & DST PARAMETERS ----")

srcHost = str(" ".join(args.srcHost))
srcPort = str(" ".join(args.srcPort))
srcUser = str(" ".join(args.srcUser))
srcPass = str(" ".join(args.srcPass))
tmpStr = " SrcHost: %s\n SrcPort: %s\n SrcUser: %s\n" %(srcHost, srcPort, srcUser)
print(tmpStr)

dstHost = str(" ".join(args.dstHost))
dstPort = str(" ".join(args.dstPort))
dstUser = str(" ".join(args.dstUser))
dstPass = str(" ".join(args.dstPass))
tmpStr = " DstHost: %s\n DstPort: %s\n DstUser: %s\n" %(dstHost, dstPort, dstUser)
print(tmpStr)

# ------------- Group Management ------------------------------------
# If a Group is specified, then capture the group name and check to 
# see if it is present. The flag variable will be used later to create
# the group (and add the user to it), # if keys needs to be added 
# to the desitation.
# -------------------------------------------------------------------
t_flagGroupIsAbsent = False
if args.dstUserGroupName is not None:
    dstUserGroupName = str(" ".join(args.dstUserGroupName))
    print(" DstUserGroupName: %s" %(dstUserGroupName))
    
    # If Group is specified, download the existing groups from the destination
    # and see if the group is already present.
    dstAuthStr = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
    dstGrpList = getDstGroupsAll(dstHost, dstPort, dstAuthStr)
    # printJList("dstGrpList:", dstGrpList)
    
    # Presume the group is not present, unless it is found within
    # the list of download group names.
    t_flagGroupIsAbsent = True
    for t_Grp in dstGrpList[CMAttributeType.RESOURCES.value]:
        if dstUserGroupName == t_Grp[CMAttributeType.NAME.value]:
            print(" ", dstUserGroupName, "is present on the destination server.")
            t_flagGroupIsAbsent = False
    

# ---- List Only Filters ----------------------------------------------
# Collect the list only filter value and print it
# ---------------------------------------------------------------------
listOnly = str(" ".join(args.listOnly))
print(" ListOnly:", listOnly)

# ---- List srcUUID ---------------------------------------------------
# Collect the UUID string and print it
# ---------------------------------------------------------------------
if args.srcUuid is not None:
    srcUUID = str(" ".join(args.srcUuid))
    print(" Source UUID (filter):", srcUUID)

# ---- NetAPP Customer Attributes---------------------------------------
# If custom attributes are specified in the command line, ensure they 
# are included in a dictionary that will be used to filter out the objects
# -----------------------------------------------------------------------
srcNetAppFilterDict = {}
if args.srcNANodeID is not None:
    srcNetAppNodeID = str(" ".join(args.srcNANodeID))
    print(" NetApp NodeID:", srcNetAppNodeID)
    srcNetAppFilterDict[NetAppAttribute.NODEID.value] = srcNetAppNodeID
    
if args.srcNAClusterName is not None:
    srcNetAppClusterName = str(" ".join(args.srcNAClusterName))
    print(" NetApp ClusterName:", srcNetAppClusterName)
    srcNetAppFilterDict[NetAppAttribute.CLUSTERNAME.value] = srcNetAppClusterName

if args.srcNAVserverID is not None:
    srcNetAppVserverID = str(" ".join(args.srcNAVserverID))
    print(" NetApp VServer ID:", srcNetAppVserverID)
    srcNetAppFilterDict[NetAppAttribute.VSERVERID.value] = srcNetAppVserverID
    
# DEBUG - this is a custom attribute that appears occastionally for non-NetApp objects
# srcNetAppFilterDict['y-RNGSimulation'] = 'Qg'

# ------------- Source Client ------------------------------------
# Set the client information if it is specified
# -------------------------------------------------------------------
if args.srcClientName is not None:
    srcClientName = str(" ".join(args.srcClientName))
    print(" Source Client Name:", srcClientName)

listSrcClients = args.listSrcClients
addClientUser = args.resolveSrcClientOwnership

# ------------- Secrets Flag ----------------------------------------
# Set Secrets collection flag
# -------------------------------------------------------------------
includeSecrets = args.includeSecrets
print(" Include Secrets:", includeSecrets)

print("\n--------------- PROCESSING -----------------------------------------------")

# ---- Command PARSING COMPLETE ----------------------------------------------------------

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# ################################################################################
# Get Source Information and Material
# ################################################################################
print("\n Accessing Source and Destination Hosts and collecting Authorization Strings...")

if listOnly != listOnlyOption.DESTINATION.value:
    srcAuthStr      = createSrcAuthStr(srcHost, srcPort, srcUser, srcPass)
    print("  * Source Access Confirmed *")
    tmpStr = "    Username: %s\n" %(srcUser)
    print(tmpStr)

# ------------- Source Client Information ---------------------------
# If a list of clients is requested, then provide it.
# -------------------------------------------------------------------

    # Initialize for Client User List
    clientList          = getSrcClients(srcHost, srcPort, srcAuthStr)
    listLen             = len(clientList)
    srcClientFound      = False
    t_srcUserList       = []
    clientUserAdded     = False

    # Initialize for Symmetric Key Objects
    srcKeyObjDataList   = []
    srcClientKeyCount   = 0
    srcKeyListCnt       = 0

    # Initialize for Secret Data Objects
    srcSecretObjDataList = []
    srcSecretListCnt    = 0


    # If user wants a list of available clients, provide it.
    if listSrcClients:  
        tmpStr = "    Available Source Clients (%s): " %(listLen)
        print(tmpStr)

    # Now for each client in the Source Server, extract the objects
    for client in range(listLen):
        t_clientName = clientList[client][GKLMAttributeType.CLIENT_NAME.value]
        t_symKeyCount = 0
        t_secretCount = 0

        t_mgdObjCnt = clientList[client][GKLMAttributeType.MANAGED_OBJECT_COUNT.value]
        
        t_objStr = clientList[client][GKLMAttributeType.OBJECT.value]        
        
        # Now check for the presents of any objects for the client
        if len(t_objStr) > 0:

            # Now since the client has objects, check for the presence of any SYMMETRIC KEYS.  Note that the format of information
            # in the object string looks like "Symmetric Key (128) Secret Data (4)" where the number within the parenthasis is the quantity of 
            # symmetric keys or secret objects.

            t_objStr = t_objStr.strip() # remove leading and trailing white space
            t_objStr = t_objStr.replace(' (', ', (') # Replace spaces before parenthasis with commas for easier parsing
            t_objStr = t_objStr.replace(') ', '), ') # Replace spaces before parenthasis with commas for easier parsing
            t_objStr = t_objStr.replace(' (', '') # Remove leading parenthasis
            t_objStr = t_objStr.replace(')', '') # Remove trailing parenthasis

            t_objStrList = t_objStr.split(',') # create a list of the elements in the string.  Note elements are separated by a comma

            t_objStrDict = listToDict(t_objStrList)

            # Process SYMMETRIC KEY objects
            if ObjectTypeName.SYMMETRIC_KEY.value.title() in t_objStrDict.keys():
                t_symCntStr = t_objStrDict[ObjectTypeName.SYMMETRIC_KEY.value.title()]

                # Finally, an integer of the actual count.
                t_symKeyCount = int(t_symCntStr)
                srcKeyListCnt = srcKeyListCnt + int(t_symKeyCount)

            # Process SECRET DATA objects
            if ObjectTypeName.SECRET_DATA.value.title() in t_objStrDict.keys():
                t_secCntStr = t_objStrDict[ObjectTypeName.SECRET_DATA.value.title()]

                # Finally, an integer of the actual count.
                t_secretCount = int(t_secCntStr)
                srcSecretListCnt = srcSecretListCnt + int(t_secretCount)

        if listSrcClients:  # if user wants a list of available clients, provide it.
            tmpStr = "\n      %s contains %s Managed Objects %s Exportable Symmetric Keys %s Exportable Secrets" %(t_clientName, t_mgdObjCnt, t_symKeyCount, t_secretCount)
            print(tmpStr)


        # If a client name is specified, then check to ensure it is present.
        # If client name was specified, search for it and then capture key information 
        # specific to that client (presuming keys exist)
        if len(srcClientName) > 0:
            if srcClientName == t_clientName:
                srcClientFound = True

                # Before attempting to get the key material, ensure that the srcUser has the permissions to obtain objects
                if addClientUser and (srcUser not in clientList[client][GKLMAttributeType.CLIENT_USERS.value]):
                    t_srcUserList.append(srcUser) # create list of user with the user associated with login
                    t_success = assignSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_srcUserList)
                    clientUserAdded = True

                # Save Key And Secret Object Counts
                srcClientKeyCount       = t_symKeyCount
                srcClientSecretCount    = t_secretCount

                if int(t_symKeyCount) > 0:
                    tmpStr = "       Retrieving symmetric key information for %s... " %(t_clientName)
                    print(tmpStr)

                    # -------------- Retrieve the Key Material --------------------------------------------------------------
                    t_srcKeyObjDataList   = getSrcObjDataListByClient(srcHost, srcPort, srcAuthStr, srcUUID, GKLMAttributeType.SYMMETRIC_KEY.value, t_clientName)
                    srcKeyObjDataList.extend(t_srcKeyObjDataList) # Add client-specific information to total list of key objects
                    # -------------------------------------------------------------------------------------------------------

                if includeSecrets and int(t_secretCount) > 0:
                    tmpStr = "       Retrieving secret data information for %s... " %(t_clientName)
                    print(tmpStr)

                    # -------------- Retrieve the Secret Data Material --------------------------------------------------------------
                    t_srcSecretObjDataList   = getSrcObjDataListByClient(srcHost, srcPort, srcAuthStr, srcUUID, GKLMAttributeType.SECRET_DATA.value, t_clientName)
                    srcSecretObjDataList.extend(t_srcSecretObjDataList) # Add client-specific information to total list of secrete data objects
                    # -------------------------------------------------------------------------------------------------------

                # If a client user was added, remove it and restore the original ownership.
                if clientUserAdded:
                    t_success = removeSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_srcUserList)
                    t_originalClientUserList = clientList[client][GKLMAttributeType.CLIENT_USERS.value] # retrieve original list of users
                    t_success = assignSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_originalClientUserList)

        # Otherwise, just collect the key material and append it to the exhaustive list of ALL objects for ALL clients
        else:
            # Before attempting to get the key material, ensure that the srcUser has the permissions to obtain objects
            if addClientUser and (srcUser not in clientList[client][GKLMAttributeType.CLIENT_USERS.value]):
                t_srcUserList.append(srcUser) # create list of user with the user associated with login
                t_success = assignSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_srcUserList)
                clientUserAdded = True

            if int(t_symKeyCount) > 0:
                tmpStr = "       Retrieving symmetric key information for %s... " %(t_clientName)
                print(tmpStr)

                # -------------- Retrieve the Key Material --------------------------------------------------------------
                t_srcKeyObjDataList   = getSrcObjDataListByClient(srcHost, srcPort, srcAuthStr, srcUUID, GKLMAttributeType.SYMMETRIC_KEY.value, t_clientName)
                srcKeyObjDataList.extend(t_srcKeyObjDataList) # Add client-specific information to total list of key objects
                # -------------------------------------------------------------------------------------------------------

            if includeSecrets and int(t_secretCount) > 0:
                tmpStr = "       Retrieving secret data information for %s... " %(t_clientName)
                print(tmpStr)

                # -------------- Retrieve the Secret Data Material --------------------------------------------------------------
                t_srcSecretObjDataList   = getSrcObjDataListByClient(srcHost, srcPort, srcAuthStr, srcUUID, GKLMAttributeType.SECRET_DATA.value, t_clientName)
                srcSecretObjDataList.extend(t_srcSecretObjDataList) # Add client-specific information to total list of secrete data objects
                # -------------------------------------------------------------------------------------------------------

            # If a client user was added, remove it and restore the original ownership.
            if clientUserAdded:
                t_success = removeSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_srcUserList)
                t_originalClientUserList = clientList[client][GKLMAttributeType.CLIENT_USERS.value] # retrieve original list of users
                t_success = assignSrcClientUsers(srcHost, srcPort, srcAuthStr, t_clientName, t_originalClientUserList)

    # Once list of clients has been parsed, if the srcClientName was specified but it is not present (or has no keys),
    # then bail and make the user correct and resubmit the command.
    if len(srcClientName) > 0: 
        if srcClientFound == False:
            tmpStr = "\n    ERROR: Client Name %s not found in list of available clients. Please try again." %(srcClientName)
            print(tmpStr)
            exit()
        elif srcClientKeyCount == 0 and srcClientSecretCount == 0:
            tmpStr = "\n    ERROR: Client Name %s was found in list of available clients, but does not contain any SYMMETRIC keys or SECRET objects. Please try again." %(srcClientName)
            print(tmpStr)
            exit()
        else:
            tmpStr = "\n    Client Name %s was found in list of available clients and contains %s SYMMETRIC keys and %s SECRET objects. " %(srcClientName, srcClientKeyCount, srcClientSecretCount)
            print(tmpStr)            

    # If the length of the NetApp filter (dictionary) is greater than zero, apply NetApp filter.
    if len(srcNetAppFilterDict) > 0:
        # filter key objects against NetAP dictionary
        t_srcFilteredList = filterNetAppObjDataList(srcKeyObjDataList, srcNetAppFilterDict)
        srcKeyObjDataList = t_srcFilteredList   # replace key obj data list with filtered list

        # filter secret objects against NetAPP dictionary
        t_srcFilteredList = filterNetAppObjDataList(srcSecretObjDataList, srcNetAppFilterDict)
        srcSecretObjDataList = t_srcFilteredList   # replace key obj data list with filtered list

    # After iterating through all of the clients in the source, report the total of all key and secret material in the list
    srcKeyObjCnt        = len(srcKeyObjDataList)    # Key Objects
    srcSecretObjCnt     = len(srcSecretObjDataList) # Secret Objects

    if listOnly != listOnlyOption.DESTINATION.value:
        print("\n Number of Src List Keys: ", srcKeyListCnt)
        print(" Number of filtered and exportable Src Key Objects: ", srcKeyObjCnt)
        printSrcKeyObjDataList(srcKeyObjDataList)

        if includeSecrets:
            print("\n Number of Src List Secrets: ", srcSecretListCnt)
            print(" Number of filtered and exportable Src Secret Objects: ", srcSecretObjCnt)
            printSrcSecretObjDataList(srcSecretObjDataList)

        print("\n --- SRC OBJECT RETRIEVAL COMPLETE --- \n")

# ################################################################################
# Get Destiation Information and Material
# ################################################################################
if listOnly != listOnlyOption.SOURCE.value:
    dstAuthStr      = createDstAuthStr(dstHost, dstPort, dstUser, dstPass)
    print("  * Destination Access Confirmed *")

# Get destination user meta data that will be used later for 
    dstUsrSelfJSON  = getDstUserSelf(dstHost, dstPort, dstAuthStr)

    CM_userName     = dstUsrSelfJSON[CMUserAttribute.NAME.value]
    CM_userNickname = dstUsrSelfJSON[CMUserAttribute.NICKNAME.value]
    CM_userID       = dstUsrSelfJSON[CMUserAttribute.USER_ID.value]

    tmpStr = "    Username: %s\n    User: %s\n    UserID: %s\n" %(CM_userNickname, CM_userName, CM_userID)
    print(tmpStr)

# Get a list of all users on the destination for later use and create a dictionary of user_id and nickname
    dstUsrsAllData  = getDstUsersAll(dstHost, dstPort, dstAuthStr)
    dstUsrsAllJSON  = dstUsrsAllData[CMAttributeType.RESOURCES.value]   # extract just the user data
    dstUsrsAllDict  = {} # define user dictionary - to be used later

    for t_idx in dstUsrsAllJSON:
        t_user_id   = t_idx[CMUserAttribute.USER_ID.value]
        t_nickname  = t_idx[CMUserAttribute.NICKNAME.value]
        dstUsrsAllDict[t_user_id] = t_nickname

        
if listOnly == listOnlyOption.NEITHER.value:
###########################################################################################################        
# Create and upload all of the key objects to the destination unless a flag to LIST ONLY has been specified. 
########################################################################################################### 

    #  Create Key object dictionary and list to map GKLM keys and values to CM
    xKeyObj     = {}
    xKeyObjList = []

    #  Create Secret object dictionary and list to map GKLM keys and values to CM
    xSecretObj     = {}
    xSecretObjList = []

    # -------------- KEY OBJECT MAPPING ------------------------------------------------------------- 
    # For each KEY object in the source, map it with the proper dictionary keys to a x-formed list of 
    # dictionaries for later upload to the destination
    # -----------------------------------------------------------------------------------------------
    for k in range(srcKeyObjCnt):
        # xKeyObj[CMAttributeType.UUID.value]         = srcKeyObjDataList[k][GKLMAttributeType.UUID.value]

        # GKLM stores the Key Usage Mask as a string.  CM stores it a the associated KMIP value.  As such,
        # The GKLM Key Usage Mask string must be replaced with the appropriate value before storing it in CM.
        srcUM       = srcKeyObjDataList[k][GKLMAttributeType.CRYPTOGRAPHIC_USAGE_MASK.value]
        srcUMClean  = "".join(srcUM.split())    #trim leading and trailing spaces from srcUM string
        for tmpUM in CryptographicUsageMask:        
            if srcUMClean == tmpUM.name:
                xKeyObj[CMAttributeType.USAGE_MASK.value]   = tmpUM.value

        # The GKLM Alias seems to match the patter of the CM Name key.  
        # However, GKLM includes brakcets ("[]") in the string
        # and they need to be removed before copying the true alias value to CM
        tmpStr = srcKeyObjDataList[k][GKLMAttributeType.ALIAS.value]
        xKeyObj[CMAttributeType.NAME.value]         = tmpStr.strip("[]")

        # xKeyObj[CMAttributeType.STATE.value]        = srcKeyObjDataList[k][GKLMAttributeType.KEY_STATE.value]
        xKeyObj[CMAttributeType.ALGORITHM.value]    = srcKeyObjDataList[k][GKLMAttributeType.KEY_ALGORITHM.value]
        xKeyObj[CMAttributeType.SIZE.value]         = int(srcKeyObjDataList[k][GKLMAttributeType.KEY_LENGTH.value])

        # In GKLM, the Object Type uses underscores intead of spaces ("SYMMETRIC_KEY" vs "Symmetric Key")
        # and, therefore, needs some adjusting before it can be sent to CM.
        tmpStr  = srcKeyObjDataList[k][GKLMAttributeType.KEY_TYPE.value]
        tmpStr2 = tmpStr.replace("_", " ")  # SYMMETRIC_KEY -> SYMMETRIC KEY
        
        xKeyObj[CMAttributeType.OBJECT_TYPE.value]  = tmpStr2.title()   # SYMMETRIC KEY -> Symmetric Key
        xKeyObj[CMAttributeType.MATERIAL.value]     = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_MATERIAL']
        xKeyObj[CMAttributeType.FORMAT.value]       = srcKeyObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_FORMAT'].lower()
        
        # Add a userID to the associated key object so it can be made owner of the key
        # when uploaded to CM
        xKeyObj[CMAttributeType.META.value]= {CMAttributeType.OWNER_ID.value: CM_userID}

        # After assembling the key object, append it to the list of other key objects
        xKeyObjList.append(xKeyObj.copy())
        # print("\n Key Obj: ", json.dumps(xKeyObj, skipkeys = True, allow_nan = True, indent = 3))


    # -------------- SECRET OBJECT MAPPING ------------------------------------------------------------- 
    # For each SECRET object in the source, map it with the proper dictionary keys to a x-formed list of 
    # dictionaries for later upload to the destination
    # -----------------------------------------------------------------------------------------------
    if includeSecrets: 
        for k in range(srcSecretObjCnt):
            # xSecretObj[CMAttributeType.UUID.value]         = srcSecretObjDataList[k][GKLMAttributeType.UUID.value]

            # GKLM stores the Usage Mask as a string.  CM stores it a the associated KMIP value.  As such,
            # The GKLM Usage Mask string must be replaced with the appropriate value before storing it in CM.
            srcUM       = srcSecretObjDataList[k][GKLMAttributeType.CRYPTOGRAPHIC_USAGE_MASK.value]
            xSecretObj[CMAttributeType.USAGE_MASK.value]   = CryptographicUsageMask.NULL.value # initiate UM to null

            for tmpUM in CryptographicUsageMask:
                if tmpUM.name in srcUM:
                    xSecretObj[CMAttributeType.USAGE_MASK.value]  = xSecretObj[CMAttributeType.USAGE_MASK.value] | tmpUM.value # OR the usage values


            # GKLM does not use alias for Secrets.  So we are copying the Name into the CM Alias.  
            # However, GKLM includes brakcets ("[]") in the string and they need to be removed 
            # before copying the true name value to CM

            t_nameStrDict   = bracketsToDict(srcSecretObjDataList[k][GKLMAttributeType.NAME.value])
            t_name          = t_nameStrDict[GKLMAttributeType.NAME_VALUE.value]
            xSecretObj[CMAttributeType.NAME.value] = t_name

            # Copy name into Alias component of dst object
            t_aliasList = [{CMAliasesAttribute.ALIAS.value:t_nameStrDict[GKLMAttributeType.NAME_VALUE.value], CMAliasesAttribute.TYPE.value:"string", CMAliasesAttribute.INDEX.value:0}]
            xSecretObj[CMAttributeType.ALIASES.value] = t_aliasList

            xSecretObj[CMAttributeType.STATE.value]         = srcSecretObjDataList[k][GKLMAttributeType.SECRET_STATE.value].replace("_","-").title()
            xSecretObj[CMAttributeType.ALGORITHM.value]     = CMSecretAlgorithType.SECRET_SEED.value # CM seems to store them all as "SECRETESEED"
            xSecretObj[CMAttributeType.OBJECT_TYPE.value]   = CMSecretObjectType.SECRET_DATA.value # CM seems to store them all as "Secret Data"
            xSecretObj[CMAttributeType.SIZE.value]          = int(srcSecretObjDataList[k][GKLMAttributeType.SECRET_CRYPOGRAPHIC_LENGTH.value])

            # In GKLM, the Secret Object Type appears as "PASSWORD".  However, CM uses the term "Secret Data" for 
            # CM Object Type and "seed" for Data Type.  Let's copy the OBJECT TYPE string for now into CMs dataType.

            xSecretObj[CMSecretAttributeType.DATA_TYPE.value] = str(srcSecretObjDataList[k][GKLMAttributeType.TYPE.value]).lower()

            # Finally, copy the actual material and format
            xSecretObj[CMAttributeType.MATERIAL.value]     = srcSecretObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_MATERIAL']
            xSecretObj[CMAttributeType.FORMAT.value]       = srcSecretObjDataList[k][GKLMAttributeType.KEY_BLOCK.value]['KEY_FORMAT'].lower()
        
            # Add a userID to the associated Secret object so it can be made owner of the Secret
            # when uploaded to CM
            xSecretObj[CMAttributeType.META.value]= {CMAttributeType.OWNER_ID.value: CM_userID}

            # After assembling the Secret object, append it to the list of other Secret objects
            xSecretObjList.append(xSecretObj.copy())
            # print("\n Secret Obj: ", json.dumps(xSecretObj, skipkeys = True, allow_nan = True, indent = 3))
   
    # ----------------------------------------------------------------------------------------------
    # Now that the keys have been read and mapped, send them to the destiation.  
    #
    # The first step is to ensure that if the dstUserGroup name is provided, that it exists on the
    # destination server.  If it does not exist, create it and add the dstUsr to the group.
    # ----------------------------------------------------------------------------------------------

    if args.dstUserGroupName is not None:
        if t_flagGroupIsAbsent:
            createDstUsrGroup(dstHost, dstPort, dstAuthStr, dstUserGroupName)
            addDstUsrToGroup(dstHost, dstPort, dstAuthStr, CM_userNickname, CM_userID, dstUserGroupName)
            print(" * ", dstUserGroupName, "group configuration complete. * ")
    
    # ----------------------------------------------------------------------------------------------
    # IMPORT Key Material into Destination
    # ----------------------------------------------------------------------------------------------
    print("\n*** Importing KEY material into destination... ***")
    
    for xKeyObj in xKeyObjList:
        t_keyObjName = xKeyObj[CMAttributeType.NAME.value]
        print("\n xKeyObjName: ",  t_keyObjName)    
        success = importDstDataKeyObject(dstHost, dstPort, dstUser, dstAuthStr, xKeyObj)
        print(" --> importDstDataKeyOjbect Success:", success)
        
        # After the object has been successfully created, assign it to the Group, if one has been provided.
        if success:
            if args.dstUserGroupName is not None:
                xKeyObjFromDst = getDstKeyByName(dstHost, dstPort, dstAuthStr, t_keyObjName)                
                addDataObjectToGroup(dstHost, dstPort, dstUserGroupName, dstAuthStr, xKeyObjFromDst)

    # ----------------------------------------------------------------------------------------------
    # IMPORT Secret Material into Destination
    # ----------------------------------------------------------------------------------------------
    if includeSecrets:
        print("\n*** Importing SECRET material into destination... ***")
    
        for xSecretObj in xSecretObjList:
            t_SecretObjName = xSecretObj[CMAttributeType.NAME.value]
            print("\n xSecretObjName: ",  t_SecretObjName)    
            success = importDstDataSecretObject(dstHost, dstPort, dstUser, dstAuthStr, xSecretObj)
            print(" --> importDstDataSecretOjbect Success:", success)
        
            # After the object has been successfully created, assign it to the Group, if one has been provided.
            if success:
                if args.dstUserGroupName is not None:
                    xSecretObjFromDst = getDstKeyByName(dstHost, dstPort, dstAuthStr, t_SecretObjName)                
                    addDataObjectToGroup(dstHost, dstPort, dstUserGroupName, dstAuthStr, xSecretObjFromDst)

if listOnly != listOnlyOption.SOURCE.value:
###########################################################################################################        
# Read keys that are now in the destination unless the user asks for source-only information 
########################################################################################################### 

    print("\nRetrieving list of objects from destination...")
    dstObjList      = getDstObjList(dstHost, dstPort, dstAuthStr)
    print("\nDst Object List Count: ", len(dstObjList))

    # Filter and show NetApp specific information.
    if len(srcNetAppFilterDict) > 0:
        t_FilteredList = filterNetAppObjDataList(dstObjList, srcNetAppFilterDict)
        dstObjList = t_FilteredList   # replace key obj data list with filtered list
        
    dstObjData      = exportDstObjData(dstHost, dstPort, dstObjList, dstAuthStr)
    dstExpObjCnt    = len(dstObjData)
    print("Dst Exportable Data Object Count: ", dstExpObjCnt)
    printDstObjDataAndOwner(dstObjData, dstUsrsAllDict)
    
    print("\n --- DST OBJECT RETRIEVAL COMPLETE --- \n")
    

#####################################################################################
