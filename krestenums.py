# key-rest-enums
#
# definition file
######################################################################
import enum

# Class and enumersations taken from KMIP standard
class ObjectType(enum.Enum):
    CERTIFICATE         = 0x00000001
    SYMMETRIC_KEY       = 0x00000002
    PUBLIC_KEY          = 0x00000003
    PRIVATE_KEY         = 0x00000004
    SPLIT_KEY           = 0x00000005
    TEMPLATE            = 0x00000006 
    SECRET_DATA         = 0x00000007
    OPAQUE_DATA         = 0x00000008
    PGP_KEY             = 0x00000009
    CERTIFICATE_REQUEST = 0x0000000A
    
class ObjectTypeName(enum.Enum):
    CERTIFICATE         = 'CERTIFICATE'
    SYMMETRIC_KEY       = 'SYMMETRIC KEY'
    PUBLIC_KEY          = 'PUBLIC_KEY'
    PRIVATE_KEY         = 'PRIVATE_KEY'
    SPLIT_KEY           = 'SPLIT_KEY'
    TEMPLATE            = 'TEMPLATE' 
    SECRET_DATA         = 'SECRET DATA'
    OPAQUE_DATA         = 'OPAQUE_DATA'
    PGP_KEY             = 'PGP_KEY'
    CERTIFICATE_REQUEST = 'CERTIFICATE_REQUEST'
    OPAQUE_OBJECT       = "Opaque Object"
   
class CryptographicUsageMask(enum.Enum):
    # KMIP 1.0
    NULL                = 0x00000000
    SIGN                = 0x00000001
    VERIFY              = 0x00000002
    ENCRYPT             = 0x00000004
    DECRYPT             = 0x00000008
    WRAP_KEY            = 0x00000010
    UNWRAP_KEY          = 0x00000020
    EXPORT              = 0x00000040
    MAC_GENERATE        = 0x00000080
    MAC_VERIFY          = 0x00000100
    # DERIVE_KEY          = 0x00000200
    DERIVE              = 0x00000200
    CONTENT_COMMITMENT  = 0x00000400
    KEY_AGREEMENT       = 0x00000800
    CERTIFICATE_SIGN    = 0x00001000
    CRL_SIGN            = 0x00002000
    GENERATE_CRYPTOGRAM = 0x00004000  # Designated '(Reserved)' in KMIP 2.0
    VALIDATE_CRYPTOGRAM = 0x00008000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_ENCRYPT   = 0x00010000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_DECRYPT   = 0x00020000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_WRAP      = 0x00040000  # Designated '(Reserved)' in KMIP 2.0
    TRANSLATE_UNWRAP    = 0x00080000  # Designated '(Reserved)' in KMIP 2.0
    # KMIP 2.0
    AUTHENTICATE        = 0x00100000
    UNRESTRICTED        = 0x00200000
    FPE_ENCRYPT         = 0x00400000
    FPE_DECRYPT         = 0x00800000    
    
class GKLMAttributeType(enum.Enum):
    UUID                        = 'uuid'
    INFORMATION                 = 'information'
    ALIAS                       = 'alias'
    KEY_ALGORITHM               = 'key algorithm'
    KEY_LENGTH                  = 'key length (in bits)'
    KEY_TYPE                    = 'key type'
    OWNER                       = 'owner'
    KEY_STORE_NAME              = 'key store name'
    KEY_STORE_UUID              = 'key store uuid'
    KEY_STATE                   = 'key state'
    ACTIVATION_DATE             = 'activation date'
    ARCHIVE_DATE                = 'archive date'
    COMPROMISE_DATE             = 'compromise date'
    CREATION_DATE               = 'creation date'
    EXPIRATION_DATE             = 'expiration date'
    DESTROY_DATE                = 'destroy date'
    KEY_GROUP_IDS               = 'key group ids'
    HASH_VALUE                  = 'hash value'
    USAGE                       = 'usage'
    CRYPTOGRAPHIC_USAGE_MASK    = 'Cryptographic Usage Mask'
    USAGE_LIMITS                = 'Usage Limits'
    OPERATIONAL_POLICY_NAME     = 'Operation Policy Name'
    PROCESS_START_DATE          = 'Process Start Date'
    PROTECT_STOP_DATE           = 'Protect Stop Date'
    DEACTIVATION_DATE           = 'Deactivation Date'
    CONTACT_INFORMATION         = 'Contact Information'
    REVOCATION_REASON           = 'Revocation Reason'
    NAME                        = 'Name'
    CRYPTOGRAPHIC_PARAMETERS    = 'Cryptographic Parameters'
    OBJECT_GROUP                = 'Object Group'
    LINK                        = 'Link'
    DIGEST                      = 'Digest'
    APPLICATION_SPECIFIC_INFORMATION = 'Application Specific Information'
    CUSTOM_ATTRIBUTES           = 'Custom Attributes'
    LAST_CHANGED_DATE           = 'Last Changed Date'
    COMPROMISE_OCCURANCE_DATE   = 'Compromise Occurence Date'
    LEASE_TIME                  = 'Lease Time'
    KEY_BLOCK                   = "KEY_BLOCK"
    KEY_MATERIAL                = "KEY_MATERIAL"
    KEY_FORMAT                  = "KEY_FORMAT"
    CLIENT                      = "client"
    CLIENT_NAME                 = "clientName"
    MANAGED_OBJECT_COUNT        = "managedObjectCount"
    OBJECT_COUNT                = "objectCount"
    OBJECT                      = "object"
    SYMMETRIC_KEY               = "SYMMETRIC_KEY"   # Note that this attribute is written differently than a key type
    SECRET_DATA                 = "SECRET_DATA"
    SECRET_STATE                = "State"
    SECRET_ALGORITHM            = "Algorithm"
    SECRET_CRYPOGRAPHIC_LENGTH  = "Cryptographic Length"
    NAME_VALUE                  = "VALUE"
    OPAQUE_OBJECT               = "OPAQUE_OBJECT"
    TYPE                        = "Type"
    CLIENT_USERS                = "users"           # this is the user assigned to the client

class CMSecretDataType(enum.Enum):
    BLOB                = "blob"
    PASSWORD            = "PASSWORD"
    SEED                = "seed"
    OPAQUE              = "OPAQUE"

class CMSecretAlgorithType(enum.Enum):
    SECRET_SEED        = "SECRETSEED"

class CMSecretAttributeType(enum.Enum):
    DATA_TYPE           = "dataType"
    MATERIAL            = "material"
    META                = "meta"
    NAME                = "name"
    PASSWORD_CONFIG     = "passwordConfig"
    STATE               = "state"
    UNDELETEABLE        = "undeletable"
    UNEXPORTABLE        = "unexportable"
    USAGE_MASK          = "usageMask"

class CMSecretPWConfigType(enum.Enum):
    PASSWORD_LENGTH     = "passwordLength"

class CMSecretObjectType(enum.Enum):
    SECRET_DATA     = "Secret Data"
    
class CMAttributeType(enum.Enum):
    ID                          = 'id'
    URI                         = 'uri'
    ACCOUNT                     = 'account'
    APPLICATION                 = 'application'
    DEV_ACCOUNT                 = 'devAccount'
    CREATED_AT                  = 'createdAt'
    NAME                        = 'name'
    UPDATED_AT                  = 'updatedAT'
    ACTIVATION_DATE             = 'activationDate'
    STATE                       = 'state'
    USAGE                       = 'usage'
    USAGE_MASK                  = 'usageMask'
    META                        = 'meta'
    OBJECT_TYPE                 = 'objectType'
    ALIASES                     = 'aliases'
    SHA1_FINGERPRINT            = 'sha1Fingerprint'
    SHA256_FINGERPRINT          = 'sha256Fingerprint'
    DEFAULT_IV                  = 'defaultIV'
    VERSION                     = 'version'
    ALGORITHM                   = 'algorithm'
    SIZE                        = 'size'
    UNEXPORTABLE                = 'unexportable'
    UNDELETEABLE                = 'undeletable'
    NEVER_EXPORTED              = 'neverExported'
    NEVER_EXPORTABLE            = 'neverExportable'
    EMPTY_MATERIAL              = 'emptyMaterial'
    UUID                        = 'uuid'
    MUID                        = 'muid'
    MATERIAL                    = 'material'
    FORMAT                      = 'format'
    OWNER_ID                    = 'ownerId'
    RESOURCES                   = 'resources'
    TOTAL                       = 'total'

class CMAliasesAttribute(enum.Enum):
    ALIAS                       = 'alias'
    TYPE                        = 'type'
    INDEX                       = 'index'
    
class CMUserAttribute(enum.Enum):    
    NAME                        = 'name'
    NICKNAME                    = 'nickname'
    USER_ID                     = 'user_id'
        
class listOnlyOption(enum.Enum):
    NEITHER                     = 'NEITHER'
    SOURCE                      = 'SOURCE'
    DESTINATION                 = 'DESTINATION'
    BOTH                        = 'BOTH'
    
class NetAppCustomAttribute(enum.Enum):
    NETAPPHEADER                = 'x-NETAPP'
    NODEID                      = 'x-NETAPP-NodeId'
    NODENAME                    = 'x-NETAPP-NodeName'
    CLUSTERNAME                 = 'x-NETAPP-ClusterName'
    CLUSTERID                   = 'x-NETAPP-ClusterId'
    VSERVERID                   = 'x-NETAPP-VserverId'
    VSERVERUUID                 = 'x-NETAPP-VserverUuid'
    TAG                         = 'x-NETAPP-Tag'
    PARTNERCLUSTERID            = 'x-NETAPP-PartnerClusterId'
    PARTNERCLUSTERNAME          = 'x-NETAPP-PartnerClusterName'
    PARTNERNODEID               = 'x-NETAPP-PartnerNodeID'
    PARTNERNODENAME             = 'x-NETAPP-PartnerNodeName'
    PRODUCT                     = 'x-NETAPP-Product'
    VERSION                     = 'x-NETAPP-Version'
    KEYID                       = 'x-NETAPP-KeyId'
    KEYUSAGE                    = 'x-NETAPP-KeyUsage'
    KEYTYPE                     = 'x-NETAPP-KeyType'
    VOLUMEID                    = 'x-NETAPP-VolumeId'
    VOLUMEIDHASH                = 'x-NETAPP-VolumeIdHash'

class NetAppMetaAttribute(enum.Enum):
    KMIP                        = 'kmip'
    CUSTOM                      = 'custom'
    TYPE                        = 'type'
    INDEX                       = 'index'
    TYPE_VALUE                  = 'TextString'

class CMMetaAttribute(enum.Enum):    
    OWNER_ID                    = 'ownerId'
    GROUP_PERMISSIONS           = 'permissions'

class CMMetaGroupPermissions(enum.Enum):    
    USE_KEY                     = 'UseKey'
    READ_KEY                    = 'ReadKey'
    EXPORT_KEY                  = 'ExportKey'
    UPLOAD_KEY                  = 'UploadKey'
    SIGN                        = 'SignWithKey'
    DECRYPT                     = 'DecryptWithKey'
    ENCRYPT                     = 'EncryptWithKey'
    SIGN_VERIFY                 = 'SignVerifyWithKey'

class CMSecretDataType(enum.Enum):
    BLOB                        = "blob"
    PASSWORD                    = "password"
    SEED                        = "seed"
    
class CMUserGroup:
    def __init__(self, name, member, description=None):
        self.name               = name
        self.member             = member
        self.desc               = description

class CMKeyNewMetaData:
    def __init__(self, t_alias, t_group):
        self.alias              = t_alias
        self.group              = t_group
        
        self.permissions        = {}
        self.permissions.update({"UseKey":              [t_group]})
        self.permissions.update({"ReadKey":             [t_group]})
        self.permissions.update({"ExportKey":           [t_group]})
        self.permissions.update({"UploadKey":           [t_group]})
        self.permissions.update({"SignWithKey":         [t_group]})
        self.permissions.update({"DecryptWithKey":      [t_group]})
        self.permissions.update({"EncryptWithKey":      [t_group]})
        self.permissions.update({"SignVerifyWithKey":   [t_group]})
        
        self.meta               = {"permissions":self.permissions}
        self.aliases            = [{"alias":t_alias, "type":"string"}]
        self.allVersions        = True
        
        self.payload            = {"meta": self.meta, "aliases":self.aliases, "allVersions": self.allVersions}
    
class CMKeyEmptyAliasData:
    def __init__(self):
        self.aliases            = [{"alias":"", "index":0}]
        self.payload            = {"aliases":self.aliases}    