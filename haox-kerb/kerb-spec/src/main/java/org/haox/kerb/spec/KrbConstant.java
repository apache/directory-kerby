package org.haox.kerb.spec;

public interface KrbConstant {
/** The Kerberos version 5 */
    public final static int KERBEROS_V5 = 5;
//-------------------------------------------------------------------------
// Messages
//-------------------------------------------------------------------------
/** Ticket message's tags */
    public final static int TICKET_TAG = 0x61;
    public final static int TICKET_TKT_VNO_TAG = 0xA0;
    public final static int TICKET_REALM_TAG = 0xA1;
    public final static int TICKET_SNAME_TAG = 0xA2;
    public final static int TICKET_ENC_PART_TAG = 0xA3;
/** Authenticator tags */
    public final static int AUTHENTICATOR_TAG = 0x62;
    public final static int AUTHENTICATOR_AUTHENTICATOR_VNO_TAG = 0xA0;
    public final static int AUTHENTICATOR_CREALM_TAG = 0xA1;
    public final static int AUTHENTICATOR_CNAME_TAG = 0xA2;
    public final static int AUTHENTICATOR_CKSUM_TAG = 0xA3;
    public final static int AUTHENTICATOR_CUSEC_TAG = 0xA4;
    public final static int AUTHENTICATOR_CTIME_TAG = 0xA5;
    public final static int AUTHENTICATOR_SUBKEY_TAG = 0xA6;
    public final static int AUTHENTICATOR_SEQ_NUMBER_TAG = 0xA7;
    public final static int AUTHENTICATOR_AUTHORIZATION_DATA_TAG = 0xA8;
/** AS-REQ's tags */
    public final static int AS_REQ_TAG = 0x6A;
/** AS-REP's tags */
    public final static int AS_REP_TAG = 0x6B;
/** TGS-REQ's tags */
    public final static int TGS_REQ_TAG = 0x6C;
/** TGS-REP's tags */
    public final static int TGS_REP_TAG = 0x6D;
/** AP-REQ tags */
    public final static int AP_REQ_TAG = 0x6E;
    public final static int AP_REQ_PVNO_TAG = 0xA0;
    public final static int AP_REQ_MSG_TYPE_TAG = 0xA1;
    public final static int AP_REQ_AP_OPTIONS_TAG = 0xA2;
    public final static int AP_REQ_TICKET_TAG = 0xA3;
    public final static int AP_REQ_AUTHENTICATOR_TAG = 0xA4;
/** AP-REP tags */
    public final static int AP_REP_TAG = 0x6F;
    public final static int AP_REP_PVNO_TAG = 0xA0;
    public final static int AP_REP_MSG_TYPE_TAG = 0xA1;
    public final static int AP_REP_ENC_PART_TAG = 0xA2;
/** KrbSafe tags */
    public final static int KRB_SAFE_TAG = 0x74;
    public final static int KRB_SAFE_PVNO_TAG = 0xA0;
    public final static int KRB_SAFE_MSGTYPE_TAG = 0xA1;
    public final static int KRB_SAFE_SAFE_BODY_TAG = 0xA2;
    public final static int KRB_SAFE_CKSUM_TAG = 0xA3;
/** KrbPriv */
    public final static int KRB_PRIV_TAG = 0x75;
    public final static int KRB_PRIV_PVNO_TAG = 0xA0;
    public final static int KRB_PRIV_MSGTYPE_TAG = 0xA1;
    public final static int KRB_PRIV_ENC_PART_TAG = 0xA3;
/** EncAsRepPart's tags */
    public final static int ENC_AS_REP_PART_TAG = 0x79;
/** EncTgsRepPart's tags */
    public final static int ENC_TGS_REP_PART_TAG = 0x7A;
/** EncAPRepPart's tags */
    public final static int ENC_AP_REP_PART_TAG = 0x7B;
    public final static int ENC_AP_REP_PART_CTIME_TAG = 0xA0;
    public final static int ENC_AP_REP_PART_CUSEC_TAG = 0xA1;
    public final static int ENC_AP_REP_PART_SUB_KEY_TAG = 0xA2;
    public final static int ENC_AP_REP_PART_SEQ_NUMBER_TAG = 0xA3;
/** EncKrbPrivPart */
    public final static int ENC_KRB_PRIV_PART_TAG = 0x7C;
    public final static int ENC_KRB_PRIV_PART_USER_DATA_TAG = 0xA0;
    public final static int ENC_KRB_PRIV_PART_TIMESTAMP_TAG = 0xA1;
    public final static int ENC_KRB_PRIV_PART_USEC_TAG = 0xA2;
    public final static int ENC_KRB_PRIV_PART_SEQ_NUMBER_TAG = 0xA3;
    public final static int ENC_KRB_PRIV_PART_SENDER_ADDRESS_TAG = 0xA4;
    public final static int ENC_KRB_PRIV_PART_RECIPIENT_ADDRESS_TAG = 0xA5;
/** KRB-ERROR tags */
    public final static int KRB_ERROR_TAG = 0x7E;
    public final static int KRB_ERROR_PVNO_TAG = 0xA0;
    public final static int KRB_ERROR_MSGTYPE_TAG = 0xA1;
    public final static int KRB_ERROR_CTIME_TAG = 0xA2;
    public final static int KRB_ERROR_CUSEC_TAG = 0xA3;
    public final static int KRB_ERROR_STIME_TAG = 0xA4;
    public final static int KRB_ERROR_SUSEC_TAG = 0xA5;
    public final static int KRB_ERROR_ERROR_CODE_TAG = 0xA6;
    public final static int KRB_ERROR_CREALM_TAG = 0xA7;
    public final static int KRB_ERROR_CNAME_TAG = 0xA8;
    public final static int KRB_ERROR_REALM_TAG = 0xA9;
    public final static int KRB_ERROR_SNAME_TAG = 0xAA;
    public final static int KRB_ERROR_ETEXT_TAG = 0xAB;
    public final static int KRB_ERROR_EDATA_TAG = 0xAC;
/** KRB-CRED tags */
    public final static int KRB_CRED_TAG = 0x76;
    public final static int KRB_CRED_PVNO_TAG = 0xA0;
    public final static int KRB_CRED_MSGTYPE_TAG = 0xA1;
    public final static int KRB_CRED_TICKETS_TAG = 0xA2;
    public final static int KRB_CRED_ENCPART_TAG = 0xA3;
//-------------------------------------------------------------------------
// Components
//-------------------------------------------------------------------------
/** AD-AND-OR */
    public final static int AD_AND_OR_CONDITION_COUNT_TAG = 0xA0;
    public final static int AD_AND_OR_ELEMENTS_TAG = 0xA1;
/** AD-KDCIssued */
    public final static int AD_KDC_ISSUED_AD_CHECKSUM_TAG = 0xA0;
    public final static int AD_KDC_ISSUED_I_REALM_TAG = 0xA1;
    public final static int AD_KDC_ISSUED_I_SNAME_TAG = 0xA2;
    public final static int AD_KDC_ISSUED_ELEMENTS_TAG = 0xA3;
/** AuthorizationData tags */
    public final static int AUTHORIZATION_DATA_ADTYPE_TAG = 0xA0;
    public final static int AUTHORIZATION_DATA_ADDATA_TAG = 0xA1;
/** Checksum tags */
    public final static int CHECKSUM_TYPE_TAG = 0xA0;
    public final static int CHECKSUM_CHECKSUM_TAG = 0xA1;
/** EncKdcRepPart tags */
    public final static int ENC_KDC_REP_PART_KEY_TAG = 0xA0;
    public final static int ENC_KDC_REP_PART_LAST_REQ_TAG = 0xA1;
    public final static int ENC_KDC_REP_PART_NONCE_TAG = 0xA2;
    public final static int ENC_KDC_REP_PART_KEY_EXPIRATION_TAG = 0xA3;
    public final static int ENC_KDC_REP_PART_FLAGS_TAG = 0xA4;
    public final static int ENC_KDC_REP_PART_AUTH_TIME_TAG = 0xA5;
    public final static int ENC_KDC_REP_PART_START_TIME_TAG = 0xA6;
    public final static int ENC_KDC_REP_PART_END_TIME_TAG = 0xA7;
    public final static int ENC_KDC_REP_PART_RENEW_TILL_TAG = 0xA8;
    public final static int ENC_KDC_REP_PART_SREALM_TAG = 0xA9;
    public final static int ENC_KDC_REP_PART_SNAME_TAG = 0xAA;
    public final static int ENC_KDC_REP_PART_CADDR_TAG = 0xAB;
/** EncKrbCredPart tags */
    public final static int ENC_KRB_CRED_PART_TAG = 0x7D;
    public final static int ENC_KRB_CRED_TICKET_INFO_TAG = 0xA0;
    public final static int ENC_KRB_CRED_PART_NONCE_TAG = 0xA1;
    public final static int ENC_KRB_CRED_PART_TIMESTAMP_TAG = 0xA2;
    public final static int ENC_KRB_CRED_PART_USEC_TAG = 0xA3;
    public final static int ENC_KRB_CRED_PART_SENDER_ADDRESS_TAG = 0xA4;
    public final static int ENC_KRB_CRED_PART_RECIPIENT_ADDRESS_TAG = 0xA5;
/** Encrypteddata's tags */
    public final static int ENCRYPTED_DATA_ETYPE_TAG = 0xA0;
    public final static int ENCRYPTED_DATA_KVNO_TAG = 0xA1;
    public final static int ENCRYPTED_DATA_CIPHER_TAG = 0xA2;
/** EncryptionKey tags */
    public final static int ENCRYPTION_KEY_TYPE_TAG = 0xA0;
    public final static int ENCRYPTION_KEY_VALUE_TAG = 0xA1;
/** EncTicketPart tags */
    public final static int ENC_TICKET_PART_TAG = 0x63;
    public final static int ENC_TICKET_PART_FLAGS_TAG = 0xA0;
    public final static int ENC_TICKET_PART_KEY_TAG = 0xA1;
    public final static int ENC_TICKET_PART_CREALM_TAG = 0xA2;
    public final static int ENC_TICKET_PART_CNAME_TAG = 0xA3;
    public final static int ENC_TICKET_PART_TRANSITED_TAG = 0xA4;
    public final static int ENC_TICKET_PART_AUTHTIME_TAG = 0xA5;
    public final static int ENC_TICKET_PART_STARTTIME_TAG = 0xA6;
    public final static int ENC_TICKET_PART_ENDTIME_TAG = 0xA7;
    public final static int ENC_TICKET_PART_RENEWTILL_TAG = 0xA8;
    public final static int ENC_TICKET_PART_CADDR_TAG = 0xA9;
    public final static int ENC_TICKET_PART_AUTHORIZATION_DATA_TAG = 0xAA;
/** ETYPE-INFO-ENTRY tags */
    public final static int ETYPE_INFO_ENTRY_ETYPE_TAG = 0xA0;
    public final static int ETYPE_INFO_ENTRY_SALT_TAG = 0xA1;
/** ETYPE-INFO2-ENTRY tags */
    public final static int ETYPE_INFO2_ENTRY_ETYPE_TAG = 0xA0;
    public final static int ETYPE_INFO2_ENTRY_SALT_TAG = 0xA1;
    public final static int ETYPE_INFO2_ENTRY_S2KPARAMS_TAG = 0xA2;
/** HostAddress' tags */
    public final static int HOST_ADDRESS_ADDR_TYPE_TAG = 0xA0;
    public final static int HOST_ADDRESS_ADDRESS_TAG = 0xA1;
/** KrbCredInfo tags */
    public final static int KRB_CRED_INFO_KEY_TAG = 0xA0;
    public final static int KRB_CRED_INFO_PREALM_TAG = 0xA1;
    public final static int KRB_CRED_INFO_PNAME_TAG = 0xA2;
    public final static int KRB_CRED_INFO_FLAGS_TAG = 0xA3;
    public final static int KRB_CRED_INFO_AUTHTIME_TAG = 0xA4;
    public final static int KRB_CRED_INFO_STARTTIME_TAG = 0xA5;
    public final static int KRB_CRED_INFO_ENDTIME_TAG = 0xA6;
    public final static int KRB_CRED_INFO_RENEWTILL_TAG = 0xA7;
    public final static int KRB_CRED_INFO_SREALM_TAG = 0xA8;
    public final static int KRB_CRED_INFO_SNAME_TAG = 0xA9;
    public final static int KRB_CRED_INFO_CADDR_TAG = 0xAA;
/** KRB-REP's tags */
    public final static int KDC_REP_PVNO_TAG = 0xA0;
    public final static int KDC_REP_MSG_TYPE_TAG = 0xA1;
    public final static int KDC_REP_PA_DATA_TAG = 0xA2;
    public final static int KDC_REP_CREALM_TAG = 0xA3;
    public final static int KDC_REP_CNAME_TAG = 0xA4;
    public final static int KDC_REP_TICKET_TAG = 0xA5;
    public final static int KDC_REP_ENC_PART_TAG = 0xA6;
/** KRB-REQ's tags */
    public final static int KDC_REQ_PVNO_TAG = 0xA1;
    public final static int KDC_REQ_MSG_TYPE_TAG = 0xA2;
    public final static int KDC_REQ_PA_DATA_TAG = 0xA3;
    public final static int KDC_REQ_KDC_REQ_BODY_TAG = 0xA4;
/** KRB-REQ-BODY's tags */
    public final static int KDC_REQ_BODY_KDC_OPTIONS_TAG = 0xA0;
    public final static int KDC_REQ_BODY_CNAME_TAG = 0xA1;
    public final static int KDC_REQ_BODY_REALM_TAG = 0xA2;
    public final static int KDC_REQ_BODY_SNAME_TAG = 0xA3;
    public final static int KDC_REQ_BODY_FROM_TAG = 0xA4;
    public final static int KDC_REQ_BODY_TILL_TAG = 0xA5;
    public final static int KDC_REQ_BODY_RTIME_TAG = 0xA6;
    public final static int KDC_REQ_BODY_NONCE_TAG = 0xA7;
    public final static int KDC_REQ_BODY_ETYPE_TAG = 0xA8;
    public final static int KDC_REQ_BODY_ADDRESSES_TAG = 0xA9;
    public final static int KDC_REQ_BODY_ENC_AUTHZ_DATA_TAG = 0xAA;
    public final static int KDC_REQ_BODY_ADDITIONAL_TICKETS_TAG = 0xAB;
/** KrbSafeBody tags */
    public final static int KRB_SAFE_BODY_USER_DATA_TAG = 0xA0;
    public final static int KRB_SAFE_BODY_TIMESTAMP_TAG = 0xA1;
    public final static int KRB_SAFE_BODY_USEC_TAG = 0xA2;
    public final static int KRB_SAFE_BODY_SEQ_NUMBER_TAG = 0xA3;
    public final static int KRB_SAFE_BODY_SENDER_ADDRESS_TAG = 0xA4;
    public final static int KRB_SAFE_BODY_RECIPIENT_ADDRESS_TAG = 0xA5;
/** LastRequest tags */
    public final static int LAST_REQ_LR_TYPE_TAG = 0xA0;
    public final static int LAST_REQ_LR_VALUE_TAG = 0xA1;
/** PaData tags */
    public final static int PADATA_TYPE_TAG = 0xA1;
    public final static int PADATA_VALUE_TAG = 0xA2;
/** PA-ENC-TS-ENC tags */
    public final static int PA_ENC_TS_ENC_PA_TIMESTAMP_TAG = 0xA0;
    public final static int PA_ENC_TS_ENC_PA_USEC_TAG = 0xA1;
/** PrincipalName's tags */
    public final static int PRINCIPAL_NAME_NAME_TYPE_TAG = 0xA0;
    public final static int PRINCIPAL_NAME_NAME_STRING_TAG = 0xA1;
/** TransitedEncoding tags */
    public final static int TRANSITED_ENCODING_TR_TYPE_TAG = 0xA0;
    public final static int TRANSITED_ENCODING_CONTENTS_TAG = 0xA1;
/** TypedData tags */
    public final static int TYPED_DATA_TDTYPE_TAG = 0xA0;
    public final static int TYPED_DATA_TDDATA_TAG = 0xA1;
/** CHangePasswdData tags */
    public final static int CHNGPWD_NEWPWD_TAG = 0xA0;
    public final static int CHNGPWD_TARGNAME_TAG = 0xA1;
    public final static int CHNGPWD_TARGREALM_TAG = 0xA2;
};
