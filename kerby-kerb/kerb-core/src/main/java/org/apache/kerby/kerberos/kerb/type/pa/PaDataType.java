/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.type.pa;

import org.apache.kerby.asn1.EnumType;

/**
 * The various pre-authorization types, as defined in RFC 4120, RFC 3961, RFC 4556, RFC 6820,
 * RFC 6112, RFC 6113, RFC 6560 and RFC 6806.
 * 
 * From RFC 4120 : 
 * <pre>
 * 7.5.2.  PreAuthentication Data Types
 * 
 *    Padata and Data Type    Padata-type   Comment
 *                             Value
 * 
 *    PA-TGS-REQ                  1
 *    PA-ENC-TIMESTAMP            2
 *    PA-PW-SALT                  3
 *    [reserved]                  4
 *    PA-ENC-UNIX-TIME            5        (deprecated)
 *    PA-SANDIA-SECUREID          6
 *    PA-SESAME                   7
 *    PA-OSF-DCE                  8
 *    PA-CYBERSAFE-SECUREID       9
 *    PA-AFS3-SALT                10
 *    PA-ETYPE-INFO               11
 *    PA-SAM-CHALLENGE            12       (sam/otp)
 *    PA-SAM-RESPONSE             13       (sam/otp)
 *    PA-PK-AS-REQ_OLD            14       (pkinit)
 *    PA-PK-AS-REP_OLD            15       (pkinit)
 *    PA-PK-AS-REQ                16       (pkinit)
 *    PA-PK-AS-REP                17       (pkinit)
 *    PA-ETYPE-INFO2              19       (replaces pa-etype-info)
 *    PA-USE-SPECIFIED-KVNO       20
 *    PA-SAM-REDIRECT             21       (sam/otp)
 *    PA-GET-FROM-TYPED-DATA      22       (embedded in typed data)
 *    TD-PADATA                   22       (embeds padata)
 *    PA-SAM-ETYPE-INFO           23       (sam/otp)
 *    PA-ALT-PRINC                24       (crawdad@fnal.gov)
 *    PA-SAM-CHALLENGE2           30       (kenh@pobox.com)
 *    PA-SAM-RESPONSE2            31       (kenh@pobox.com)
 *    PA-EXTRA-TGT                41       Reserved extra TGT
 *    TD-PKINIT-CMS-CERTIFICATES  101      CertificateSet from CMS
 *    TD-KRB-PRINCIPAL            102      PrincipalName
 *    TD-KRB-REALM                103      Realm
 *    TD-TRUSTED-CERTIFIERS       104      from PKINIT
 *    TD-CERTIFICATE-INDEX        105      from PKINIT
 *    TD-APP-DEFINED-ERROR        106      application specific
 *    TD-REQ-NONCE                107      INTEGER
 *    TD-REQ-SEQ                  108      INTEGER
 *    PA-PAC-REQUEST              128      (jbrezak@exchange.microsoft.com)
 * </pre>
 * 
 * From RFC 6113 :
 * <pre>
 *    PA-FOR_USER                129  [MS-KILE]
 *    PA-FOR-X509-USER           130  [MS-KILE]
 *    PA-FOR-CHECK_DUPS          131  [MS-KILE]
 *    PA-AS-CHECKSUM             132  [MS-KILE]
 *    PA-FX-COOKIE               133  [RFC6113]
 *    PA-AUTHENTICATION-SET      134  [RFC6113]
 *    PA-AUTH-SET-SELECTED       135  [RFC6113]
 *    PA-FX-FAST                 136  [RFC6113]
 *    PA-FX-ERROR                137  [RFC6113]
 *    PA-ENCRYPTED-CHALLENGE     138  [RFC6113]
 *    PA-OTP-CHALLENGE           141  (gareth.richards@rsa.com) [OTP-PREAUTH]
 *    PA-OTP-REQUEST             142  (gareth.richards@rsa.com) [OTP-PREAUTH]
 *    PA-OTP-CONFIRM             143  (gareth.richards@rsa.com) [OTP-PREAUTH]
 *    PA-OTP-PIN-CHANGE          144  (gareth.richards@rsa.com) [OTP-PREAUTH]
 *    PA-EPAK-AS-REQ             145  (sshock@gmail.com) [RFC6113]
 *    PA-EPAK-AS-REP             146  (sshock@gmail.com) [RFC6113]
 *    PA_PKINIT_KX               147  [RFC6112]
 *    PA_PKU2U_NAME              148  [PKU2U]
 * </pre>
 * 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum PaDataType implements EnumType {
    NONE                        (0),
    TGS_REQ                     (1),  // RFC 4120 : DER encoding of AP-REQ
    AP_REQ                      (1),  // same
    ENC_TIMESTAMP               (2),  // RFC 4120 : DER encoding of PA-ENC-TIMESTAMP
    PW_SALT                     (3),  // RFC 4120 : salt (not ASN.1 encoded)
    ENC_ENCKEY                  (4),  // RFC 4120 : [reserved] Key encrypted within itself
    ENC_UNIX_TIME               (5),  // RFC 4120 : deprecated (timestamp encrypted in key )
    ENC_SANDIA_SECURID          (6),  // RFC 4120 : SecureId passcode
    SESAME                      (7),  // RFC 4120 : Sesame project 
    OSF_DCE                     (8),  // RFC 4120 : OSF DCE
    CYBERSAFE_SECUREID          (9),  // RFC 4120 : Cybersafe 
    AFS3_SALT                   (10), // RFC 4120 : 
    ETYPE_INFO                  (11), // RFC 4120 : DER encoding of ETYPE-INFO
    SAM_CHALLENGE               (12), // RFC 4120 : SAM/OTP
    SAM_RESPONSE                (13), // RFC 4120 : SAM/OTP
    PK_AS_REQ_OLD               (14), // RFC 4120 : pkinit
    PK_AS_REP_OLD               (15), // RFC 4120 : pkinit
    PK_AS_REQ                   (16), // RFC 4120 : pkinit
    PK_AS_REP                   (17), // RFC 4120 : pkinit
    // 18 is undefined
    ETYPE_INFO2                 (19), // RFC 4120 : DER encoding of ETYPE-INFO2
    USE_SPECIFIED_KVNO          (20), // RFC 4120
    SVR_REFERRAL_INFO           (20), // RFC 6806 : Kerberos Principal Name Canonicalization and Cross-Realm Referrals
    SAM_REDIRECT                (21), // RFC 4120 : SAM/OTP
    GET_FROM_TYPED_DATA         (22), // RFC 4120 : Embedded in typed data
    //SAM_ETYPE_INFO            (23), // RFC 4120 : SAM/OTP
    //ALT_PRINC                 (24), // RFC 4120 : crawdad@fnal.gov
    REFERRAL                    (25), // draft-ietf-krb-wg-kerberos-referrals, up to version 11. Removed
    // 26 to 29 undefined
    SAM_CHALLENGE_2             (30), // kenh@pobox.com
    SAM_RESPONSE_2              (31), // kenh@pobox.com
    // 32 to 40 are undefined
    //EXTRA_TGT                 (41), // RFC 4120 : Reserved extra TGT
    //TD_PKINIT-CMS_CERTIFICATES(101), // RFC 4120 : CertificateSet from CMS
    //TD_KRB_PRINCIPAL          (102), // RFC 4120 : PrincipalName
    //TD_KRB_REALM              (103), // RFC 4120 : Realm
    //TD_TRUSTED_CERTIFIERS     (104), // RFC 4120 : from PKINIT
    //TD_CERTIFICATE_INDEX      (105), // RFC 4120 : from PKINIT
    //TD_APP_DEFINED_ERROR      (106), // RFC 4120 : application specific
    //TD_REQ_NONCE              (107), // RFC 4120 : INTEGER
    //TD_REQ_SEQ                (108), // RFC 4120 : INTEGER
    
    /* MS-KILE */
    PAC_REQUEST                 (128), // Microsoft, "Kerberos Protocol Extensions"
    FOR_USER                    (129), // Microsoft, "Kerberos Protocol Extensions"
    S4U_X509_USER               (130), // Microsoft, "Kerberos Protocol Extensions"
    // 131 undefined, Microsoft, "Kerberos Protocol Extensions"
    AS_CHECKSUM                 (132), // Microsoft, "Kerberos Protocol Extensions"
    FX_COOKIE                   (133), // RFC 6113 : Managing States for the KDC
    
    // 134 and 135 undefined
    //AUTHENTICATION_SET        (134), // RFC 6113 : Pre-Authentication Set
    //AUTH_SET_SELECTED         (135), // RFC 6113 : Pre-Authentication Set
    FX_FAST                     (136), // RFC 6113 : FAST Request
    FX_ERROR                    (137), // RFC 6113 : Authenticated Kerberos Error Messages Using Kerberos FAST
    ENCRYPTED_CHALLENGE         (138), // RFC 6113 : The Encrypted Challenge FAST Factor
    // 139 and 140 undefined
    
    OTP_CHALLENGE               (141), // RFC 6560 : One-Time Password pre-auth section 4.1
    OTP_REQUEST                 (142), // RFC 6560 : One-Time Password pre-auth section 4.2
    // 143 undefined
    OTP_PIN_CHANGE              (144), // RFC 6560 : One-Time Password pre-auth section 4.3
    // 145 and 146 undefined
    PKINIT_KX                   (147), // RFC 6112 : PKINIT Client Contribution to the Ticket Session Key
    TOKEN_REQUEST               (148), // [PKU2U]
    ENCPADATA_REQ_ENC_PA_REP    (149), // RFC 6806 : Negotiation of FAST and Detecting Modified Requests
    TOKEN_CHALLENGE             (149); // ???

    /** The inner value */
    private final int value;

    /**
     * Create a new enum instance
     */
    PaDataType(int value) {
        this.value = value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name();
    }

    /**
     * Get the PaDataType associated with a value.
     * 
     * @param value The integer value of the PaDataType we are looking for
     * @return The associated PaDataType, or NONE if not found or if value is null
     */
    public static PaDataType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (PaDataType) e;
                }
            }
        }

        return NONE;
    }
}
