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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.EnumType;

/**
 * From krb5.hin
 */
public enum KeyUsage implements EnumType {
    UNKNOWN(-1),
    NONE(0),
    //AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client key
    AS_REQ_PA_ENC_TS(1),
    //AS-REP Ticket and TGS-REP Ticket (includes TGS session key or application session key),
    //encrypted with the service key (Section 5.3)
    KDC_REP_TICKET(2),
    //AS-REP encrypted part (includes TGS session key or application session key),
    //encrypted with the client key (Section 5.4.2)
    AS_REP_ENCPART(3),
    //TGS-REQ KDC-REQ-BODY AuthorizationData,
    //encrypted with the TGS session key (Section 5.4.1)
    TGS_REQ_AD_SESSKEY(4),
    //TGS-REQ KDC-REQ-BODY AuthorizationData,
    //encrypted with the TGS authenticator subkey (Section 5.4.1)
    TGS_REQ_AD_SUBKEY(5),
    //TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum,
    //keyed with the TGS session key (Section 5.5.1)
    TGS_REQ_AUTH_CKSUM(6),
    //TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes TGS authenticator subkey),
    //encrypted with the TGS session key (Section 5.5.1)
    TGS_REQ_AUTH(7),
    //TGS-REP encrypted part (includes application session key),
    //encrypted with the TGS session key (Section 5.4.2)
    TGS_REP_ENCPART_SESSKEY(8),
    //TGS-REP encrypted part (includes application session key),
    //encrypted with the TGS authenticator subkey (Section 5.4.2)
    TGS_REP_ENCPART_SUBKEY(9),
    //AP-REQ Authenticator cksum, keyed with the application session key (Section 5.5.1)
    AP_REQ_AUTH_CKSUM(10),
    //AP-REQ Authenticator (includes application authenticator subkey),
    //encrypted with the application session key (Section 5.5.1)
    AP_REQ_AUTH(11),
    //AP-REP encrypted part (includes application session subkey),
    //encrypted with the application session key (Section 5.5.2)
    AP_REP_ENCPART(12),
    //KRB-PRIV encrypted part, encrypted with a key chosen by the application (Section 5.7.1)
    KRB_PRIV_ENCPART(13),
    KRB_CRED_ENCPART(14),
    KRB_SAFE_CKSUM(15),
    APP_DATA_ENCRYPT(16),
    APP_DATA_CKSUM(17),
    KRB_ERROR_CKSUM(18),
    AD_KDCISSUED_CKSUM(19),
    AD_MTE(20),
    AD_ITE(21),
    GSS_TOK_MIC(22),
    GSS_TOK_WRAP_INTEG(23),
    GSS_TOK_WRAP_PRIV(24),
    //Defined in Integrating SAM Mechanisms with Kerberos draft
    PA_SAM_CHALLENGE_CKSUM(25),
    //Note conflict with @ref PA_S4U_X509_USER_REQUEST
    PA_SAM_CHALLENGE_TRACKID(26),
    //Note conflict with @ref PA_S4U_X509_USER_REPLY
    PA_SAM_RESPONSE(27),
    //Defined in [MS-SFU]
    //Note conflict with @ref PA_SAM_CHALLENGE_TRACKID
    PA_S4U_X509_USER_REQUEST(26),
    //Note conflict with @ref PA_SAM_RESPONSE
    PA_S4U_X509_USER_REPLY(27),
    //unused
    PA_REFERRAL(26),
    AD_SIGNEDPATH(-21),
    IAKERB_FINISHED(42),
    PA_PKINIT_KX(44),
    PA_OTP_REQUEST(45),  //See RFC 6560 section 4.2
    //define in preauth-framework
    FAST_REQ_CHKSUM(50),
    FAST_ENC(51),
    FAST_REP(52),
    FAST_FINISHED(53),
    ENC_CHALLENGE_CLIENT(54),
    ENC_CHALLENGE_KDC(55),
    AS_REQ(56),
    //PA-TOKEN padata,encrypted with the client key
    PA_TOKEN(57),
    AD_CAMMAC_VERIFIER_MAC(64);  //See RFC 7751

    private int value;

    KeyUsage(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    @Override
    public String getName() {
        return name();
    }

    public static KeyUsage fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value) {
                    return (KeyUsage) e;
                }
            }
        }
        return UNKNOWN;
    }

    public static final boolean isValid(int usage) {
        return usage > -1;
    }
}
