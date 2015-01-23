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
package org.apache.kerby.kerberos.kerb.spec.pa;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

/**
 * From krb5.h
 */
public enum PaDataType implements KrbEnum {
    NONE                (0),
    TGS_REQ              (1),
    AP_REQ              (1),
    ENC_TIMESTAMP       (2), // RFC 4120
    PW_SALT             (3), // RFC 4120
    ENC_ENCKEY        (4),  // Key encrypted within itself
    ENC_UNIX_TIME       (5),  // timestamp encrypted in key. RFC 4120
    ENC_SANDIA_SECURID (6),  // SecurId passcode. RFC 4120
    SESAME              (7),  // Sesame project. RFC 4120
    OSF_DCE             (8),  // OSF DCE. RFC 4120
    CYBERSAFE_SECUREID (9),  // Cybersafe. RFC 4120
    AFS3_SALT           (10), // Cygnus. RFC 4120, 3961
    ETYPE_INFO          (11), // Etype info for preauth. RFC 4120
    SAM_CHALLENGE       (12), // SAM/OTP
    SAM_RESPONSE        (13), // SAM/OTP
    PK_AS_REQ           (16), // PKINIT. RFC 4556
    PK_AS_REP           (17), // PKINIT. RFC 4556
    ETYPE_INFO2         (19), // RFC 4120
    USE_SPECIFIED_KVNO  (20), // RFC 4120
    SVR_REFERRAL_INFO   (20), // Windows 2000 referrals. RFC 6820
    SAM_REDIRECT        (21), // SAM/OTP. RFC 4120
    GET_FROM_TYPED_DATA (22), // Embedded in typed data. RFC 4120
    REFERRAL            (25), // draft referral system
    SAM_CHALLENGE_2     (30), // draft challenge system, updated
    SAM_RESPONSE_2      (31), // draft challenge system, updated
    /* MS-KILE */
    PAC_REQUEST         (128), // include Windows PAC
    FOR_USER            (129), // username protocol transition request
    S4U_X509_USER       (130), // certificate protocol transition request
    AS_CHECKSUM         (132), // AS checksum
    FX_COOKIE           (133), // RFC 6113
    FX_FAST             (136), // RFC 6113
    FX_ERROR            (137), // RFC 6113
    ENCRYPTED_CHALLENGE (138), // RFC 6113
    OTP_CHALLENGE       (141), // RFC 6560 section 4.1
    OTP_REQUEST         (142), // RFC 6560 section 4.2
    OTP_PIN_CHANGE      (144), // RFC 6560 section 4.3
    PKINIT_KX           (147), // RFC 6112
    ENCPADATA_REQ_ENC_PA_REP   (149), // RFC 6806
    TOKEN_REQUEST       (148), // TokenPreauth
    TOKEN_CHALLENGE     (149);

    private final int value;

    private PaDataType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static PaDataType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (PaDataType) e;
                }
            }
        }

        return NONE;
    }
}
