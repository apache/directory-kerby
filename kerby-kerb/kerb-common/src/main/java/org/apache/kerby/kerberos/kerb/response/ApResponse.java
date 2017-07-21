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
package org.apache.kerby.kerberos.kerb.response;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.request.ApRequest;
import org.apache.kerby.kerberos.kerb.type.ap.ApRep;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.type.ap.EncAPRepPart;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;

/**
 * A wrapper for ApRep request.
 */
public class ApResponse {
    private ApReq apReq;
    private ApRep apRep;
    EncryptionKey encryptionKey;

    public ApResponse(ApReq apReq, EncryptionKey encryptionKey) {
        this.apReq = apReq;
        this.encryptionKey = encryptionKey;
    }

    public ApResponse(ApReq apReq) {
        this.apReq = apReq;
    }

    public ApRep getApRep() throws KrbException {
        if (encryptionKey != null) {
            ApRequest.validate(encryptionKey, apReq);
        }

        if (apRep == null) {
            apRep = makeApRep();
        }
        return apRep;
    }

    public void setApRep(ApRep apRep) {
        this.apRep = apRep;
    }

    /*
     *  The KRB_AP_REP message contains the Kerberos protocol version number,
     *  the message type, and an encrypted time-stamp.
     */
    private ApRep makeApRep() throws KrbException {

        ApRep apRep = new ApRep();
        EncAPRepPart encAPRepPart = new EncAPRepPart();

        Authenticator auth = apReq.getAuthenticator();
        // This field contains the current time on the client's host.
        encAPRepPart.setCtime(auth.getCtime());
        // This field contains the microsecond part of the client's timestamp.
        encAPRepPart.setCusec(auth.getCusec());
        encAPRepPart.setSubkey(auth.getSubKey());
        encAPRepPart.setSeqNumber(0);
        apRep.setEncRepPart(encAPRepPart);
        EncryptedData encPart = EncryptionUtil.seal(encAPRepPart, auth.getSubKey(), KeyUsage.AP_REP_ENCPART);
        apRep.setEncryptedEncPart(encPart);

        return apRep;
    }

    /**
     * Validation for KRB_AP_REP message
     * @param encKey key used to encrypt encrypted part of KRB_AP_REP message
     * @param apRep KRB_AP_REP message received
     * @param apReqSent the KRB_AP_REQ message that caused the KRB_AP_REP message from server
     * @throws KrbException
     */
    public static void validate(EncryptionKey encKey, ApRep apRep, ApReq apReqSent) throws KrbException {
        EncAPRepPart encPart = EncryptionUtil.unseal(apRep.getEncryptedEncPart(),
                encKey, KeyUsage.AP_REP_ENCPART, EncAPRepPart.class);
        apRep.setEncRepPart(encPart);
        if (apReqSent != null) {
            Authenticator auth = apReqSent.getAuthenticator();
            if (!encPart.getCtime().equals(auth.getCtime())
                    || encPart.getCusec() != auth.getCusec()) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_MUT_FAIL);
            }
        }
    }
}
