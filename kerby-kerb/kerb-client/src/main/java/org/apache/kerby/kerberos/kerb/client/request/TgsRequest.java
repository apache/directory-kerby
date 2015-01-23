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
package org.apache.kerby.kerberos.kerb.client.request;

import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerby.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.KeyUsage;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.*;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

public class TgsRequest extends KdcRequest {
    private TgtTicket tgt;
    private ApReq apReq;

    public TgsRequest(KrbContext context, TgtTicket tgtTicket) {
        super(context);
        this.tgt = tgtTicket;

        setAllowedPreauth(PaDataType.TGS_REQ);
    }

    public PrincipalName getClientPrincipal() {
        return tgt.getClientPrincipal();
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return getSessionKey();
    }

    public EncryptionKey getSessionKey() {
        return tgt.getSessionKey();
    }

    @Override
    protected void preauth() throws KrbException {
        apReq = makeApReq();
        super.preauth();
    }

    @Override
    public void process() throws KrbException {
        super.process();

        TgsReq tgsReq = new TgsReq();

        KdcReqBody tgsReqBody = makeReqBody();
        tgsReq.setReqBody(tgsReqBody);
        tgsReq.setPaData(getPreauthContext().getOutputPaData());

        setKdcReq(tgsReq);
    }

    private ApReq makeApReq() throws KrbException {
        ApReq apReq = new ApReq();

        Authenticator authenticator = makeAuthenticator();
        EncryptionKey sessionKey = tgt.getSessionKey();
        EncryptedData authnData = EncryptionUtil.seal(authenticator,
                sessionKey, KeyUsage.TGS_REQ_AUTH);
        apReq.setEncryptedAuthenticator(authnData);

        apReq.setTicket(tgt.getTicket());
        ApOptions apOptions = new ApOptions();
        apReq.setApOptions(apOptions);

        return apReq;
    }

    private Authenticator makeAuthenticator() {
        Authenticator authenticator = new Authenticator();
        authenticator.setCname(getClientPrincipal());
        authenticator.setCrealm(tgt.getRealm());

        authenticator.setCtime(KerberosTime.now());
        authenticator.setCusec(0);

        EncryptionKey sessionKey = tgt.getSessionKey();
        authenticator.setSubKey(sessionKey);

        return authenticator;
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException {
        setKdcRep(kdcRep);

        TgsRep tgsRep = (TgsRep) getKdcRep();
        EncTgsRepPart encTgsRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(),
                getSessionKey(),
                KeyUsage.TGS_REP_ENCPART_SESSKEY, EncTgsRepPart.class);

        tgsRep.setEncPart(encTgsRepPart);

        if (getChosenNonce() != encTgsRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }
    }

    public ServiceTicket getServiceTicket() {
        ServiceTicket serviceTkt = new ServiceTicket(getKdcRep().getTicket(),
                (EncTgsRepPart) getKdcRep().getEncPart());
        return serviceTkt;
    }

    public ApReq getApReq() {
        return apReq;
    }
}
