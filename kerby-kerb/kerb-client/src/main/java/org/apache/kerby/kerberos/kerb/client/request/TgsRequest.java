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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncTgsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TgsRequest extends KdcRequest {
    private static final Logger LOG = LoggerFactory.getLogger(TgsRequest.class);

    public TgsRequest(KrbContext context) {
        super(context);
    }

    @Override
    public PrincipalName getClientPrincipal() {
        return null;
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return null;
    }

    public EncryptionKey getSessionKey() {
        return null;
    }

    @Override
    public void process() throws KrbException {
        String serverPrincipal = getRequestOptions().getStringOption(KrbOption.SERVER_PRINCIPAL);
        if (serverPrincipal == null) {
            LOG.warn("Server principal is null.");
        }
        setServerPrincipal(new PrincipalName(serverPrincipal));
        super.process();

        TgsReq tgsReq = new TgsReq();

        KdcReqBody tgsReqBody = getReqBody(null);
        tgsReq.setReqBody(tgsReqBody);
        tgsReq.setPaData(getPreauthContext().getOutputPaData());

        setKdcReq(tgsReq);
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException {
        setKdcRep(kdcRep);

        TgsRep tgsRep = (TgsRep) getKdcRep();
        EncTgsRepPart encTgsRepPart;
        try {
            encTgsRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(),
                getSessionKey(),
                KeyUsage.TGS_REP_ENCPART_SESSKEY, EncTgsRepPart.class);
        } catch (KrbException e) {
            encTgsRepPart = EncryptionUtil.unseal(tgsRep.getEncryptedEncPart(),
                getSessionKey(),
                KeyUsage.TGS_REP_ENCPART_SUBKEY, EncTgsRepPart.class);
        }

        tgsRep.setEncPart(encTgsRepPart);

        if (getChosenNonce() != encTgsRepPart.getNonce()) {
            LOG.error("Nonce " + getChosenNonce() + "didn't match " + encTgsRepPart.getNonce());
            throw new KrbException("Nonce didn't match");
        }
    }

    public SgtTicket getSgt() {
        SgtTicket serviceTkt = new SgtTicket(getKdcRep().getTicket(),
                (EncTgsRepPart) getKdcRep().getEncPart());
        return serviceTkt;
    }
}
