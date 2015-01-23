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

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.*;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;

import java.io.IOException;
import java.util.List;

public class AsRequest extends KdcRequest {

    private PrincipalName clientPrincipal;
    private EncryptionKey clientKey;

    public AsRequest(KrbContext context) {
        super(context);

        setServerPrincipal(makeTgsPrincipal());
    }

    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(PrincipalName clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public EncryptionKey getClientKey() throws KrbException {
        return clientKey;
    }

    @Override
    public void process() throws KrbException {
        super.process();

        KdcReqBody body = makeReqBody();

        AsReq asReq = new AsReq();
        asReq.setReqBody(body);
        asReq.setPaData(getPreauthContext().getOutputPaData());

        setKdcReq(asReq);
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException  {
        setKdcRep(kdcRep);

        PrincipalName clientPrincipal = getKdcRep().getCname();
        String clientRealm = getKdcRep().getCrealm();
        clientPrincipal.setRealm(clientRealm);
        if (! clientPrincipal.equals(getClientPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_NAME_MISMATCH);
        }

        byte[] decryptedData = decryptWithClientKey(getKdcRep().getEncryptedEncPart(),
                KeyUsage.AS_REP_ENCPART);
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode EncAsRepPart", e);
        }
        getKdcRep().setEncPart(encKdcRepPart);

        if (getChosenNonce() != encKdcRepPart.getNonce()) {
            throw new KrbException("Nonce didn't match");
        }

        PrincipalName serverPrincipal = encKdcRepPart.getSname();
        serverPrincipal.setRealm(encKdcRepPart.getSrealm());
        if (! serverPrincipal.equals(getServerPrincipal())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
        }

        HostAddresses hostAddresses = getHostAddresses();
        if (hostAddresses != null) {
            List<HostAddress> requestHosts = hostAddresses.getElements();
            if (!requestHosts.isEmpty()) {
                List<HostAddress> responseHosts = encKdcRepPart.getCaddr().getElements();
                for (HostAddress h : requestHosts) {
                    if (!responseHosts.contains(h)) {
                        throw new KrbException("Unexpected client host");
                    }
                }
            }
        }
    }

    public TgtTicket getTicket() {
        TgtTicket TgtTicket = new TgtTicket(getKdcRep().getTicket(),
                (EncAsRepPart) getKdcRep().getEncPart(), getKdcRep().getCname().getName());
        return TgtTicket;
    }

    private PrincipalName makeTgsPrincipal() {
        return new PrincipalName(KrbConstant.TGS_PRINCIPAL + "@" + getContext().getKdcRealm());
    }
}
