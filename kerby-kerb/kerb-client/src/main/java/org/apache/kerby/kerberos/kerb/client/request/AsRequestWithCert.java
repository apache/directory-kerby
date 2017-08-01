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

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.preauth.PreauthContext;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;

public class AsRequestWithCert extends AsRequest {

    public static final String ANONYMOUS_PRINCIPAL = "ANONYMOUS@WELLKNOWN:ANONYMOUS";

    public AsRequestWithCert(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.PK_AS_REQ);
    }

    @Override
    public void process() throws KrbException {
        KdcReqBody body = getReqBody(null);
        AsReq asReq = new AsReq();
        asReq.setReqBody(body);
        setKdcReq(asReq);

        preauth();

        asReq.setPaData(getPreauthContext().getOutputPaData());
        setKdcReq(asReq);
    }

    @Override
    public KOptions getPreauthOptions() {
        KOptions results = new KOptions();

        KOptions krbOptions = getRequestOptions();
        results.add(krbOptions.getOption(PkinitOption.X509_CERTIFICATE));
        results.add(krbOptions.getOption(PkinitOption.X509_ANCHORS));
        results.add(krbOptions.getOption(PkinitOption.X509_PRIVATE_KEY));
        results.add(krbOptions.getOption(PkinitOption.X509_IDENTITY));
        results.add(krbOptions.getOption(PkinitOption.USING_RSA));

        if (krbOptions.contains(PkinitOption.USE_ANONYMOUS)) {
            getKdcOptions().setFlag(KdcOption.REQUEST_ANONYMOUS);
        }

        return results;
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException {

        PreauthContext preauthContext = getPreauthContext();
        preauthContext.setInputPaData(kdcRep.getPaData());
        preauth();

        super.processResponse(kdcRep);
    }

    @Override
    public EncryptionKey getClientKey() throws KrbException {
        return getAsKey();
    }
}
