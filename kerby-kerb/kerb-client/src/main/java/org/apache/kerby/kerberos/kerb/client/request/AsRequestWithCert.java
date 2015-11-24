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
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.PaPkAsRep;

public class AsRequestWithCert extends AsRequest {

    public static final String ANONYMOUS_PRINCIPAL = "ANONYMOUS@WELLKNOWN:ANONYMOUS";

    public AsRequestWithCert(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.PK_AS_REQ);
        getKdcOptions().setFlag(KdcOption.REQUEST_ANONYMOUS);
    }

    @Override
    public void process() throws KrbException {
        KdcReqBody body = makeReqBody();
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

        KOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_CERTIFICATE));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_ANCHORS));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_PRIVATE_KEY));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_IDENTITY));
        results.add(krbOptions.getOption(KrbOption.PKINIT_USING_RSA));

        return results;
    }

    @Override
    public void processResponse(KdcRep kdcRep) throws KrbException  {

        PaData paData = kdcRep.getPaData();
        for (PaDataEntry paEntry : paData.getElements()) {
            if (paEntry.getPaDataType() == PaDataType.PK_AS_REP) {

                PaPkAsRep paPkAsRep = KrbCodec.decode(paEntry.getPaDataValue(), PaPkAsRep.class);

                byte[] a = paPkAsRep.getEncKeyPack();
//                DHRepInfo dhRepInfo =paPkAsRep.getDHRepInfo();
//                DHNonce nonce = dhRepInfo.getServerDhNonce();
//                byte[] dhSignedData = dhRepInfo.getDHSignedData();
//                PKCS7 pkcs7 = null;
//                try {
//                   pkcs7 = new PKCS7(dhSignedData);
//                } catch (ParsingException e) {
//                    e.printStackTrace();
//                }
//                pkcs7.getContentInfo();

            }
        }

        super.processResponse(kdcRep);
    }
}
