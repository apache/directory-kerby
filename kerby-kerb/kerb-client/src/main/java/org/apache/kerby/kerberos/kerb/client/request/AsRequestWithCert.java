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
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.cms.type.CertificateChoices;
import org.apache.kerby.cms.type.CertificateSet;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhClient;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CmsMessageType;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitCrypto;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.DhRepInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDhKeyInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.apache.kerby.x509.type.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.interfaces.DHPublicKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AsRequestWithCert extends AsRequest {

    private static final Logger LOG = LoggerFactory.getLogger(AsRequestWithCert.class);
    public static final String ANONYMOUS_PRINCIPAL = "ANONYMOUS@WELLKNOWN:ANONYMOUS";

    public AsRequestWithCert(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.PK_AS_REQ);
    }

    @Override
    public void process() throws KrbException {
        KdcReqBody body = getReqBody();
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

        PaData paData = kdcRep.getPaData();
        for (PaDataEntry paEntry : paData.getElements()) {
            // Parse PA-PK-AS-REP message.
            if (paEntry.getPaDataType() == PaDataType.PK_AS_REP) {
                LOG.info("processing PK_AS_REP");

                PaPkAsRep paPkAsRep = KrbCodec.decode(paEntry.getPaDataValue(), PaPkAsRep.class);
                DhRepInfo dhRepInfo = paPkAsRep.getDHRepInfo();

                byte[] dhSignedData = dhRepInfo.getDHSignedData();

                ContentInfo contentInfo = new ContentInfo();
                try {
                    contentInfo.decode(dhSignedData);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                SignedData signedData = contentInfo.getContentAs(SignedData.class);

                PkinitCrypto.verifyCmsSignedData(
                    CmsMessageType.CMS_SIGN_SERVER, signedData);


                String anchorFileName = getContext().getConfig().getPkinitAnchors().get(0);

                X509Certificate x509Certificate = null;
                try {
                    x509Certificate = (X509Certificate) CertificateHelper.loadCerts(
                            anchorFileName).iterator().next();
                } catch (KrbException e) {
                    e.printStackTrace();
                }
                Certificate archorCertificate = PkinitCrypto.changeToCertificate(x509Certificate);

                CertificateSet certificateSet = signedData.getCertificates();
                List<CertificateChoices> certificateChoicesList = certificateSet.getElements();
                List<Certificate> certificates = new ArrayList<>();
                for (CertificateChoices certificateChoices : certificateChoicesList) {
                    certificates.add(certificateChoices.getCertificate());
                }
                try {
                    PkinitCrypto.validateChain(certificates, archorCertificate);
                } catch (Exception e) {
                    throw new KrbException(KrbErrorCode.KDC_ERR_INVALID_CERTIFICATE, e);
                }

                PrincipalName kdcPrincipal = KrbUtil.makeTgsPrincipal(
                        getContext().getConfig().getKdcRealm());
                //TODO USE CertificateSet
                boolean validSan = PkinitCrypto.verifyKdcSan(
                        getContext().getConfig().getPkinitKdcHostName(), kdcPrincipal,
                        certificates);
                if (!validSan) {
                    LOG.error("Did not find an acceptable SAN in KDC certificate");
                }

                LOG.info("skipping EKU check");

                LOG.info("as_rep: DH key transport algorithm");
                KdcDhKeyInfo kdcDhKeyInfo = new KdcDhKeyInfo();
                try {
                    kdcDhKeyInfo.decode(signedData.getEncapContentInfo().getContent());
                } catch (IOException e) {
                    String errMessage = "failed to decode KdcDhKeyInfo " + e.getMessage();
                    LOG.error(errMessage);
                    throw new KrbException(errMessage);
                }

                byte[] subjectPublicKey = kdcDhKeyInfo.getSubjectPublicKey().getValue();

                Asn1Integer clientPubKey = KrbCodec.decode(subjectPublicKey, Asn1Integer.class);
                BigInteger y = clientPubKey.getValue();

                DhClient client = getDhClient();
                BigInteger p = client.getDhParam().getP();
                BigInteger g = client.getDhParam().getG();

                DHPublicKey dhPublicKey = PkinitCrypto.createDHPublicKey(p, g, y);

                EncryptionKey secretKey = null;
                try {
                    client.doPhase(dhPublicKey.getEncoded());
                    secretKey = client.generateKey(null, null, getEncType());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                // Set the DH shared key as the client key
                if (secretKey == null) {
                    throw new KrbException("Fail to create client key.");
                } else {
                    setClientKey(secretKey);
                }
            }
        }
        super.processResponse(kdcRep);
    }
}
