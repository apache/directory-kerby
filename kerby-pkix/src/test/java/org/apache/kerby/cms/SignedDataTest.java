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
package org.apache.kerby.cms;

import org.apache.kerby.asn1.Asn1;
import org.apache.kerby.cms.type.CertificateChoices;
import org.apache.kerby.cms.type.CertificateSet;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.EncapsulatedContentInfo;
import org.apache.kerby.cms.type.SignedContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.x509.type.Certificate;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class SignedDataTest extends CmsTestBase {

    @Test
    public void testDecoding() throws IOException {
        byte[] data = readDataFile("/signed-data.txt");
        try {
            Asn1.parseAndDump(data);
            //Asn1.decodeAndDump(data);

            SignedContentInfo contentInfo = new SignedContentInfo();
            contentInfo.decode(data);
            //Asn1.dump(contentInfo);

            SignedData signedData = contentInfo.getSignedData();
            Asn1.dump(signedData);

            Asn1.dump(contentInfo);
            byte[] encodedData = contentInfo.encode();
            Asn1.parseAndDump(encodedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncoding() throws IOException {
        SignedContentInfo contentInfo = new SignedContentInfo();
        contentInfo.setContentType("1.2.840.113549.1.7.2");
        SignedData signedData = new SignedData();
        EncapsulatedContentInfo eContentInfo = new EncapsulatedContentInfo();
        eContentInfo.setContentType("1.3.6.1.5.2.3.1");
        eContentInfo.setContent("data".getBytes());
        signedData.setEncapContentInfo(eContentInfo);

        byte[] data = readDataFile("/certificate1.txt");
        Certificate certificate = new Certificate();
        certificate.decode(data);
        CertificateChoices certificateChoices = new CertificateChoices();
        certificateChoices.setCertificate(certificate);
        CertificateSet certificateSet = new CertificateSet();
        certificateSet.addElement(certificateChoices);
        signedData.setCertificates(certificateSet);

        contentInfo.setSignedData(signedData);
        Asn1.dump(contentInfo);

        byte[] encodedData = contentInfo.encode();
        Asn1.parseAndDump(encodedData);

        SignedContentInfo decodedContentInfo = new SignedContentInfo();
        decodedContentInfo.decode(encodedData);
        Asn1.dump(decodedContentInfo);

        SignedData decodedSignedData =
                decodedContentInfo.getSignedData();
        Asn1.dump(decodedSignedData);
    }

    @Test
    public void testContentInfo() throws IOException {
        byte[] data = readDataFile("/anonymous.txt");
        try {
            Asn1.parseAndDump(data);

            ContentInfo contentInfo = new ContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);
            SignedData signedData =
                    contentInfo.getContentAs(SignedData.class);
            Asn1.dump(signedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }
}
