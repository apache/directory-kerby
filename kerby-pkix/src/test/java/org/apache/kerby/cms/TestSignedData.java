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
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.EncapsulatedContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class TestSignedData extends CmsTestBase {

    @Test
    public void testDecoding() throws IOException {
        byte[] data = readDataFile("/signed-data.txt");
        try {
            Asn1.dump(data, true);

            ContentInfo contentInfo = new ContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);

            /** TO BE FIXED AFTER choice supported
            SignedData signedData =
                contentInfo.getContentAs(SignedData.class);
            Asn1.dump(signedData);

            byte[] encodedData = contentInfo.encode();
            Asn1.dump(encodedData, true);
             */
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncoding() throws IOException {
        ContentInfo contentInfo = new ContentInfo();
        contentInfo.setContentType(new Asn1ObjectIdentifier("1.2.840.113549.1.7.2"));
        SignedData signedData = new SignedData();
        EncapsulatedContentInfo eContentInfo = new EncapsulatedContentInfo();
        eContentInfo.setContentType(new Asn1ObjectIdentifier("1.3.6.1.5.2.3.1"));
        eContentInfo.setContent("data".getBytes());
        signedData.setEncapContentInfo(eContentInfo);
        contentInfo.setContent(signedData);
        Asn1.dump(contentInfo);
        byte[] encodedData = contentInfo.encode();
        Asn1.dump(encodedData, true);

        ContentInfo decodedContentInfo = new ContentInfo();
        decodedContentInfo.decode(encodedData);
        Asn1.dump(decodedContentInfo);

        SignedData decodedSignedData =
                decodedContentInfo.getContentAs(SignedData.class);
        Asn1.dump(decodedSignedData);
    }

    @Test
    public void testContentInfo() throws IOException {
        byte[] data = readDataFile("/anonymous.txt");
        try {
            Asn1.dump(data, true);

            ContentInfo contentInfo = new ContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);
/** Failed in DigestAlgorithmIdentifiers*/
//            SignedData signedData =
//                    contentInfo.getContentAs(SignedData.class);
//            Asn1.dump(signedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }
}
