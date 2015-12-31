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
import org.apache.kerby.cms.type.EnvelopedContentInfo;
import org.apache.kerby.cms.type.EnvelopedData;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class EnvelopedDataTest extends CmsTestBase {

    @Test
    public void testDecodingKeyTrns() throws IOException {
        byte[] data = readDataFile("/enveloped-keytrns.txt");
        try {
            Asn1.parseAndDump(data);

            EnvelopedContentInfo contentInfo = new EnvelopedContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);

            EnvelopedData envelopedData = contentInfo.getEnvelopedData();
            Asn1.dump(envelopedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testDecodingKek() throws IOException {
        byte[] data = readDataFile("/enveloped-kek.txt");
        try {
            Asn1.parseAndDump(data);

            EnvelopedContentInfo contentInfo = new EnvelopedContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);

            EnvelopedData envelopedData = contentInfo.getEnvelopedData();
            Asn1.dump(envelopedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testDecodingNestedNDEF() throws IOException {
        byte[] data = readDataFile("/enveloped-nested-ndef.txt");
        try {
            Asn1.parseAndDump(data);

            EnvelopedContentInfo contentInfo = new EnvelopedContentInfo();
            contentInfo.decode(data);
            Asn1.dump(contentInfo);

            EnvelopedData envelopedData = contentInfo.getEnvelopedData();
            Asn1.dump(envelopedData);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

}
