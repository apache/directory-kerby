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
import org.apache.kerby.x500.type.Name;
import org.apache.kerby.x509.type.Certificate;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class CertificateTest extends CmsTestBase {
    @Test
    public void testDecodingCertificate() throws IOException {
        byte[] data = readDataFile("/certificate1.txt");
        try {
            Asn1.parseAndDump(data);
            Certificate certificate = new Certificate();
            certificate.decode(data);
            Asn1.dump(certificate);

        } catch (Exception e) {
            Assert.fail("Failed to decode certificate from file:"
                    + " certificate1.txt. " + e.toString());
        }
    }

    @Test
    public void testEncodingCertificate() throws IOException {
        byte[] data = readDataFile("/certificate1.txt");
        Asn1.parseAndDump(data);
        try {
            Certificate certificate = new Certificate();
            certificate.decode(data);
            Asn1.dump(certificate);
            byte[] encodedData = certificate.encode();
            Asn1.parseAndDump(encodedData);

        } catch (Exception e) {
            Assert.fail("Failed to encode certificate from file:"
                    + " certificate1.txt. " + e.toString());
        }
    }

    @Test
    public void testDecodingName() throws IOException {
        byte[] data = readDataFile("/name.txt");
        try {
            Asn1.parseAndDump(data);
            Name name = new Name();
            name.decode(data);
            Asn1.dump(name.getName());
        } catch (Exception e) {
            Assert.fail("Failed to decode name from file:"
                    + " name.txt. " + e.toString());
        }
    }
}
