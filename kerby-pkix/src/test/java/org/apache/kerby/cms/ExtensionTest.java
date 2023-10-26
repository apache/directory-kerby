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

import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.x509.type.Extension;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

public class ExtensionTest {

    @Test
    public void testUnsetCritical() throws IOException {
        Extension extension = new Extension();
        extension.setExtnId(new Asn1ObjectIdentifier("1.3.6.1.5.2.3.1"));
        extension.setExtnValue("value".getBytes());
        extension.setCritical(false);
        byte[] encodedBytes = extension.encode();
        Extension decodedExtension = new Extension();
        decodedExtension.decode(encodedBytes);
        assertThat(decodedExtension.getCritical()).isFalse();
    }

    @Test
    public void testSetCritical() throws IOException {
        Extension extension = new Extension();
        extension.setCritical(true);
        extension.setExtnId(new Asn1ObjectIdentifier("1.3.6.1.5.2.3.1"));
        extension.setExtnValue("value".getBytes());
        byte[] encodedBytes = extension.encode();
        Extension decodedExtension = new Extension();
        decodedExtension.decode(encodedBytes);
        assertThat(decodedExtension.getCritical()).isTrue();
    }
}
