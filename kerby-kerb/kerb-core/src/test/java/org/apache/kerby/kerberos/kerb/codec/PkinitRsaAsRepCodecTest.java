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
package org.apache.kerby.kerberos.kerb.codec;

import org.apache.kerby.asn1.Asn1;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.EnvelopedData;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.*;

public class PkinitRsaAsRepCodecTest {
    @Test
    public void test() throws IOException {
        byte[] bytes = CodecTestUtil.readDataFile("/pkinit_rsa_asrep.token");
        ByteBuffer asRepToken = ByteBuffer.wrap(bytes);

        AsRep asRep = new AsRep();
        asRep.decode(asRepToken);

        assertThat(asRep.getPvno()).isEqualTo(5);
        assertThat(asRep.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
        PaData paData = asRep.getPaData();

        PaDataEntry pkAsRepEntry = paData.findEntry(PaDataType.PK_AS_REP);
        assertThat(pkAsRepEntry.getPaDataType()).isEqualTo(PaDataType.PK_AS_REP);

        PaPkAsRep paPkAsRep = new PaPkAsRep();
        byte[] padataValue = pkAsRepEntry.getPaDataValue();
        paPkAsRep.decode(padataValue);

        assertThat(paPkAsRep.getEncKeyPack()).isNotNull();

        byte[] encKeyPack = paPkAsRep.getEncKeyPack();
        Asn1.parseAndDump(encKeyPack);
        ContentInfo contentInfo = new ContentInfo();
        contentInfo.decode(encKeyPack);
        assertThat(contentInfo.getContentType()).isEqualTo("1.2.840.113549.1.7.3");
        EnvelopedData envelopedData = contentInfo.getContentAs(EnvelopedData.class);
        Asn1.dump(envelopedData);
    }
}
