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
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsReq;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

public class PkinitRsaAsReqCodecTest {
    @Test
    public void test() throws IOException, ParseException {
        byte[] bytes = CodecTestUtil.readDataFile("/pkinit_rsa_asreq.token");
        Asn1.parseAndDump(bytes);
        ByteBuffer asReqToken = ByteBuffer.wrap(bytes);

        AsReq asReq = new AsReq();
        asReq.decode(asReqToken);
        //Asn1.decodeAndDump(asReq);

        assertThat(asReq.getPvno()).isEqualTo(5);
        assertThat(asReq.getMsgType()).isEqualTo(KrbMessageType.AS_REQ);

        PaData paData = asReq.getPaData();

        PaDataEntry paFxCookieEntry = paData.findEntry(PaDataType.FX_COOKIE);
        assertThat(paFxCookieEntry.getPaDataType()).isEqualTo(PaDataType.FX_COOKIE);
        assertThat(paFxCookieEntry.getPaDataValue()).isEqualTo(Arrays.copyOfRange(bytes, 38, 41));

        PaDataEntry pkAsReqEntry = paData.findEntry(PaDataType.PK_AS_REQ);
        assertThat(pkAsReqEntry.getPaDataType()).isEqualTo(PaDataType.PK_AS_REQ);
        assertThat(pkAsReqEntry.getPaDataValue()).isEqualTo(Arrays.copyOfRange(bytes, 58, 2138));

        PaPkAsReq paPkAsReq = new PaPkAsReq();
        paPkAsReq.decode(pkAsReqEntry.getPaDataValue());
        ContentInfo contentInfo = new ContentInfo();
        //Asn1.parseAndDump(paPkAsReq.getSignedAuthPack());
        contentInfo.decode(paPkAsReq.getSignedAuthPack());
        assertThat(contentInfo.getContentType()).isEqualTo("1.2.840.113549.1.7.2");
        //Asn1.dump(contentInfo);

        SignedData signedData = contentInfo.getContentAs(SignedData.class);
        assertThat(signedData.getCertificates().getElements().size()).isEqualTo(1);
        assertThat(signedData.getEncapContentInfo().getContentType()).isEqualTo("1.3.6.1.5.2.3.1");

        PaDataEntry encpaEntry = paData.findEntry(PaDataType.ENCPADATA_REQ_ENC_PA_REP);
        assertThat(encpaEntry.getPaDataType()).isEqualTo(PaDataType.ENCPADATA_REQ_ENC_PA_REP);
        assertThat(encpaEntry.getPaDataValue()).isEqualTo(Arrays.copyOfRange(bytes, 2148, 2148));

        KdcReqBody body = asReq.getReqBody();
        assertThat(body.getKdcOptions().getPadding()).isEqualTo(0);
        assertThat(body.getKdcOptions().getValue()).isEqualTo(Arrays.copyOfRange(bytes, 2161, 2165));
        PrincipalName cName = body.getCname();
        assertThat(cName.getNameType()).isEqualTo(NameType.NT_PRINCIPAL);
        assertThat(body.getRealm()).isEqualTo("EXAMPLE.COM");
        PrincipalName sName = body.getSname();
        assertThat(sName.getNameType()).isEqualTo(NameType.NT_SRV_INST);
        assertThat(sName.getNameStrings()).hasSize(2)
                .contains("krbtgt", "EXAMPLE.COM");

        assertThat(body.getNonce()).isEqualTo(658979657);

        List<EncryptionType> types = body.getEtypes();
        assertThat(types).hasSize(6);
        assertThat(types.get(0).getValue()).isEqualTo(0x0012);
        assertThat(types.get(1).getValue()).isEqualTo(0x0011);
        assertThat(types.get(2).getValue()).isEqualTo(0x0010);
        assertThat(types.get(3).getValue()).isEqualTo(0x0017);
        assertThat(types.get(4).getValue()).isEqualTo(0x0019);
        assertThat(types.get(5).getValue()).isEqualTo(0x001A);

        // Test encode PaPkAsReq
        byte[] encodedPaPkAsReq = paPkAsReq.encode();
        PaPkAsReq decodedPaPkAsReq = new PaPkAsReq();
        decodedPaPkAsReq.decode(encodedPaPkAsReq);
    }
}
