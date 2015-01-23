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
package org.apache.kerby.kerberos.kerb.codec.test;

import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;

/**
 * Test AsReq message using a real 'correct' network packet captured from MS-AD to detective programming errors
 * and compatibility issues particularly regarding Kerberos crypto.
 */
public class TestAsReqCodec {

    @Test
    public void test() throws IOException, ParseException {
        byte[] bytes = CodecTestUtil.readBinaryFile("/asreq.token");
        ByteBuffer asReqToken = ByteBuffer.wrap(bytes);

        AsReq asReq = new AsReq();
        asReq.decode(asReqToken);

        Assert.assertEquals(5, asReq.getPvno());
        Assert.assertEquals(KrbMessageType.AS_REQ, asReq.getMsgType());

        PaData paData = asReq.getPaData();
        PaDataEntry encTimestampEntry = paData.findEntry(PaDataType.ENC_TIMESTAMP);
        Assert.assertEquals(PaDataType.ENC_TIMESTAMP, encTimestampEntry.getPaDataType());
        Assert.assertArrayEquals(Arrays.copyOfRange(bytes, 33, 96), encTimestampEntry.getPaDataValue());
        PaDataEntry pacRequestEntry = paData.findEntry(PaDataType.PAC_REQUEST);
        Assert.assertEquals(PaDataType.PAC_REQUEST, pacRequestEntry.getPaDataType());
        Assert.assertArrayEquals(Arrays.copyOfRange(bytes, 108, 115), pacRequestEntry.getPaDataValue());

        KdcReqBody body = asReq.getReqBody();
        Assert.assertEquals(0, body.getKdcOptions().getPadding());
        Assert.assertArrayEquals(Arrays.copyOfRange(bytes, 126, 130), body.getKdcOptions().getValue());
        PrincipalName cName = body.getCname();
        Assert.assertEquals(NameType.NT_PRINCIPAL, cName.getNameType());
        Assert.assertEquals("des", cName.getName());
        Assert.assertEquals("DENYDC", body.getRealm());
        PrincipalName sName = body.getSname();
        Assert.assertEquals(NameType.NT_SRV_INST, sName.getNameType());
        Assert.assertEquals(2, sName.getNameStrings().size());
        Assert.assertEquals("krbtgt", sName.getNameStrings().get(0));
        Assert.assertEquals("DENYDC", sName.getNameStrings().get(1));

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        Assert.assertEquals(date.getTime(), body.getTill().getTime());
        Assert.assertEquals(date.getTime(), body.getRtime().getTime());

        Assert.assertEquals(197451134, body.getNonce());

        List<EncryptionType> types = body.getEtypes();
        Assert.assertEquals(0x0017, types.get(0).getValue());
        //Assert.assertEquals(0xff7b, types.get(1).getValue());//FIXME
        //Assert.assertEquals(0x0080, types.get(2).getValue());//FIXME
        Assert.assertEquals(0x0003, types.get(3).getValue());
        Assert.assertEquals(0x0001, types.get(4).getValue());
        Assert.assertEquals(0x0018, types.get(5).getValue());
        //Assert.assertEquals(0xff79, types.get(6).getValue());//FIXME

        List<HostAddress> hostAddress = body.getAddresses().getElements();
        Assert.assertEquals(1, hostAddress.size());
        Assert.assertEquals(HostAddrType.ADDRTYPE_NETBIOS, hostAddress.get(0).getAddrType());
    }
}
