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
package org.apache.kerberos.kerb.codec.test;

import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.HostAddrType;
import org.apache.kerberos.kerb.spec.common.KrbMessageType;
import org.apache.kerberos.kerb.spec.common.NameType;
import org.apache.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
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
        ByteBuffer asreqToken = ByteBuffer.wrap(bytes);

        AsReq asReq = new AsReq();
        asReq.decode(asreqToken);

        Assert.assertEquals(asReq.getPvno(), 5);
        Assert.assertEquals(asReq.getMsgType(), KrbMessageType.AS_REQ);

        Assert.assertEquals(asReq.getPaData().findEntry(PaDataType.ENC_TIMESTAMP).getPaDataType(), PaDataType.ENC_TIMESTAMP);
        byte[] paDataEncTimestampValue = Arrays.copyOfRange(bytes, 33, 96);
        byte[] paDataEncTimestampRealValue = asReq.getPaData().findEntry(PaDataType.ENC_TIMESTAMP).getPaDataValue();
        Assert.assertTrue(Arrays.equals(paDataEncTimestampValue, paDataEncTimestampRealValue));
        Assert.assertEquals(asReq.getPaData().findEntry(PaDataType.PAC_REQUEST).getPaDataType(), PaDataType.PAC_REQUEST);
        byte[] paPacRequestValue = Arrays.copyOfRange(bytes, 108, 115);
        byte[] paPacRequestRealValue = asReq.getPaData().findEntry(PaDataType.PAC_REQUEST).getPaDataValue();
        Assert.assertTrue(Arrays.equals(paPacRequestValue, paPacRequestRealValue));

        Assert.assertEquals(asReq.getReqBody().getKdcOptions().getPadding(), 0);
        Assert.assertTrue(Arrays.equals(asReq.getReqBody().getKdcOptions().getValue(), Arrays.copyOfRange(bytes, 126, 130)));

        Assert.assertEquals(asReq.getReqBody().getCname().getNameType(), NameType.NT_PRINCIPAL);
        Assert.assertEquals(asReq.getReqBody().getCname().getName(), "des");
        Assert.assertEquals(asReq.getReqBody().getRealm(), "DENYDC");
        Assert.assertEquals(asReq.getReqBody().getSname().getNameType(), NameType.NT_SRV_INST);
        Assert.assertEquals(asReq.getReqBody().getSname().getNameStrings().get(0), "krbtgt");
        Assert.assertEquals(asReq.getReqBody().getSname().getNameStrings().get(1), "DENYDC");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        Date date = sdf.parse("20370913024805");
        Assert.assertEquals(asReq.getReqBody().getTill().getTime(), date.getTime());
        Assert.assertEquals(asReq.getReqBody().getRtime().getTime(), date.getTime());

        Assert.assertEquals(asReq.getReqBody().getNonce(), 197451134);

        List<EncryptionType> types = asReq.getReqBody().getEtypes();
        Assert.assertEquals(types.get(0).getValue(), 0x0017);
        //Assert.assertEquals(types.get(1).getValue(), 0xff7b);//FIXME
        //Assert.assertEquals(types.get(2).getValue(), 0x0080);//FIXME
        Assert.assertEquals(types.get(3).getValue(), 0x0003);
        Assert.assertEquals(types.get(4).getValue(), 0x0001);
        Assert.assertEquals(types.get(5).getValue(), 0x0018);
        //Assert.assertEquals(types.get(6).getValue(), 0xff79);//FIXME

        Assert.assertEquals(asReq.getReqBody().getAddresses().getElements().size(), 1);
        Assert.assertEquals(asReq.getReqBody().getAddresses().getElements().get(0).getAddrType(), HostAddrType.ADDRTYPE_NETBIOS);
        //FIXME net bios name
    }
}
