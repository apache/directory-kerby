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

import org.apache.kerby.asn1.Asn1Dump;
import org.apache.kerby.asn1.Asn1InputBuffer;
import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.type.Asn1Item;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.spec.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.spec.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.junit.Test;
import sun.security.krb5.internal.KDCReq;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class CodecTest {

    @Test
    public void testCodec() throws KrbException, IOException {
        CheckSum mcs = new CheckSum();
        mcs.setCksumtype(CheckSumType.CRC32);
        mcs.setChecksum(new byte[] {0x10});
        byte[] bytes = KrbCodec.encode(mcs);
        assertThat(bytes).isNotNull();

        CheckSum restored = KrbCodec.decode(bytes, CheckSum.class);
        assertThat(restored).isNotNull();
        assertThat(restored.getCksumtype()).isEqualTo(mcs.getCksumtype());
        assertThat(mcs.getChecksum()).isEqualTo(restored.getChecksum());
        assertThat(restored.tagNo()).isEqualTo(mcs.tagNo());
        assertThat(restored.tagFlags()).isEqualTo(mcs.tagFlags());
    }

    @Test
    public void testDecode() throws IOException {
        AsReq expected = new AsReq();

        KdcReqBody body = new KdcReqBody();

        expected.setReqBody(body);

        Asn1InputBuffer ib = new Asn1InputBuffer(expected.encode());
        Asn1Type fd1 = ib.read();
        Asn1Type fd2 = ib.read();
        Asn1Type fd3 = ib.read();
        Asn1Type fd4 = ib.read();
        Asn1Type fd5 = ib.read();
        Asn1Type fd6 = ib.read();
        Asn1Type fd7 = ib.read();
        Asn1Type fd8 = ib.read();
        Asn1Type fd9 = ib.read();

    }
}
