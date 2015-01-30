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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.codec.KrbCodec;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSumType;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class CodecTest {

    @Test
    public void testCodec() throws KrbException {
        CheckSum mcs = new CheckSum();
        mcs.setCksumtype(CheckSumType.CRC32);
        mcs.setChecksum(new byte[] {0x10});
        byte[] bytes = KrbCodec.encode(mcs);
        assertThat(bytes).isNotNull();

        CheckSum restored = KrbCodec.decode(bytes, CheckSum.class);
        assertThat(restored).isNotNull();
        assertThat(restored.getCksumtype()).isEqualTo(mcs.getCksumtype());
        assertThat(mcs.getChecksum()).isEqualTo(restored.getChecksum());
    }
}
