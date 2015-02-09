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
package org.apache.kerby.kerberos.kerb.codec.kerberos;

import org.apache.kerby.asn1.Asn1InputBuffer;
import org.apache.kerby.asn1.type.Asn1Item;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;

import java.io.IOException;

public class KerberosToken {

    private KerberosApRequest apRequest;

    public KerberosToken(byte[] token) throws Exception {
        this(token, null);
    }

    public KerberosToken(byte[] token, EncryptionKey key) throws Exception {

        if (token.length <= 0) {
            throw new IOException("kerberos.token.empty");
        }

        Asn1InputBuffer buffer = new Asn1InputBuffer(token);

        Asn1Item value = (Asn1Item) buffer.read();
        if(! value.isAppSpecific() && ! value.isConstructed()) {
            throw new IOException("kerberos.token.malformed");
        }

        buffer = new Asn1InputBuffer(value.getBodyContent());
        buffer.skipNext();

        buffer.skipBytes(2);

        apRequest = new KerberosApRequest(buffer.readAllLeftBytes(), key);
    }

    public KerberosApRequest getApRequest() {
        return apRequest;
    }
}
