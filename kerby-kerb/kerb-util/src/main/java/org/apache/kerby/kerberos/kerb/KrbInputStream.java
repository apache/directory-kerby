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
package org.apache.kerby.kerberos.kerb;

import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class KrbInputStream extends DataInputStream
{
    public KrbInputStream(InputStream in) {
        super(in);
    }

    public KerberosTime readTime() throws IOException {
        long value = readInt();
        KerberosTime time = new KerberosTime(value * 1000);
        return time;
    }

    public abstract PrincipalName readPrincipal(int version) throws IOException;

    public EncryptionKey readKey(int version) throws IOException {
        int eType = readShort();
        EncryptionType encryptionType = EncryptionType.fromValue(eType);

        byte[] keyData = readCountedOctets();
        EncryptionKey key = new EncryptionKey(encryptionType, keyData);

        return key;
    }

    public String readCountedString() throws IOException {
        byte[] countedOctets = readCountedOctets();
        // ASCII
        return new String(countedOctets);
    }

    public byte[] readCountedOctets() throws IOException {
        int len = readOctetsCount();
        if (len == 0) {
            return null;
        }

        byte[] data = new byte[len];
        read(data);

        return data;
    }

    public abstract int readOctetsCount() throws IOException;
}
