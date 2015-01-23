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

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

import java.io.IOException;
import java.io.InputStream;

public class KerberosCredentials {

    private static Keytab keytab;

    private static void init() throws IOException {
        InputStream kis = KerberosCredentials.class.getResourceAsStream("/server.keytab");
        keytab = new Keytab();
        keytab.load(kis);
    }

    public static EncryptionKey getServerKey(EncryptionType etype) throws IOException {
        if (keytab == null) {
            init();
        }

        for (PrincipalName principal : keytab.getPrincipals()) {
            for (KeytabEntry entry : keytab.getKeytabEntries(principal)) {
                if (entry.getKey().getKeyType() == etype) {
                    return entry.getKey();
                }
            }
        }
        return null;
    }
}
