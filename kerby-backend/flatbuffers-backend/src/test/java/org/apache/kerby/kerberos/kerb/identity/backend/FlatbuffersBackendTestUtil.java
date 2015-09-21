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
package org.apache.kerby.kerberos.kerb.identity.backend;

import MyGame.Example.*;
import com.google.flatbuffers.FlatBufferBuilder;
import org.apache.kerby.kerberos.kdc.identitybackend.FbsEncryptionKey;
import org.apache.kerby.kerberos.kdc.identitybackend.FbsKerby;
import org.apache.kerby.kerberos.kdc.identitybackend.FbsKrbIdentity;
import org.apache.kerby.kerberos.kdc.identitybackend.FbsPrincipalName;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Flatbuffers test utilities
 */
public class FlatbuffersBackendTestUtil {

    public static void main(String[] args) throws KrbException {
        List<KrbIdentity> idendenties = BackendTestUtil.createManyIdentities(2);

        FlatBufferBuilder fbb = new FlatBufferBuilder(1024);

        int name = fbb.createString("KerbyBackend");

        KrbIdentity krbId = idendenties.get(0);
        int princNameOff = fbb.createString(krbId.getPrincipalName());
        int nameType = krbId.getPrincipal().getNameType().getValue();
        int princOff = FbsPrincipalName.createFbsPrincipalName(fbb, nameType, princNameOff);
        EncryptionKey encKey = krbId.getKeys().entrySet().iterator().next().getValue();
        int keyValueOff = FbsEncryptionKey.createKeyValueVector(fbb, encKey.getKeyData());
        int encKeyOff = FbsEncryptionKey.createFbsEncryptionKey(fbb,
                encKey.getKeyType().getValue(), keyValueOff);
        int keysOff = FbsKrbIdentity.createKeysVector(fbb, new int[]{encKeyOff});
        int identityOff = FbsKrbIdentity.createFbsKrbIdentity(fbb, princOff, 1, 1, false, keysOff);
        int idsOff = FbsKerby.createIdentitiesVector(fbb, new int[]{identityOff});

        FbsKerby.startFbsKerby(fbb);
        FbsKerby.addName(fbb, name);
        FbsKerby.addIdentities(fbb, idsOff);
        int kerbyOff = FbsKerby.endFbsKerby(fbb);
        FbsKerby.finishFbsKerbyBuffer(fbb, kerbyOff);

        ByteBuffer dataBuffer = fbb.dataBuffer().duplicate();

        FbsKerby fbsKerby2 = FbsKerby.getRootAsFbsKerby(dataBuffer);
        String kerbyName = fbsKerby2.name();
        FbsKrbIdentity krbId2 = fbsKerby2.identities(0);
        String princName2 = krbId2.principal().nameString();
        return;
    }
}
