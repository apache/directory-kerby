/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.kerby;

import org.apache.directory.mavibot.btree.serializer.BufferHandler;
import org.apache.directory.mavibot.btree.serializer.ElementSerializer;
import org.apache.directory.mavibot.btree.serializer.IntSerializer;
import org.apache.directory.mavibot.btree.serializer.LongSerializer;
import org.apache.directory.mavibot.btree.serializer.StringSerializer;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Comparator;
import java.util.Map;

/**
 * Serializer for KrbIdentity.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class KrbIdentitySerializer implements ElementSerializer<KrbIdentity> {
    /** the static instance of the serializer */
    public static final KrbIdentitySerializer INSTANCE = new KrbIdentitySerializer();

    /** comparator for KrbIdentity */
    private KrbIdentityComparator comparator = KrbIdentityComparator.INSTANCE;

    @Override
    public byte[] serialize(KrbIdentity entry) {
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            // the principalName
            out.write(StringSerializer.INSTANCE.serialize(entry.getPrincipalName()));
            
            // key version
            out.write(IntSerializer.serialize(entry.getKeyVersion()));
            
            out.write(IntSerializer.serialize(entry.getKdcFlags()));
            
            // mask for disabled and lock flags
            byte mask = 0;
            
            if (entry.isDisabled()) {
                mask |= 1 << 1;
            }

            if (entry.isLocked()) {
                mask |= 1 << 2;
            }
            
            out.write(mask);
            
            // creation time
            out.write(LongSerializer.serialize(entry.getCreatedTime().getTime()));
            
            // expiration time
            out.write(LongSerializer.serialize(entry.getExpireTime().getTime()));
            
            Map<EncryptionType, EncryptionKey> keys = entry.getKeys();
            // num keys
            out.write(IntSerializer.serialize(keys.size()));
            
            for (EncryptionKey ek : keys.values()) {
                int type = ek.getKeyType().getValue();
                out.write(IntSerializer.serialize(type));
                byte[] data = ek.getKeyData();
                out.write(IntSerializer.serialize(data.length));
                out.write(data);
            }
            
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize the identity " + entry);
        }
    }

    @Override
    public KrbIdentity deserialize(BufferHandler bufferHandler)
            throws IOException {
        return fromBytes(bufferHandler.getBuffer());
    }

    @Override
    public KrbIdentity deserialize(ByteBuffer buffer) throws IOException {
        KrbIdentity id = null;
        
        String principal = StringSerializer.INSTANCE.deserialize(buffer);
        
        id = new KrbIdentity(principal);
        
        int kvno = IntSerializer.INSTANCE.deserialize(buffer);
        id.setKeyVersion(kvno);
        
        int flags = IntSerializer.INSTANCE.deserialize(buffer);
        id.setKdcFlags(flags);
        
        byte mask = buffer.get();
        
        if ((mask & 2) != 0) {
            id.setDisabled(true);
        }
        
        if ((mask & 4) != 0) {
            id.setLocked(true);
        }
        
        long creationTime = LongSerializer.INSTANCE.deserialize(buffer);
        id.setCreatedTime(new KerberosTime(creationTime));
        
        long exprTime = LongSerializer.INSTANCE.deserialize(buffer);
        id.setExpireTime(new KerberosTime(exprTime));

        int numKeys = IntSerializer.INSTANCE.deserialize(buffer);
        
        for (int i = 0; i < numKeys; i++) {
            int keyType = IntSerializer.INSTANCE.deserialize(buffer);
            int keyLen = IntSerializer.INSTANCE.deserialize(buffer);
            
            byte[] keyData = new byte[keyLen];
            buffer.get(keyData);
            
            EncryptionKey ek = new EncryptionKey(keyType, keyData);
            
            id.addKey(ek);
        }
        
        return id;
    }

    @Override
    public KrbIdentity fromBytes(byte[] buffer) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(buffer);
        return deserialize(buf);
    }

    @Override
    public KrbIdentity fromBytes(byte[] buffer, int pos) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(buffer, pos, buffer.length - pos);
        return deserialize(buf);
    }

    @Override
    public int compare(KrbIdentity type1, KrbIdentity type2) {
        return comparator.compare(type1, type2);
    }

    @Override
    public Comparator<KrbIdentity> getComparator() {
        return comparator;
    }

    @Override
    public Class<?> getType() {
        return KrbIdentity.class;
    }
}
