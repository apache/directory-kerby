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
package org.apache.kerby.kerberos.kdc.identitybackend.typeAdapter;

import com.google.gson.*;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.util.HexUtil;

import java.lang.reflect.Type;

public class EncryptionKeyAdapter implements JsonSerializer<EncryptionKey>,
        JsonDeserializer<EncryptionKey> {

    @Override
    public EncryptionKey deserialize(JsonElement jsonElement, Type type,
                                     JsonDeserializationContext jsonDeserializationContext)
            throws JsonParseException {
        JsonObject jsonObject = (JsonObject) jsonElement;
        EncryptionKey encryptionKey = new EncryptionKey();
        encryptionKey.setKvno(jsonObject.get("kvno").getAsInt());
        String encryptionTypeString = jsonObject.get("keyType").getAsString();
        EncryptionType encryptionType = EncryptionType.fromName(encryptionTypeString);
        encryptionKey.setKeyType(encryptionType);
        encryptionKey.setKeyData(HexUtil.hex2bytes(jsonObject.get("keyData").getAsString()));
        return encryptionKey;
    }

    @Override
    public JsonElement serialize(EncryptionKey encryptionKey,
                                 Type type, JsonSerializationContext jsonSerializationContext) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("kvno", encryptionKey.getKvno());
        jsonObject.addProperty("keyType", encryptionKey.getKeyType().getName());
        jsonObject.addProperty("keyData", HexUtil.bytesToHex(encryptionKey.getKeyData()));
        return jsonObject;
    }
}
