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
package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.kerberos.kerb.codec.KrbCodec;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessage;
import org.apache.kerby.transport.Transport;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbUtil {

    public static void sendMessage(KrbMessage message, Transport transport) {
        int bodyLen = message.encodingLength();
        ByteBuffer buffer = ByteBuffer.allocate(bodyLen + 4);
        buffer.putInt(bodyLen);
        message.encode(buffer);
        buffer.flip();
        transport.sendMessage(buffer);
    }

    public static KrbMessage decodeMessage(ByteBuffer message) throws IOException {
        int bodyLen = message.getInt();
        assert (message.remaining() >= bodyLen);

        KrbMessage krbMessage = KrbCodec.decodeMessage(message);

        return krbMessage;
    }

}
