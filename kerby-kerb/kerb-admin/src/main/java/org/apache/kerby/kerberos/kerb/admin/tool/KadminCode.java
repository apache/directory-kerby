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
package org.apache.kerby.kerberos.kerb.admin.tool;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Used to decode messages between admin and admin server.
 */
public class KadminCode {
    public static ByteBuffer encodeMessage(AdminMessage adminMessage) {
        int length = adminMessage.encodingLength();
        ByteBuffer buffer = ByteBuffer.allocate(length + 4); // 4 is the head to go through network
        buffer.putInt(length); // head in network
        //buffer.putInt(adminMessage.getAdminMessageType().getValue());
        // type has been encoded in the admin message
        buffer.put(adminMessage.getMessageBuffer());
        buffer.flip();
        return buffer;
    }


    public static AdminMessage decodeMessage(ByteBuffer buffer) throws IOException {
        //go through network, the total length has been removed.
        int type = buffer.getInt();
        System.out.println("type: " + type);
        AdminMessageType adminMessageType = AdminMessageType.findType(type);
        AdminMessage adminMessage = null;
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        if (adminMessageType == AdminMessageType.ADD_PRINCIPAL_REQ) {
            adminMessage = new AddPrincipalReq();
            System.out.println("check if decoding right: " + new String(ByteBuffer.wrap(bytes).array()));
        } else if (adminMessageType == AdminMessageType.ADD_PRINCIPAL_REP) {
            adminMessage = new AddPrincipalRep();
            System.out.println("check if decoding right2: " + new String(ByteBuffer.wrap(bytes).array()));
        } else {
            throw new IOException("Unknown Admin Message Type: " + type);
        }

        return adminMessage;
    }
}
