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

import java.nio.ByteBuffer;

/**
 * Deal with messages sent and received between Kadmin and Kadmin Server.
 *       (MSB)                   (LSB)
 *      +-------+-------+-------+-------+
 *      |msg_type |para_num |prin_name |...(koptions, password) |
 *      +-------+-------+-------+-------+
 */
public class AdminMessage {
    private AdminMessageType adminMessageType;
    private ByteBuffer messageBuffer;

    public AdminMessage(AdminMessageType adminMessageType) {
        this.adminMessageType = adminMessageType;
    }

    public AdminMessageType getAdminMessageType() {
        return adminMessageType;
    }

    public void setMessageBuffer(ByteBuffer messageBuffer) {
        this.messageBuffer = messageBuffer;
    }

    public ByteBuffer getMessageBuffer() {
        return messageBuffer;
    }

    public int encodingLength() {
        return messageBuffer.limit(); // no + 4 is the length of whole message
    }


}
