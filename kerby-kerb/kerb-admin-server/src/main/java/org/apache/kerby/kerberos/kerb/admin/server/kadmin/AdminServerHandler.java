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
package org.apache.kerby.kerberos.kerb.admin.server.kadmin;

import org.apache.kerby.kerberos.kerb.admin.tool.AddPrincipalRep;
import org.apache.kerby.kerberos.kerb.admin.tool.KadminCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * KDC handler to process client requests. Currently only one realm is supported.
 */
public class AdminServerHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AdminServerHandler.class);
    private final AdminServerContext adminServerContext;

    /**
     * Constructor with kdc context.
     *
     * @param adminServerContext admin admin context
     */
    public AdminServerHandler(AdminServerContext adminServerContext) {
        this.adminServerContext = adminServerContext;
    }

    /**
     * Process the client request message.
     *
     * @throws KrbException e
     * @param receivedMessage The client request message
     * @param remoteAddress Address from remote side
     * @return The response message
     */
    public ByteBuffer handleMessage(ByteBuffer receivedMessage,
                                    InetAddress remoteAddress) throws KrbException, IOException {
        AdminMessage requestMessage = KadminCode.decodeMessage(receivedMessage);
        System.out.println("receive message type: " + requestMessage.getAdminMessageType());
        String receiveMsg = new String (requestMessage.getMessageBuffer().array());
        System.out.println("server handleMessage: " + receiveMsg);
        String[] principal = receiveMsg.split("@");
        System.out.println("clientName: " + principal[0]);
        System.out.println("realm: " + principal[1]);

        /**Add principal to backend here*/
        //LocalKadmin localKadmin = new LocalKadminImpl(adminServerContext.getAdminServerSetting().getAdminServerConfig(),
         //       adminServerContext.getAdminServerSetting().getBackendConfig());
        //localKadmin.addPrincipal(principal[0]);

        String message = "add principal of " + principal[0];
        AdminMessage replyMeesage = new AddPrincipalRep(ByteBuffer.wrap(message.getBytes()));
        ByteBuffer responseMessage = KadminCode.encodeMessage(replyMeesage);

        return responseMessage;

    }
}
