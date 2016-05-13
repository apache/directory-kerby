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

import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.tool.*;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.XdrString;
import org.apache.kerby.xdr.type.XdrStructType;
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
        LOG.info("Admin realm: " + this.adminServerContext.getAdminRealm());
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
        XdrStructType decoded = new AdminMessageCode();
        decoded.decode(receivedMessage);
        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        System.out.println("receive message type: " + fieldInfos[0].getValue());
        System.out.println("receive message paramNum: " + fieldInfos[1].getValue());
        int paramNum = (int) fieldInfos[1].getValue();
        //AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();
        /** now only support add principal request*/

        /**Create LocalKadmin here*/
        LocalKadmin localKadmin = new LocalKadminImpl(adminServerContext.getAdminServerSetting());

        String principal = (String) fieldInfos[2].getValue();
        if (paramNum == 1) {
            /** Add principal with only principal name*/
            System.out.println("handle nokey principal " + principal);
            String[] temp = principal.split("@");
            try {
                localKadmin.addPrincipal(temp[0]);
            } catch (KrbException e) {
                String error = "principal already exist!";
                System.out.println(error);
                AdminMessage errorMessage = new AddPrincipalRep();
                XdrString xdrMessage = new XdrString(error);
                errorMessage.setMessageBuffer(ByteBuffer.wrap(xdrMessage.encode()));
                ByteBuffer response = KadminCode.encodeMessage(errorMessage);
                return response;
            }
        } else if (paramNum == 2 && fieldInfos[3].getDataType() == XdrDataType.STRING) {
            /** Add principal with password*/
            System.out.println("handle principal with password " + principal);
            String[] temp = principal.split("@");
            String password = (String) fieldInfos[3].getValue();
            try {
                localKadmin.addPrincipal(temp[0], password);
            } catch (KrbException e) {
                String error = "principal already exist.\n"
                    + "Choose update password instead of add principal";
                System.out.println(error);
                AdminMessage errorMessage = new AddPrincipalRep();
                XdrString xdrMessage = new XdrString(error);
                errorMessage.setMessageBuffer(ByteBuffer.wrap(xdrMessage.encode()));
                ByteBuffer response = KadminCode.encodeMessage(errorMessage);
                return response;
            }
        }

        String message = "add principal of " + principal;
        //content to reply remain to construct
        AdminMessage addPrincipalRep = new AddPrincipalRep();
        /** encode admin message:
         *  encode type
         *  encode paranum
         *  encode principal name
         *  (encode koptions)
         *  (encode passsword)
         */
        XdrString value = new XdrString(message);
        addPrincipalRep.setMessageBuffer(ByteBuffer.wrap(value.encode()));
        System.out.println("value length:" + addPrincipalRep.getMessageBuffer().capacity());
        ByteBuffer responseMessage = KadminCode.encodeMessage(addPrincipalRep);

        return responseMessage;

    }
}
