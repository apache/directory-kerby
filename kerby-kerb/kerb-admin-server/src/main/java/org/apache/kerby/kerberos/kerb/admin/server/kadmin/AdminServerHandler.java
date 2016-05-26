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
        AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();

        /**Create LocalKadmin here*/
        LocalKadmin localKadmin = new LocalKadminImpl(adminServerContext.getAdminServerSetting());
        ByteBuffer responseMessage = null;

        switch (type) {
            case ADD_PRINCIPAL_REQ:
                System.out.println("message type: add principal req");
                responseMessage = handleAddPrincipalReq(localKadmin, fieldInfos);
                break;
            case DELETE_PRINCIPAL_REQ:
                System.out.println("message type: delete principal req");
                responseMessage = handleDeletePrincipalReq(localKadmin, fieldInfos);
                break;
            case RENAME_PRINCIPAL_REQ:
                System.out.println("message type: rename principal req");
                responseMessage = handleRenamePrincipalReq(localKadmin, fieldInfos);
                break;
            default:
                throw new KrbException("AdminMessageType error, can not handle it.");
        }
        return responseMessage;

    }

    private ByteBuffer handleAddPrincipalReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        String principal = (String) fieldInfos[2].getValue();
        int paramNum = (int) fieldInfos[1].getValue();

        if (paramNum == 1) {
            /** Add principal with only principal name*/
            LOG.info("handle nokey principal " + principal);
            String[] temp = principal.split("@");
            try {
                localKadmin.addPrincipal(temp[0]);
            } catch (KrbException e) {
                String error = "principal already exist!";
                LOG.error(error);
                System.err.println(error);
                XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
                xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.ADD_PRINCIPAL_REP);
                xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
                xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, error);
                AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
                AdminMessage errorMessage = new AddPrincipalRep();
                errorMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));
                ByteBuffer response = KadminCode.encodeMessage(errorMessage);
                return response;
            }
        } else if (paramNum == 2 && fieldInfos[3].getDataType() == XdrDataType.STRING) {
            /** Add principal with password*/
            LOG.info("handle principal with password " + principal);
            String[] temp = principal.split("@");
            String password = (String) fieldInfos[3].getValue();
            try {
                localKadmin.addPrincipal(temp[0], password);
            } catch (KrbException e) {
                String error = "principal already exist.\n"
                    + "Choose update password instead of add principal";
                LOG.error(error);
                XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
                xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.ADD_PRINCIPAL_REP);
                xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
                xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, error);
                AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
                AdminMessage errorMessage = new AddPrincipalRep();
                errorMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));
                ByteBuffer response = KadminCode.encodeMessage(errorMessage);
                return response;
            }
        }

        String message = "add principal of " + principal;
        LOG.info(message);
        //content to reply remain to construct
        AdminMessage addPrincipalRep = new AddPrincipalRep();
        /** encode admin message:
         *  encode type
         *  encode message
         */
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.ADD_PRINCIPAL_REP);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, message);
        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        addPrincipalRep.setMessageBuffer(ByteBuffer.wrap(value.encode()));
        ByteBuffer responseMessage = KadminCode.encodeMessage(addPrincipalRep);
        return responseMessage;
    }

    private ByteBuffer handleDeletePrincipalReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        /** message structure: msg_type, para_num(always equals 1), principal_name*/
        String principal = (String) fieldInfos[2].getValue();
        String[] temp = principal.split("@");
        try {
            localKadmin.deletePrincipal(temp[0]);
        } catch (KrbException e) {
            String error = "no such principal exist!";
            LOG.error(error);
            XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.DELETE_PRINCIPAL_REP);
            xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
            xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, error);
            AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
            AdminMessage errorMessage = new DeletePrincipalRep();
            errorMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));
            ByteBuffer response = KadminCode.encodeMessage(errorMessage);
            return response;
        }

        String message = "delete principal of " + principal;
        LOG.info(message);
        AdminMessage deletePrincipalRep = new DeletePrincipalRep();
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.DELETE_PRINCIPAL_REP);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, message);
        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        deletePrincipalRep.setMessageBuffer(ByteBuffer.wrap(value.encode()));
        ByteBuffer responseMessage = KadminCode.encodeMessage(deletePrincipalRep);
        return responseMessage;
    }

    private ByteBuffer handleRenamePrincipalReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        /** message structure: msg_type, para_num(always equals 2), old name, new name*/

        String[] oldPrincipalName = ((String) fieldInfos[2].getValue()).split("@");
        String[] newPrincipalName = ((String) fieldInfos[3].getValue()).split("@");

        try {
            localKadmin.renamePrincipal(oldPrincipalName[0], newPrincipalName[0]);
        } catch (KrbException e) {
            String error = "the old principal name does not exist, or the new principal name"
                + " already exists, rename failed.";
            System.err.println(error);
            XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.RENAME_PRINCIPAL_REP);
            xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
            xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, error);
            AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
            AdminMessage errorMessage = new RenamePrincipalRep();
            errorMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));
            ByteBuffer response = KadminCode.encodeMessage(errorMessage);
            return response;
        }

        String message = "rename " + oldPrincipalName[0] + " to " + newPrincipalName[0];
        AdminMessage renamePrincipalRep = new RenamePrincipalRep();
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.RENAME_PRINCIPAL_REP);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, message);
        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        renamePrincipalRep.setMessageBuffer(ByteBuffer.wrap(value.encode()));
        ByteBuffer responseMessage = KadminCode.encodeMessage(renamePrincipalRep);
        return responseMessage;
    }
}
