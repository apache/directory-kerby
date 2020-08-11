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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.message.AddPrincipalRep;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessage;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.message.DeletePrincipalRep;
import org.apache.kerby.kerberos.kerb.admin.message.GetprincsRep;
import org.apache.kerby.kerberos.kerb.admin.message.KadminCode;
import org.apache.kerby.kerberos.kerb.admin.message.RenamePrincipalRep;
import org.apache.kerby.kerberos.kerb.admin.message.KeytabMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.ExportKeytabRep;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.XdrStructType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

/**
 * admin server handler to process client acmin requests.
 */
public class AdminServerHandler {
    private static final Logger LOG = LoggerFactory.getLogger(AdminServerHandler.class);
    private final AdminServerContext adminServerContext;

    /**
     * Constructor with admin server context.
     *
     * @param adminServerContext admin admin server context
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
            case GET_PRINCS_REQ:
                System.out.println("message type: get principals req");
                responseMessage = handleGetprincsReq(localKadmin, fieldInfos);
                break;
            case EXPORT_KEYTAB_REQ:
                System.out.println("message type: export keytab req");
                responseMessage = handleExportKeytabReq(localKadmin, fieldInfos);
                break;
            default:
                throw new KrbException("AdminMessageType error, can not handle the type: " + type);
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
                String error = "The principal already exists!";
                LOG.error(error);
                System.err.println(error);
                ByteBuffer response = infoPackageTool(error, "addPrincipal");
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
                String error = " The principal already exists.\n"
                        + "Choose update password instead of add principal";
                LOG.error(error);
                ByteBuffer response = infoPackageTool(error, "addPrincipal");
                return response;
            }
        }
        String message = "Add principal:" + principal;
        System.out.println(message);
        LOG.info(message);
        ByteBuffer responseMessage = infoPackageTool(message, "addPrincipal");
        return responseMessage;
    }

    private ByteBuffer handleDeletePrincipalReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        /** message structure: msg_type, para_num(always equals 1), principal_name*/
        String principal = (String) fieldInfos[2].getValue();
        String[] temp = principal.split("@");
        try {
            localKadmin.deletePrincipal(temp[0]);
        } catch (KrbException e) {
            String error = "No such principal exists!";
            LOG.error(error);
            ByteBuffer response = infoPackageTool(error, "deletePrincipal");
            return response;
        }
        String message = "Delete principal of " + principal;
        System.out.println(message);
        LOG.info(message);
        ByteBuffer responseMessage = infoPackageTool(message, "deletePrincipal");
        return responseMessage;
    }

    private ByteBuffer handleRenamePrincipalReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        /** message structure: msg_type, para_num(always equals 2), old name, new name*/
        String[] oldPrincipalName = ((String) fieldInfos[2].getValue()).split("@");
        String[] newPrincipalName = ((String) fieldInfos[3].getValue()).split("@");
        try {
            localKadmin.renamePrincipal(oldPrincipalName[0], newPrincipalName[0]);
        } catch (KrbException e) {
            String error = "The old principal name does not exist, or the new principal name"
                    + " already exists, rename failed.";
            System.err.println(error);
            ByteBuffer response = infoPackageTool(error, "renamePrincipal");
            return response;
        }

        String message = "Rename " + oldPrincipalName[0] + " to " + newPrincipalName[0];
        System.out.println(message);
        LOG.info(message);
        ByteBuffer responseMessage = infoPackageTool(message, "renamePrincipal");
        return responseMessage;
    }

    private ByteBuffer handleGetprincsReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        String globString = ((String) fieldInfos[2].getValue());
        List<String> princsList = null;

        try {
            if (globString == null || globString.isEmpty()) {
                princsList = localKadmin.getPrincipals();
            } else {
                princsList = localKadmin.getPrincipals(globString);
            }
            ByteBuffer responseMessage = infoPackageTool(listToString(princsList), "getPrincs");
            return responseMessage;
        } catch (KrbException e) {
            String error = "The principal does not exist.";
            LOG.error(error + e);
            ByteBuffer responseError = infoPackageTool(error, "getPrincs");
            return responseError;
        }
    }
    
    private ByteBuffer handleExportKeytabReq(LocalKadmin localKadmin, XdrFieldInfo[] fieldInfos) throws IOException {
        String principals = ((String) fieldInfos[2].getValue());
        
        if (principals != null) {
            List<String> princList = stringToList(principals);
            if (princList.size() != 0) {
                LOG.info("Exporting keytab file for " + principals + "...");
                File tempDir = Files.createTempDirectory("ktadd").toFile();
                File keytabFile = new File(tempDir, princList.get(0)
                        .replace('/', '-')
                        .replace('*', '-')
                        .replace('?', '-')
                        + ".keytab");
                try {
                    localKadmin.exportKeytab(keytabFile, princList);
                    LOG.info("Create keytab file for principals successfully.");
                    ByteBuffer responseMessage = infoPackageTool(keytabFile, "exportKeytab");
                    return responseMessage;
                } catch (KrbException e) {
                    String error = "Failed to export keytab. " + e.toString();
                    ByteBuffer responseError = infoPackageTool(error, "exportKeytab");
                    return responseError;
                }
            } else {
                String error = "No matched principals.";
                ByteBuffer responseError = infoPackageTool(error, "exportKeytab");
                return responseError;
            }
        }
        String error = "Failed to export keytab.";
        ByteBuffer responseError = infoPackageTool(error, "exportKeytab");
        return responseError;
    }

    private ByteBuffer infoPackageTool(String message, String dealType) throws IOException {
        AdminMessage adminMessage = null;
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];

        if ("getPrincs".equals(dealType)) {
            adminMessage = new GetprincsRep();
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.GET_PRINCS_REP);
        } else if ("renamePrincipal".equals(dealType)) {
            adminMessage = new RenamePrincipalRep();
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.RENAME_PRINCIPAL_REP);
        } else if ("deletePrincipal".equals(dealType)) {
            adminMessage = new DeletePrincipalRep();
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.DELETE_PRINCIPAL_REP);
        } else if ("addPrincipal".equals(dealType)) {
            adminMessage = new AddPrincipalRep();
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.ADD_PRINCIPAL_REP);
        }

        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, message);

        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        adminMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));

        return KadminCode.encodeMessage(adminMessage);
    }
    
    private ByteBuffer infoPackageTool(File keytabFile, String dealType) throws IOException {
        AdminMessage adminMessage = null;
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        if ("exportKeytab".equals(dealType)) {
            adminMessage = new ExportKeytabRep();
            xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.EXPORT_KEYTAB_REP);
        }
        
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 1);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.BYTES, Files.readAllBytes(keytabFile.toPath()));

        KeytabMessageCode value = new KeytabMessageCode(xdrFieldInfos);
        adminMessage.setMessageBuffer(ByteBuffer.wrap(value.encode()));

        return KadminCode.encodeMessage(adminMessage);
    }

    private String listToString(List<String> list) {
        if (list.isEmpty()) {
            return null;
        }
        //Both speed and safety,so use StringBuilder
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            result.append(list.get(i)).append(" ");
        }
        return result.toString();
    }
    
    private List<String> stringToList(String str) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        String[] principals = str.split(" ");
        for (int i = 0; i < principals.length; i++) {
            principals[i] = fixPrincipal(principals[i]);
        }
        return Arrays.asList(principals);
    }

    private String fixPrincipal(String principal) {
        if (!principal.contains("@")) {
            principal += "@" + adminServerContext.getAdminRealm();
        }
        return principal;
    }
}
