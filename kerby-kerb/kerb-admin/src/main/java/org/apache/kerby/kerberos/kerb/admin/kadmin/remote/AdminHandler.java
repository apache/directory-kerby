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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request.AdminRequest;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminReq;
import org.apache.kerby.kerberos.kerb.admin.tool.KadminCode;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.XdrStructType;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AdminHandler {

    /**
     * Init with krbcontext.
     *
     * @param context The krbcontext
     */
    public void init(AdminContext context) {

    }

    /**
     * Handle the kdc request.
     *
     * @param adminRequest The admin request
     * @throws KrbException e
     */
    public void handleRequest(AdminRequest adminRequest) throws KrbException {
        adminRequest.process();
        AdminReq adminReq = adminRequest.getAdminReq();
        ByteBuffer requestMessage = KadminCode.encodeMessage(adminReq);
        requestMessage.flip();

        try {
            sendMessage(adminRequest, requestMessage);
        } catch (IOException e) {
            throw new KrbException("Admin sends request message failed", e);
        }

    }

    /**
     * Process the response message from kdc.
     *
     * @param adminRequest The admin request
     * @param responseMessage The message from kdc
     * @throws KrbException e
     */
    public void onResponseMessage(AdminRequest adminRequest,
                                  ByteBuffer responseMessage) throws KrbException {


        XdrStructType decoded = new AdminMessageCode();
        try {
            decoded.decode(responseMessage);
        } catch (IOException e) {
            throw new KrbException("On response message failed.", e);
        }
        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();

        switch (type) {
            case ADD_PRINCIPAL_REP:
                if (adminRequest.getAdminReq().getAdminMessageType()
                    == AdminMessageType.ADD_PRINCIPAL_REQ) {
                    System.out.println((String) fieldInfos[2].getValue());
                } else {
                    throw new KrbException("Response message type error: need "
                    + AdminMessageType.ADD_PRINCIPAL_REP);
                }
                break;
            case DELETE_PRINCIPAL_REP:
                if (adminRequest.getAdminReq().getAdminMessageType()
                    == AdminMessageType.DELETE_PRINCIPAL_REQ) {
                    System.out.println((String) fieldInfos[2].getValue());
                } else {
                    throw new KrbException("Response message type error: need "
                    + AdminMessageType.DELETE_PRINCIPAL_REP);
                }
                break;
            case RENAME_PRINCIPAL_REP:
                if (adminRequest.getAdminReq().getAdminMessageType()
                    == AdminMessageType.RENAME_PRINCIPAL_REQ) {
                    System.out.println((String) fieldInfos[2].getValue());
                } else {
                    throw new KrbException("Response message type error: need "
                    + AdminMessageType.RENAME_PRINCIPAL_REP);
                }
                break;
            default:
                throw new KrbException("Response message type error: " + type);
        }
    }

    /**
     * Send message to kdc.
     *
     * @param adminRequest The admin request
     * @param requestMessage The request message to kdc
     * @throws IOException e
     */
    protected abstract void sendMessage(AdminRequest adminRequest,
                                        ByteBuffer requestMessage) throws IOException;
}
