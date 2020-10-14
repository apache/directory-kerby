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
import org.apache.kerby.kerberos.kerb.admin.message.AdminReq;
import org.apache.kerby.kerberos.kerb.admin.message.KadminCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.message.KeytabMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.IdentityInfoCode;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.xdr.XdrFieldInfo;
import org.apache.kerby.xdr.type.XdrStructType;
import org.xnio.sasl.SaslWrapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

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
     * @param sasl The SASL client wrapper
     * @throws KrbException e
     */
    public void handleRequest(AdminRequest adminRequest, SaslWrapper sasl) throws KrbException {
        adminRequest.process();
        AdminReq adminReq = adminRequest.getAdminReq();

        try {
            ByteBuffer requestMessage = KadminCode.encodeWrapMessage(adminReq, sasl);
            requestMessage.flip();
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
            case CHANGE_PWD_REP:
                if (adminRequest.getAdminReq().getAdminMessageType()
                        == AdminMessageType.CHANGE_PWD_REQ) {
                    System.out.println((String) fieldInfos[2].getValue());
                } else {
                    throw new KrbException("Response message type error: need "
                            + AdminMessageType.CHANGE_PWD_REP);
                }
                break;
            default:
                throw new KrbException("Response message type error: " + type);
        }
    }

    public List<String> onResponseMessageForList(AdminRequest adminRequest,
                                  ByteBuffer responseMessage) throws KrbException {
        List<String> princalsList = null;

        XdrStructType decoded = new AdminMessageCode();
        try {
            decoded.decode(responseMessage);
        } catch (IOException e) {
            throw new KrbException("On response message failed.", e);
        }
        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();

        switch (type) {
            case GET_PRINCS_REP:
                if (adminRequest.getAdminReq().getAdminMessageType()
                        == AdminMessageType.GET_PRINCS_REQ) {
                    String[] temp = ((String) fieldInfos[2].getValue()).trim().split(" ");
                    princalsList = Arrays.asList(temp);
                } else {
                    throw new KrbException("Response message type error: need "
                            + AdminMessageType.GET_PRINCS_REP);
                }
                break;
            default:
                throw new KrbException("Response message type error: " + type);
        }

        return princalsList;
    }
    
    public byte[] onResponseMessageForBytesArray(AdminRequest adminRequest,
                                 ByteBuffer responseMessage) throws KrbException {
        byte[] keytabFileBytes = null;
        
        XdrStructType decoded = new KeytabMessageCode();
        try {
            decoded.decode(responseMessage);
        } catch (IOException e) {
            throw new KrbException("On response message failed.", e);
        }
        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();
        
        switch (type) {
            case EXPORT_KEYTAB_REP:
                if (adminRequest.getAdminReq().getAdminMessageType() == AdminMessageType.EXPORT_KEYTAB_REQ) {
                    keytabFileBytes = (byte[]) fieldInfos[2].getValue();
                } else {
                    throw new KrbException("Response message type error: need "
                            + AdminMessageType.EXPORT_KEYTAB_REP);
                }
                break;
            default:
                throw new KrbException("Response message type error: " + type);
        }
        
        return keytabFileBytes;
    }

    public KrbIdentity onResponseMessageForIdentity(AdminRequest adminRequest,
                                                    ByteBuffer responseMessage) throws KrbException {
        KrbIdentity identity = null;

        IdentityInfoCode decoded = new IdentityInfoCode();
        try {
            decoded.decode(responseMessage);
        } catch (IOException e) {
            throw new KrbException("On response message failed.", e);
        }
        XdrFieldInfo[] fieldInfos = decoded.getValue().getXdrFieldInfos();
        AdminMessageType type = (AdminMessageType) fieldInfos[0].getValue();

        switch (type) {
            case GET_PRINCIPAL_REP:
                if (adminRequest.getAdminReq().getAdminMessageType() == AdminMessageType.GET_PRINCIPAL_REQ) {
                    identity = new KrbIdentity((String) fieldInfos[2].getValue());

                    identity.setExpireTime(new KerberosTime((long) fieldInfos[3].getValue()));
                    identity.setCreatedTime(new KerberosTime((long) fieldInfos[4].getValue()));
                    identity.setKdcFlags((int) fieldInfos[5].getValue());
                    identity.setKeyVersion((int) fieldInfos[6].getValue());
                    int keySize = (int) fieldInfos[7].getValue();
                    String[] keySet = ((String) fieldInfos[8].getValue()).split(",");
                    for (int i = 0; i < keySize; i++) {
                        EncryptionKey key = new EncryptionKey();
                        key.setKeyType(EncryptionType.fromName(keySet[i]));
                        identity.addKey(key);
                    }

                }
                break;
            default:
                throw new KrbException("Response message type error: " + type);
        }
        return identity;
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

    protected abstract List<String> handleRequestForList(AdminRequest adminRequest,
                                                         SaslWrapper sasl) throws KrbException;

    protected abstract byte[] handleRequestForBytes(AdminRequest adminRequest,
                                                    SaslWrapper sasl) throws KrbException;

    protected abstract KrbIdentity handleRequestForIdentity(AdminRequest adminRequest,
                                                            SaslWrapper sasl) throws KrbException;
}
