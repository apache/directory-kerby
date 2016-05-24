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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.tool.AddPrincipalReq;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageType;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * AddPrincipal request
 */
public class AddPrincipalRequest extends AdminRequest {

    private KOptions kOptions;
    private String password;

    public AddPrincipalRequest(String principal) {
        super(principal);
    }

    public AddPrincipalRequest(String principal, KOptions kOptions) {
        super(principal);
        this.kOptions = kOptions;
    }

    public AddPrincipalRequest(String principal, String password) {
        super(principal);
        this.password = password;
    }

    public AddPrincipalRequest(String princial, KOptions kOptions, String password) {
        super(princial);
        this.kOptions = kOptions;
        this.password = password;
    }


    @Override
    public void process() throws KrbException {
        super.process();
        /**replace this with encode in handler*/
        AddPrincipalReq addPrincipalReq = new AddPrincipalReq();
        /** encode admin message:
         *  encode type
         *  encode paranum
         *  encode principal name
         *  (encode koptions)
         *  (encode passsword)
         */
        int paramNum = getParamNum();
        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[paramNum + 2];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.ADD_PRINCIPAL_REQ);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, paramNum);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, getPrincipal());
        if (paramNum == 2 && kOptions != null) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRUCT, kOptions); /////koption
        } else if (paramNum == 2 && password != null) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRING, password);
        } else if (paramNum == 3) {
            xdrFieldInfos[3] = new XdrFieldInfo(3, XdrDataType.STRUCT, kOptions); ////koption
            xdrFieldInfos[4] = new XdrFieldInfo(4, XdrDataType.STRING, password);
        }
        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        byte[] encodeBytes;
        try {
            encodeBytes = value.encode();
        } catch (IOException e) {
            throw new KrbException("Xdr encode error when generate add principal request.", e);
        }
        ByteBuffer messageBuffer = ByteBuffer.wrap(encodeBytes);
        addPrincipalReq.setMessageBuffer(messageBuffer);




        setAdminReq(addPrincipalReq);

    }

    public int getParamNum() {
        int paramNum = 0;
        if (getPrincipal() == null) {
            throw new RuntimeException("Principal name missing.");
        }
        if (kOptions == null && password == null) {
            paramNum = 1;
        } else if (kOptions == null || password == null) {
            paramNum = 2;
        } else {
            paramNum = 3;
        }
        return paramNum;
    }

}
