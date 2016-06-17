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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.tool.GetprincsReq;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Created by root on 6/3/16.
 */
public class GetprincsRequest extends AdminRequest {
    private String globString = null;

    public GetprincsRequest() {
        super(null);
    }

    public GetprincsRequest(String globString) {
        super(null);
        this.globString = globString;
    }

    @Override
    public void process() throws KrbException {
        //encoding and set adminReq

        GetprincsReq getprincsReq = new GetprincsReq();

        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.GET_PRINCS_REQ);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 2);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, globString);

        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        byte[] encodeBytes;
        try {
            encodeBytes = value.encode();
        } catch (IOException e) {
            throw new KrbException("Xdr encode error when generate get principals request.", e);
        }
        ByteBuffer messageBuffer = ByteBuffer.wrap(encodeBytes);
        getprincsReq.setMessageBuffer(messageBuffer);

        setAdminReq(getprincsReq);

    }

}
