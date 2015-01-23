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
package org.apache.kerby.kerberos.kerb.client.preauth;

import org.apache.kerby.kerberos.kerb.client.KrbOptions;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PluginRequestContext requestContext;

    public PreauthHandle(KrbPreauth preauth) {
        this.preauth = preauth;
    }

    public void initRequestContext(KdcRequest kdcRequest) {
        requestContext = preauth.initRequestContext(kdcRequest);
    }

    public void prepareQuestions(KdcRequest kdcRequest) throws KrbException {
        preauth.prepareQuestions(kdcRequest, requestContext);
    }

    public void setPreauthOptions(KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(kdcRequest, requestContext, preauthOptions);
    }

    public void tryFirst(KdcRequest kdcRequest, PaData outPadata) throws KrbException {
        preauth.tryFirst(kdcRequest, requestContext, outPadata);
    }

    public boolean process(KdcRequest kdcRequest,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        return preauth.process(kdcRequest, requestContext, inPadata, outPadata);
    }

    public boolean tryAgain(KdcRequest kdcRequest,
                         PaDataType paType, PaData errPadata, PaData paData) {
        return preauth.tryAgain(kdcRequest, requestContext, paType, errPadata, paData);
    }

    public boolean isReal(PaDataType paType) {
        PaFlags paFlags = preauth.getFlags(paType);
        return paFlags.isReal();
    }

}
