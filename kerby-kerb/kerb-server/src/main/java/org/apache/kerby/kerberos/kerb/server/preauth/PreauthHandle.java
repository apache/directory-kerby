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
package org.apache.kerby.kerberos.kerb.server.preauth;

import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;

public class PreauthHandle {

    public KdcPreauth preauth;
    public PluginRequestContext requestContext;

    public PreauthHandle(KdcPreauth preauth) {
        this.preauth = preauth;
    }

    public void initRequestContext(KdcRequest kdcRequest) {
        requestContext = preauth.initRequestContext(kdcRequest);
    }

    public void provideEdata(KdcRequest kdcRequest, PaData outPaData) throws KrbException {
        preauth.provideEdata(kdcRequest, requestContext, outPaData);
    }

    public void verify(KdcRequest kdcRequest, PaDataEntry paData) throws KrbException {
        preauth.verify(kdcRequest, requestContext, paData);
    }

    public void providePaData(KdcRequest kdcRequest, PaData paData) {
        preauth.providePaData(kdcRequest, requestContext, paData);
    }

    public void destroy() {
        preauth.destroy();
    }
}
