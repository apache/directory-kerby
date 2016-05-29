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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.preauth.builtin.EncTsPreauth;
import org.apache.kerby.kerberos.kerb.server.preauth.builtin.TgtPreauth;
import org.apache.kerby.kerberos.kerb.server.preauth.pkinit.PkinitPreauth;
import org.apache.kerby.kerberos.kerb.server.preauth.token.TokenPreauth;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KdcPreauth> preauths;

    /**
     * Should be called only once, for global
     */
    public void init() {
        loadPreauthPlugins();
    }

    private void loadPreauthPlugins() {
        preauths = new ArrayList<KdcPreauth>();

        KdcPreauth preauth = new EncTsPreauth();
        preauths.add(preauth);

        preauth = new TgtPreauth();
        preauths.add(preauth);

        preauth = new TokenPreauth();
        preauths.add(preauth);

        preauth = new PkinitPreauth();
        preauths.add(preauth);
    }

    /**
     * Should be called per realm
     * @param context The kdc context
     */
    public void initWith(KdcContext context) {
        for (KdcPreauth preauth : preauths) {
            preauth.initWith(context);
        }
    }

    public PreauthContext preparePreauthContext(KdcRequest kdcRequest) {
        PreauthContext preauthContext = new PreauthContext();

        KdcContext kdcContext = kdcRequest.getKdcContext();
        initWith(kdcContext);
        preauthContext.setPreauthRequired(kdcContext.getConfig().isPreauthRequired());

        for (KdcPreauth preauth : preauths) {
            PreauthHandle handle = new PreauthHandle(preauth);
            handle.initRequestContext(kdcRequest);
            preauthContext.getHandles().add(handle);
        }

        return preauthContext;
    }

    public void provideEdata(KdcRequest kdcRequest, PaData outPaData) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.provideEdata(kdcRequest, outPaData);
        }
    }

    public void verify(KdcRequest kdcRequest, PaData paData) throws KrbException {
        for (PaDataEntry paEntry : paData.getElements()) {
            PreauthHandle handle = findHandle(kdcRequest, paEntry.getPaDataType());
            if (handle != null) {
                handle.verify(kdcRequest, paEntry);
            }
        }
    }

    public void providePaData(KdcRequest kdcRequest, PaData paData) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.providePaData(kdcRequest, paData);
        }
    }

    private PreauthHandle findHandle(KdcRequest kdcRequest, PaDataType paType) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            for (PaDataType pt : handle.preauth.getPaTypes()) {
                if (pt == paType) {
                    return handle;
                }
            }
        }
        return null;
    }

    public void destroy() {
        for (KdcPreauth preauth : preauths) {
            preauth.destroy();
        }
    }

    public static boolean isToken(PaData paData) {
        if (paData != null) {
            for (PaDataEntry paEntry : paData.getElements()) {
                if (paEntry.getPaDataType() == PaDataType.TOKEN_REQUEST) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isPkinit(PaData paData) {
        if (paData != null) {
            for (PaDataEntry paEntry : paData.getElements()) {
                if (paEntry.getPaDataType() == PaDataType.PK_AS_REQ) {
                    return true;
                }
            }
        }
        return false;
    }
}
