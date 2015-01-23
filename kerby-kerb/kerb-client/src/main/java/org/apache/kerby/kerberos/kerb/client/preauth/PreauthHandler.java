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

import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOptions;
import org.apache.kerby.kerberos.kerb.client.preauth.builtin.EncTsPreauth;
import org.apache.kerby.kerberos.kerb.client.preauth.builtin.TgtPreauth;
import org.apache.kerby.kerberos.kerb.client.preauth.pkinit.PkinitPreauth;
import org.apache.kerby.kerberos.kerb.client.preauth.token.TokenPreauth;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.codec.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.EtypeInfo;
import org.apache.kerby.kerberos.kerb.spec.common.EtypeInfo2;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {
    private KrbContext krbContext;
    private List<KrbPreauth> preauths;

    public void init(KrbContext krbContext) {
        this.krbContext = krbContext;
        loadPreauthPlugins(krbContext);
    }

    private void loadPreauthPlugins(KrbContext context) {
        preauths = new ArrayList<KrbPreauth>();

        KrbPreauth preauth = new EncTsPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new TgtPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new PkinitPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new TokenPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public PreauthContext preparePreauthContext(KdcRequest kdcRequest) {
        PreauthContext preauthContext = new PreauthContext();
        preauthContext.setPreauthRequired(krbContext.getConfig().isPreauthRequired());
        for (KrbPreauth preauth : preauths) {
            PreauthHandle handle = new PreauthHandle(preauth);
            handle.initRequestContext(kdcRequest);
            preauthContext.getHandles().add(handle);
        }

        return preauthContext;
    }

    /**
     * Process preauth inputs and options, prepare and generate pdata to be out
     */
    public void preauth(KdcRequest kdcRequest) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        if (!preauthContext.isPreauthRequired()) {
            return;
        }

        if (!preauthContext.hasInputPaData()) {
            tryFirst(kdcRequest, preauthContext.getOutputPaData());
            return;
        }

        attemptETypeInfo(kdcRequest, preauthContext.getInputPaData());

        setPreauthOptions(kdcRequest, kdcRequest.getPreauthOptions());

        prepareUserResponses(kdcRequest, preauthContext.getInputPaData());

        preauthContext.getUserResponser().respondQuestions();

        if (!kdcRequest.isRetrying()) {
            process(kdcRequest, preauthContext.getInputPaData(),
                    preauthContext.getOutputPaData());
        } else {
            tryAgain(kdcRequest, preauthContext.getInputPaData(),
                    preauthContext.getOutputPaData());
        }
    }

    public void prepareUserResponses(KdcRequest kdcRequest,
                                     PaData inPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PaDataEntry pae : inPadata.getElements()) {
            if (! preauthContext.isPaTypeAllowed(pae.getPaDataType())) {
                continue;
            }

            PreauthHandle handle = findHandle(kdcRequest, pae.getPaDataType());
            if (handle == null) {
                continue;
            }

            handle.prepareQuestions(kdcRequest);
        }
    }

    public void setPreauthOptions(KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.setPreauthOptions(kdcRequest, preauthOptions);
        }
    }

    public void tryFirst(KdcRequest kdcRequest,
                         PaData outPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        PreauthHandle handle = findHandle(kdcRequest,
                preauthContext.getAllowedPaType());
        handle.tryFirst(kdcRequest, outPadata);
    }

    public void process(KdcRequest kdcRequest,
                        PaData inPadata, PaData outPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        /**
         * Process all informational padata types, then the first real preauth type
         * we succeed on
         */
        for (int real = 0; real <= 1; real ++) {
            for (PaDataEntry pae : inPadata.getElements()) {

                // Restrict real mechanisms to the chosen one if we have one
                if (real >0 && !preauthContext.isPaTypeAllowed(pae.getPaDataType())) {
                    continue;
                }

                PreauthHandle handle = findHandle(kdcRequest,
                        preauthContext.getAllowedPaType());
                if (handle == null) {
                    continue;
                }

                // Make sure this type is for the current pass
                int tmpReal = handle.isReal(pae.getPaDataType()) ? 1 : 0;
                if (tmpReal != real) {
                    continue;
                }

                if (real > 0 && preauthContext.checkAndPutTried(pae.getPaDataType())) {
                    continue;
                }

                boolean gotData = handle.process(kdcRequest, pae, outPadata);
                if (real > 0 && gotData) {
                    return;
                }
            }
        }
    }

    public void tryAgain(KdcRequest kdcRequest,
                         PaData inPadata, PaData outPadata) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        PreauthHandle handle;
        for (PaDataEntry pae : inPadata.getElements()) {
            handle = findHandle(kdcRequest, pae.getPaDataType());
            if (handle == null) continue;

            boolean gotData = handle.tryAgain(kdcRequest,
                    pae.getPaDataType(), preauthContext.getErrorPaData(), outPadata);
        }
    }

    public void destroy() {
        for (KrbPreauth preauth : preauths) {
            preauth.destroy();
        }
    }

    private PreauthHandle findHandle(KdcRequest kdcRequest,
                                     PaDataType paType) {
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

    private void attemptETypeInfo(KdcRequest kdcRequest,
                                  PaData inPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        // Find an etype-info2 or etype-info element in padata
        EtypeInfo etypeInfo = null;
        EtypeInfo2 etypeInfo2 = null;
        PaDataEntry pae = inPadata.findEntry(PaDataType.ETYPE_INFO);
        if (pae != null) {
            etypeInfo = KrbCodec.decode(pae.getPaDataValue(), EtypeInfo.class);
        } else {
            pae = inPadata.findEntry(PaDataType.ETYPE_INFO2);
            if (pae != null) {
                etypeInfo2 = KrbCodec.decode(pae.getPaDataValue(), EtypeInfo2.class);
            }
        }

        if (etypeInfo == null && etypeInfo2 == null) {
            attemptSalt(kdcRequest, inPadata);
        }
    }

    private void attemptSalt(KdcRequest kdcRequest,
                                  PaData inPadata) throws KrbException {

    }
}
