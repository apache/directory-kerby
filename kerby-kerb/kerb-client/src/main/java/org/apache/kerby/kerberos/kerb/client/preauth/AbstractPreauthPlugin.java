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
import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

import java.util.Collections;
import java.util.List;

public class AbstractPreauthPlugin implements KrbPreauth {

    private PreauthPluginMeta pluginMeta;
    protected KrbContext context;

    public AbstractPreauthPlugin(PreauthPluginMeta meta) {
        this.pluginMeta = meta;
    }

    /**
     * Get plugin name.
     */
    @Override
    public String getName() {
        return pluginMeta.getName();
    }

    /**
     * Get plugin version.
     */
    public int getVersion() {
        return pluginMeta.getVersion();
    }

    /**
     * Get padata type.
     */
    public PaDataType[] getPaTypes() {
        return pluginMeta.getPaTypes();
    }

    /**
     * {@inheritDoc}
     */
    public void init(KrbContext context) {
        this.context = context;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) throws KrbException {

        kdcRequest.needAsKey();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext, KOptions options) {

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext, PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                            PluginRequestContext requestContext, PaDataType preauthType,
                            PaData errPadata, PaData outPadata) {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {

    }

}
