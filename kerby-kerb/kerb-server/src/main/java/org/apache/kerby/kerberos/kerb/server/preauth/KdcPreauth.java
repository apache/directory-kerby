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

import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

/**
 * KDC side preauth plugin module
 */
public interface KdcPreauth extends PreauthPluginMeta {

    /**
     * Initializing plugin context for each realm
     */
    public void initWith(KdcContext context);

    /**
     * Initializing request context
     */
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest);

    /**
     * Optional: provide pa_data to send to the client as part of the "you need to
     * use preauthentication" error.
     */
    public void provideEdata(KdcRequest kdcRequest, PluginRequestContext requestContext,
                             PaData outPaData) throws KrbException;

    /**
     * Optional: verify preauthentication data sent by the client, setting the
     * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
     * field as appropriate.
     */
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException;

    /**
     * Optional: generate preauthentication response data to send to the client as
     * part of the AS-REP.
     */
    public void providePaData(KdcRequest kdcRequest, PluginRequestContext requestContext,
                              PaData paData);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(KdcRequest kdcRequest, PluginRequestContext requestContext,
                            PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy();

}
