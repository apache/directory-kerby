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
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

import java.util.List;

/**
 * Client side preauth plugin module
 */
public interface KrbPreauth extends PreauthPluginMeta {

    /**
     * Initializing preauth plugin context
     */
    public void init(KrbContext krbContext);

    /**
     * Initializing request context
     */
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest);

    /**
     * Prepare questions to prompt to you asking for credential
     */
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) throws KrbException;

    /**
     * Get supported encryption types
     */
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext);

    /**
     * Set krb options passed from user
     */
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KrbOptions preauthOptions);

    /**
     * Attempt to try any initial padata derived from user options
     */
    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException;

    /**
     * Process server returned paData and return back any result paData
     * Return true indicating padata is added
     */
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException;

    /**
     * When another request to server in the 4 pass, any paData to provide?
     * Return true indicating padata is added
     */
    public boolean tryAgain(KdcRequest kdcRequest,
                            PluginRequestContext requestContext,
                            PaDataType preauthType,
                            PaData errPadata,
                            PaData outPadata);

    /**
     * Return PA_REAL if pa_type is a real preauthentication type or PA_INFO if it is
     * an informational type.
     */
    public PaFlags getFlags(PaDataType paType);

    /**
     * When exiting...
     */
    public void destroy();

}
