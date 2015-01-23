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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;

import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.IdentityOpts;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PluginOpts;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;

public class PkinitRequestContext implements PluginRequestContext {

    public PkinitRequestOpts requestOpts = new PkinitRequestOpts();
    public IdentityOpts identityOpts = new IdentityOpts();
    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean rfc6112Kdc;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
    public void updateRequestOpts(PluginOpts pluginOpts) {
        requestOpts.requireEku = pluginOpts.requireEku;
        requestOpts.acceptSecondaryEku = pluginOpts.acceptSecondaryEku;
        requestOpts.allowUpn = pluginOpts.allowUpn;
        requestOpts.usingRsa = pluginOpts.usingRsa;
        requestOpts.requireCrlChecking = pluginOpts.requireCrlChecking;
    }
}
