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
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminContext;
import org.apache.kerby.kerberos.kerb.transport.KrbTransport;
import org.apache.kerby.kerberos.kerb.admin.tool.AdminReq;

public class AdminRequest {
    private String principal;
    private KrbTransport transport;
    private AdminReq adminReq;

    private AdminContext context;

    public AdminRequest(AdminContext context) {
        this.context = context;
    }

    public AdminRequest(String principal) {
        this.principal = principal;
    }

    public AdminContext getContext() {
        return context;
    }

    public void setContext(AdminContext context) {
        this.context = context;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public void setAdminReq(AdminReq adminReq) {
        this.adminReq = adminReq;
    }

    public AdminReq getAdminReq() {
        return adminReq;
    }

    public void process() throws KrbException {
        //

    }


    public void setTransport(KrbTransport transport) {
        this.transport = transport;
    }

    public KrbTransport getTransport() {
        return transport;
    }
}