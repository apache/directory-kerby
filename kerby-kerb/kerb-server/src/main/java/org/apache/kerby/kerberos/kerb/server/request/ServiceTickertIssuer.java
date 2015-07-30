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
package org.apache.kerby.kerberos.kerb.server.request;

import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.kerb.spec.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.base.TransitedEncoding;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;

/**
 * Issuing service ticket.
 */
public class ServiceTickertIssuer extends TickertIssuer {
    private final Ticket tgtTicket;
    private final AuthToken token;

    public ServiceTickertIssuer(TgsRequest kdcRequest) {
        super(kdcRequest);
        tgtTicket = kdcRequest.getTgtTicket();
        token = kdcRequest.getToken();
    }

    protected KdcRequest getTgsRequest() {
        return getKdcRequest();
    }

    @Override
    protected PrincipalName getclientPrincipal() {
        if (token != null) {
            return new PrincipalName(token.getSubject());
        }
        return tgtTicket.getEncPart().getCname();
    }

    @Override
    protected TransitedEncoding getTransitedEncoding() {
        if (token != null) {
            return super.getTransitedEncoding();
        }
        return tgtTicket.getEncPart().getTransited();
    }
}
