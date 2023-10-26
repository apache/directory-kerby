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
package org.apache.kerby.kerberos.kerb.server;

import java.io.IOException;

import org.apache.kerby.KOptions;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PrincipalNameTest extends KdcTestBase {

    @Test
    public void testNTPrincipal() throws IOException, KrbException {

        KOptions options = new KOptions();
        options.add(KrbOption.CLIENT_PRINCIPAL, getClientPrincipal());
        options.add(KrbOption.USER_PASSWD, getClientPassword());
        options.add(KrbOption.USE_PASSWD, true);
        
        TgtTicket tgt = getKrbClient().requestTgt(options);
        assertThat(tgt.getClientPrincipal().getName()).isEqualTo(getClientPrincipal());
    }
    
    @Test
    @org.junit.jupiter.api.Disabled // See https://issues.apache.org/jira/browse/DIRKRB-659
    public void testNTEnterprisePrincipal() throws IOException, KrbException {

        KOptions options = new KOptions();
        options.add(KrbOption.CLIENT_PRINCIPAL, getClientPrincipal());
        options.add(KrbOption.USER_PASSWD, getClientPassword());
        options.add(KrbOption.USE_PASSWD, true);
        options.add(KrbOption.AS_ENTERPRISE_PN, true);
        
        TgtTicket tgt = getKrbClient().requestTgt(options);
        assertThat(tgt.getClientPrincipal().getName()).isEqualTo(getClientPrincipal());
    }
}
