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
package org.apache.kerby.kerberos.kerb.ccache;

import org.apache.kerby.kerberos.kerb.KrbInputStream;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlags;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class CredCacheInputStream extends KrbInputStream
{
    public CredCacheInputStream(InputStream in) {
        super(in);
    }

    @Override
    public PrincipalName readPrincipal(int version) throws IOException {
        NameType nameType = NameType.NT_UNKNOWN;
        if (version != CredentialCache.FCC_FVNO_1) {
            int typeValue = readInt();
            nameType = NameType.fromValue(typeValue);
        }

        int numComponents = readInt();
        if (version == CredentialCache.FCC_FVNO_1) {
            numComponents -= 1;
        }

        String realm = readCountedString();

        List<String> nameStrings = new ArrayList<String>();
        String component;
        for (int i = 0; i < numComponents; i++) { // sub 1 if version 0x501
            component = readCountedString();
            nameStrings.add(component);
        }

        PrincipalName principal = new PrincipalName(nameStrings, nameType);
        principal.setRealm(realm);

        return principal;
    }

    public EncryptionKey readKey(int version) throws IOException {
        if (version == CredentialCache.FCC_FVNO_3) {
            readShort(); //  ignore keytype
        }

        return super.readKey(version);
    }

    public KerberosTime[] readTimes() throws IOException {
        KerberosTime[] times = new KerberosTime[4];

        for (int i = 0; i < times.length; ++i) {
            times[i] = readTime();
        }

        return times;
    }

    public boolean readIsSkey() throws IOException {
        int value = readByte();
        return value == 1 ? true : false;
    }

    public HostAddresses readAddr() throws IOException {
        int numAddresses = readInt();
        if (numAddresses <= 0) {
            return null;
        }

        HostAddress[] addresses = new HostAddress[numAddresses];
        for (int i = 0; i < numAddresses; i++) {
            addresses[i] = readAddress();
        }

        HostAddresses result = new HostAddresses();
        result.addElements(addresses);
        return result;
    }

    public HostAddress readAddress() throws IOException {
        int typeValue = readShort();
        HostAddrType addrType = HostAddrType.fromValue(typeValue);
        byte[] addrData = readCountedOctets();

        HostAddress addr = new HostAddress();
        addr.setAddrType(addrType);
        addr.setAddress(addrData);

        return addr;
    }

    public AuthorizationData readAuthzData() throws IOException {
        int numEntries = readInt();
        if (numEntries <= 0) {
            return null;
        }

        AuthorizationDataEntry[] authzData = new AuthorizationDataEntry[numEntries];
        for (int i = 0; i < numEntries; i++) {
            authzData[i] = readAuthzDataEntry();
        }

        AuthorizationData result = new AuthorizationData();
        result.addElements(authzData);
        return result;
    }

    public AuthorizationDataEntry readAuthzDataEntry() throws IOException {
        int typeValue = readShort();
        AuthorizationType authzType = AuthorizationType.fromValue(typeValue);
        byte[] authzData = readCountedOctets();

        AuthorizationDataEntry authzEntry = new AuthorizationDataEntry();
        authzEntry.setAuthzType(authzType);
        authzEntry.setAuthzData(authzData);

        return authzEntry;
    }

    @Override
    public int readOctetsCount() throws IOException {
        return readInt();
    }

    public TicketFlags readTicketFlags() throws IOException {
        int flags = readInt();
        TicketFlags tktFlags = new TicketFlags(flags);
        return tktFlags;
    }

    public Ticket readTicket() throws IOException {
        byte[] ticketData = readCountedOctets();
        if (ticketData == null) {
            return null;
        }

        Ticket ticket = new Ticket();
        ticket.decode(ticketData);
        return ticket;
    }
}
