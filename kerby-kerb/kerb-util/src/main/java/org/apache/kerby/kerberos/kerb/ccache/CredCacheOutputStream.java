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

import org.apache.kerby.kerberos.kerb.KrbOutputStream;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.*;
import org.apache.kerby.kerberos.kerb.spec.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlags;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public class CredCacheOutputStream extends KrbOutputStream
{
	public CredCacheOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void writePrincipal(PrincipalName principal, int version) throws IOException {
        List<String> nameComponents = principal.getNameStrings();

    	if (version != CredentialCache.FCC_FVNO_1) {
        	writeInt(principal.getNameType().getValue());
        }

        int numComponents = nameComponents.size();
        if (version == CredentialCache.FCC_FVNO_1) {
            numComponents ++;
        }
        writeInt(numComponents);
        
        writeRealm(principal.getRealm());
        
        for (String nameCom : nameComponents) {
            writeCountedString(nameCom);
        }
    }

    @Override
    public void writeKey(EncryptionKey key, int version) throws IOException {
    	writeShort(key.getKeyType().getValue());
    	if (version == CredentialCache.FCC_FVNO_3) {
    		writeShort(key.getKeyType().getValue());
    	}

        writeCountedOctets(key.getKeyData());
    }

    public void writeTimes(KerberosTime[] times) throws IOException {
        for (int i = 0; i < times.length; ++i) {
            writeTime(times[i]);
        }
    }

    public void writeAddresses(HostAddresses addrs) throws IOException {
    	if (addrs == null) {
    		writeInt(0);
    	} else {
            List<HostAddress> addresses = addrs.getElements();
    		write(addresses.size());
    		for (HostAddress addr : addresses) {
                writeAddress(addr);
    		}
    	}
    }

    public void writeAddress(HostAddress address) throws IOException {
        write(address.getAddrType().getValue());
        write(address.getAddress().length);
        write(address.getAddress(), 0,
                address.getAddress().length);
    }

    public void writeAuthzData(AuthorizationData authData) throws IOException  {
    	if (authData == null) {
    		writeInt(0);
    	} else {
    		for (AuthorizationDataEntry entry : authData.getElements()) {
    			write(entry.getAuthzType().getValue());
    			write(entry.getAuthzData().length);
    			write(entry.getAuthzData());
    		}
    	}
    }
    
    public void writeTicket(Ticket t) throws IOException  {
        if (t == null) {
            writeInt(0);
        } else {
            byte[] bytes = t.encode();
            writeInt(bytes.length);
            write(bytes);
        }
    }

    public void writeIsSkey(boolean isEncInSKey) throws IOException {
        writeByte(isEncInSKey ? 1 : 0);
    }

    public void writeTicketFlags(TicketFlags ticketFlags) throws IOException {
        writeInt(ticketFlags.getFlags());
    }
}
