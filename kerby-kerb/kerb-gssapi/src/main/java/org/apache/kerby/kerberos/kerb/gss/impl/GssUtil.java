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
package org.apache.kerby.kerberos.kerb.gss.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClientBase;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.HostAddress;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncTgsRepPart;
import org.apache.kerby.kerberos.kerb.type.ticket.KrbTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;

import javax.crypto.SecretKey;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.List;

/**
 * Some utility functions to translate types between GSS and Kerby
 */
public class GssUtil {
    private static final int KERBEROS_TICKET_NUM_FLAGS = 32;  // KerberosTicket.NUM_LENGTH

    /**
     * Construct TgtTicket from info contained in KerberosTicket
     * @param kerberosTicket
     * @return
     * @throws GSSException
     */
    public static TgtTicket getTgtTicketFromKerberosTicket(KerberosTicket kerberosTicket) throws GSSException {
        String clientName = kerberosTicket.getClient().getName();
        PrincipalName clientPrincipal = new PrincipalName(clientName);

        byte[] asn1Encoded = kerberosTicket.getEncoded();
        Ticket ticket = getTicketFromAsn1Encoded(asn1Encoded);

        EncAsRepPart encAsRepPart = new EncAsRepPart();
        fillEncKdcRepPart(encAsRepPart, kerberosTicket);

        TgtTicket tgt = new TgtTicket(ticket, encAsRepPart, clientPrincipal);
        return tgt;
    }

    /**
     *  Init encKdcRepPart members with info from kerberosTicket
     * @param encKdcRepPart
     * @param kerberosTicket
     */
    public static void fillEncKdcRepPart(EncKdcRepPart encKdcRepPart, KerberosTicket kerberosTicket) {
        String clientName = kerberosTicket.getClient().getName();
        PrincipalName clientPrincipal = new PrincipalName(clientName);

        SecretKey secretKey = kerberosTicket.getSessionKey();
        int keyType = kerberosTicket.getSessionKeyType();
        EncryptionKey key = new EncryptionKey(keyType, secretKey.getEncoded());
        encKdcRepPart.setKey(key);

        encKdcRepPart.setSname(clientPrincipal);
        Date authTimeDate = kerberosTicket.getAuthTime();
        if (authTimeDate != null) {
            encKdcRepPart.setAuthTime(new KerberosTime(authTimeDate.getTime()));
        }
        Date startTimeDate = kerberosTicket.getStartTime();
        if (startTimeDate != null) {
            encKdcRepPart.setStartTime(new KerberosTime(startTimeDate.getTime()));
        }
        KerberosTime endTime = new KerberosTime(kerberosTicket.getEndTime().getTime());
        encKdcRepPart.setEndTime(endTime);


        InetAddress[] clientAddresses = kerberosTicket.getClientAddresses();
        HostAddresses hostAddresses = null;
        if (clientAddresses != null) {
            hostAddresses = new HostAddresses();
            for (InetAddress iAddr : clientAddresses) {
                hostAddresses.add(new HostAddress(iAddr));
            }
        }
        encKdcRepPart.setCaddr(hostAddresses);

        boolean[] tf = kerberosTicket.getFlags();
        TicketFlags ticketFlags = getTicketFlags(tf);
        encKdcRepPart.setFlags(ticketFlags);


        /* encKdcRepPart.setKeyExpiration();
        encKdcRepPart.setLastReq();
        encKdcRepPart.setNonce(); */

        Date renewTillDate = kerberosTicket.getRenewTill();
        KerberosTime renewTill = renewTillDate == null ? null : new KerberosTime(renewTillDate.getTime());
        encKdcRepPart.setRenewTill(renewTill);

        String serverRealm = kerberosTicket.getServer().getRealm();
        encKdcRepPart.setSrealm(serverRealm);
    }

    /**
     * Generate TicketFlags instance from flags
     * @param flags each item in flags identifies an bit setted or not
     * @return
     */
    public static TicketFlags getTicketFlags(boolean[] flags) {
        if (flags == null || flags.length != KERBEROS_TICKET_NUM_FLAGS) {
            return null;
        }
        int value = 0;
        for (boolean flag : flags) {
            value = (value << 1) + (flag ? 1 : 0);
        }
        return new TicketFlags(value);
    }

    /**
     * Decode each flag in ticketFlags into an boolean array
     * @param ticketFlags
     * @return
     */
    public static boolean[] ticketFlagsToBooleans(TicketFlags ticketFlags) {
        boolean[] ret = new boolean[KERBEROS_TICKET_NUM_FLAGS];
        int value = ticketFlags.getFlags();
        for (int i = 0; i < KERBEROS_TICKET_NUM_FLAGS; i++) {
            ret[KERBEROS_TICKET_NUM_FLAGS - i - 1] = (value & 0x1) != 0;
            value = value >> 1;
        }
        return ret;
    }

    /**
     * Construct a Ticket from bytes encoded by Asn1
     * @param encoded
     * @return
     * @throws GSSException
     */
    public static Ticket getTicketFromAsn1Encoded(byte[] encoded) throws GSSException {
        Ticket ticket = new Ticket();
        ByteBuffer byteBuffer = ByteBuffer.wrap(encoded);
        try {
            ticket.decode(byteBuffer);
            return ticket;
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, e.getMessage());
        }
    }

    /**
     * Scan current context for SgtTicket
     * @param client
     * @param service
     * @return
     */
    public static SgtTicket getSgtCredentialFromContext(GSSCaller caller, String client, String service)
            throws GSSException {
        KerberosTicket ticket = CredUtils.getKerberosTicketFromContext(caller, client, service);
        return getSgtTicketFromKerberosTicket(ticket);
    }

    /**
     * Construct a SgtTicket from KerberosTicket
     * @param kerberosTicket
     * @return
     * @throws GSSException
     */
    public static SgtTicket getSgtTicketFromKerberosTicket(KerberosTicket kerberosTicket) throws GSSException {
        if (kerberosTicket == null) {
            return null;
        }

        Ticket ticket = getTicketFromAsn1Encoded(kerberosTicket.getEncoded());

        EncTgsRepPart encTgsRepPart = new EncTgsRepPart();
        fillEncKdcRepPart(encTgsRepPart, kerberosTicket);

        SgtTicket sgt = new SgtTicket(ticket, encTgsRepPart);
        return sgt;
    }

    /**
     *  Apply SgtTicket by sending TGS_REQ to KDC
     * @param ticket
     * @param service
     * @return
     */
    public static SgtTicket applySgtCredential(KerberosTicket ticket, String service) throws GSSException {
        TgtTicket tgt = getTgtTicketFromKerberosTicket(ticket);
        return applySgtCredential(tgt, service);
    }

    public static SgtTicket applySgtCredential(TgtTicket tgt, String server) throws GSSException {
        KrbClientBase client = getKrbClient();

        SgtTicket sgt = null;
        try {
            client.init();
            sgt = client.requestSgt(tgt, server);
            return sgt;
        } catch (KrbException e) {
            throw new GSSException(GSSException.FAILURE, -1, e.getMessage());
        }
    }

    public static KerberosTicket convertKrbTicketToKerberosTicket(KrbTicket krbTicket, String clientName)
            throws GSSException {
        byte[] asn1Encoding;
        try {
            asn1Encoding = krbTicket.getTicket().encode();
        } catch (IOException e) {
            throw new GSSException(GSSException.FAILURE, -1, e.getMessage());
        }

        byte[] sessionKey = krbTicket.getSessionKey().getKeyData();
        int keyType = krbTicket.getSessionKey().getKeyType().getValue();

        EncKdcRepPart encKdcRepPart = krbTicket.getEncKdcRepPart();
        KerberosPrincipal client = new KerberosPrincipal(clientName);

        PrincipalName serverPrinc = krbTicket.getTicket().getSname();
        String serverName = serverPrinc.getName() + "@" + krbTicket.getTicket().getRealm();
        KerberosPrincipal server = new KerberosPrincipal(serverName, serverPrinc.getNameType().getValue());

        TicketFlags ticketFlags = encKdcRepPart.getFlags();
        boolean[] flags = ticketFlagsToBooleans(ticketFlags);

        Date authTime = new Date(encKdcRepPart.getAuthTime().getTime());
        Date startTime = new Date(encKdcRepPart.getStartTime().getTime());
        Date endTime = new Date(encKdcRepPart.getEndTime().getTime());
        Date renewTill = new Date(encKdcRepPart.getRenewTill().getTime());

        InetAddress[] clientAddresses = null;
        List<HostAddress> hostAddresses = encKdcRepPart.getCaddr().getElements();
        if (hostAddresses != null) {
            int i = 0;
            clientAddresses = new InetAddress[hostAddresses.size()];
            for (HostAddress hostAddr : hostAddresses) {
                try {
                    InetAddress iAddr = InetAddress.getByAddress(hostAddr.getAddress());
                    clientAddresses[i++] = iAddr;
                } catch (UnknownHostException e) {
                    throw new GSSException(GSSException.FAILURE, -1, "Bad client address");
                }
            }
        }

        KerberosTicket ticket = new KerberosTicket(
                asn1Encoding,
                client,
                server,
                sessionKey,
                keyType,
                flags,
                authTime,
                startTime,
                endTime,
                renewTill,
                clientAddresses
        );
        return ticket;
    }

    public static KrbClientBase getKrbClient() {
        KrbClientBase client;
        try {
            File confSpecified = new File(getSystemProperty("java.security.krb5.conf"));
            if (confSpecified != null) {
                client = new KrbClientBase(confSpecified);
            } else {
                client = new KrbClientBase();   // get configure file from environment variable or default path
            }

            return client;
        } catch (KrbException e) {
            return null;
        }
    }

    public static EncryptionKey[] convertKerberosKeyToEncryptionKey(KerberosKey[] krbKeys) {
        if (krbKeys == null) {
            return null;
        }
        EncryptionKey[] keys = new EncryptionKey[krbKeys.length];
        int i = 0;
        for (KerberosKey krbKey : krbKeys) {
            keys[i++] = new EncryptionKey(krbKey.getKeyType(), krbKey.getEncoded());
        }
        return keys;
    }

    /**
     * Filter out an appropriate KerberosKey from krbKeys and generate a
     * EncryptionKey accordingly
     *
     * @param krbKeys
     * @param encType
     * @param kvno
     * @return
     */
    public static EncryptionKey getEncryptionKey(KerberosKey[] krbKeys, int encType, int kvno) {
        if (krbKeys == null) {
            return null;
        }
        for (KerberosKey krbKey : krbKeys) {
            if (krbKey.getKeyType() == encType && krbKey.getVersionNumber() == kvno && !krbKey.isDestroyed()) {
                return new EncryptionKey(krbKey.getKeyType(), krbKey.getEncoded());
            }
        }
        return null;
    }

    /**
     * Get value of predefined system property
     * @param name
     * @return
     */
    private static String getSystemProperty(String name) {
        if (name == null) {
            return null;
        }

        final String propertyName = name;
        try {
            return AccessController.doPrivileged(
                    new PrivilegedExceptionAction<String>() {
                        public String run() {
                            return System.getProperty(propertyName);
                        }
                    });
        } catch (PrivilegedActionException e) {
            return null;    // ignored
        }
    }

    public static com.sun.security.jgss.AuthorizationDataEntry[]
    kerbyAuthorizationDataToJgssAuthorizationDataEntries(AuthorizationData authData) {
        if (authData == null) {
            return null;
        }
        List<AuthorizationDataEntry> kerbyEntries = authData.getElements();
        com.sun.security.jgss.AuthorizationDataEntry[] entries =
                new com.sun.security.jgss.AuthorizationDataEntry[kerbyEntries.size()];
        for (int i = 0; i < kerbyEntries.size(); i++) {
            entries[i] = new com.sun.security.jgss.AuthorizationDataEntry(
                    kerbyEntries.get(i).getAuthzType().getValue(),
                    kerbyEntries.get(i).getAuthzData());
        }
        return entries;
    }
}
