package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.*;

/**
 -- Encrypted part of ticket
 EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
 flags                   [0] TicketFlags,
 key                     [1] EncryptionKey,
 crealm                  [2] Realm,
 cname                   [3] PrincipalName,
 transited               [4] TransitedEncoding,
 authtime                [5] KerberosTime,
 starttime               [6] KerberosTime OPTIONAL,
 endtime                 [7] KerberosTime,
 renew-till              [8] KerberosTime OPTIONAL,
 caddr                   [9] HostAddresses OPTIONAL,
 authorization-data      [10] AuthorizationData OPTIONAL
 }
 */
public interface EncTicketPart extends SequenceType {
    public static enum Tag implements KrbTag {
        FLAGS(0, TicketFlags.class),
        KEY(1, EncryptionKey.class),
        CREALM(2, KrbString.class),
        CNAME(3, PrincipalName.class),
        TRANSITED(4, TransitedEncoding.class),
        AUTHTIME(5, KrbTime.class),
        STARTTIME(6, KrbTime.class),
        ENDTIME(7, KrbTime.class),
        RENEW_TILL(8, KrbTime.class),
        CADDR(9, HostAddresses.class),
        AUTHORIZATION_DATA(10, AuthorizationData.class);

        private int value;
        private Class<? extends KrbType> type;

        private Tag(int value, Class<? extends KrbType> type) {
            this.value = value;
            this.type = type;
        }

        @Override
        public int getValue() {
            return value;
        }

        @Override
        public int getIndex() {
            return ordinal();
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };

    public TicketFlags getFlags() throws KrbException;

    public void setFlags(TicketFlags flags) throws KrbException;

    public EncryptionKey getKey() throws KrbException;

    public void setKey(EncryptionKey key) throws KrbException;

    public String getCrealm() throws KrbException;

    public void setCrealm(String crealm) throws KrbException;

    public PrincipalName getCname() throws KrbException;

    public void setCname(PrincipalName cname) throws KrbException;

    public TransitedEncoding getTransited() throws KrbException;

    public void setTransited(TransitedEncoding transited) throws KrbException;

    public KrbTime getAuthTime() throws KrbException;

    public void setAuthTime(KrbTime authTime) throws KrbException;

    public KrbTime getStartTime() throws KrbException;

    public void setStartTime(KrbTime startTime) throws KrbException;

    public KrbTime getEndTime() throws KrbException;

    public void setEndTime(KrbTime endTime) throws KrbException;

    public KrbTime getRenewtill() throws KrbException;

    public void setRenewtill(KrbTime renewtill) throws KrbException;

    public HostAddresses getClientAddresses() throws KrbException;

    public void setClientAddresses(HostAddresses clientAddresses) throws KrbException;

    public AuthorizationData getAuthorizationData() throws KrbException;

    public void setAuthorizationData(AuthorizationData authorizationData) throws KrbException;
}
