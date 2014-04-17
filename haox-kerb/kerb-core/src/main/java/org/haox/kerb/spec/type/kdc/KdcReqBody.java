package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Tickets;

import java.util.Set;

/**
 KDC-REQ-BODY    ::= SEQUENCE {
 kdc-options             [0] KDCOptions,
 cname                   [1] PrincipalName OPTIONAL
 -- Used only in AS-REQ --,
 realm                   [2] Realm
 -- Server's realm
 -- Also client's in AS-REQ --,
 sname                   [3] PrincipalName OPTIONAL,
 from                    [4] KrbTime OPTIONAL,
 till                    [5] KrbTime,
 rtime                   [6] KrbTime OPTIONAL,
 nonce                   [7] UInt32,
 etype                   [8] SEQUENCE OF Int32 -- EncryptionType
 -- in preference order --,
 addresses               [9] HostAddresses OPTIONAL,
 enc-authorization-data  [10] EncryptedData OPTIONAL
 -- AuthorizationData --,
 additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
 -- NOTE: not empty
 }
 */
public interface KdcReqBody extends SequenceType {
    public static enum Tag implements KrbTag {
        KDC_OPTIONS(0, KdcOptions.class),
        CNAME(1, PrincipalName.class),
        REALM(2, KrbString.class),
        SNAME(3, PrincipalName.class),
        FROM(4, KrbTime.class),
        TILL(5, KrbTime.class),
        RTIME(6, KrbTime.class),
        NONCE(7, KrbInteger.class),
        ETYPE(8, KrbIntegers.class),
        ADDRESSES(9, HostAddresses.class),
        ENC_AUTHORIZATION_DATA(10, AuthorizationData.class),
        ADDITIONAL_TICKETS(11, Tickets.class);

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

    public KdcOptions getKdcOptions() throws KrbException;

    public void setKdcOptions(KdcOptions kdcOptions) throws KrbException;

    public PrincipalName getCname() throws KrbException;

    public void setCname(PrincipalName cname) throws KrbException;

    public String getRealm() throws KrbException;

    public void setRealm(String realm) throws KrbException;

    public PrincipalName getSname() throws KrbException;

    public void setSname(PrincipalName sname) throws KrbException;

    public KrbTime getFrom() throws KrbException;

    public void setFrom(KrbTime from) throws KrbException;

    public KrbTime getTill() throws KrbException;

    public void setTill(KrbTime till) throws KrbException;

    public KrbTime getRtime() throws KrbException;

    public void setRtime(KrbTime rtime) throws KrbException;

    public int getNonce();

    public void setNonce(int nonce);

    public Set<EncryptionType> getEtype();

    public void setEtype(Set<EncryptionType> etype);

    public HostAddresses getAddresses();

    public void setAddresses(HostAddresses addresses);

    public EncryptedData getEncryptedAuthorizationData() throws KrbException;

    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) throws KrbException;

    public AuthorizationData getAuthorizationData();

    public void setAuthorizationData(AuthorizationData encAuthorizationData);

    public Tickets getAdditionalTickets() throws KrbException;

    public void setAdditionalTickets(Tickets additionalTickets) throws KrbException;
}
