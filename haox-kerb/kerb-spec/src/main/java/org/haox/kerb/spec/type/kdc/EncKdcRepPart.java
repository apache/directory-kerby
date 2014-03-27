package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.TicketFlags;

/**
 EncKDCRepPart   ::= SEQUENCE {
 key             [0] EncryptionKey,
 last-req        [1] LastReq,
 nonce           [2] UInt32,
 key-expiration  [3] KrbTime OPTIONAL,
 flags           [4] TicketFlags,
 authtime        [5] KrbTime,
 starttime       [6] KrbTime OPTIONAL,
 endtime         [7] KrbTime,
 renew-till      [8] KrbTime OPTIONAL,
 srealm          [9] Realm,
 sname           [10] PrincipalName,
 caddr           [11] HostAddresses OPTIONAL
 }
 */
public interface EncKdcRepPart extends SequenceType {
    public static enum Tag implements KrbTag {
        KEY(0, EncryptionKey.class),
        LAST_REQ(1, LastReq.class),
        NONCE(2, KrbInteger.class),
        KEY_EXPIRATION(3, KrbTime.class),
        FLAGS(4, TicketFlags.class),
        AUTHTIME(5, KrbTime.class),
        STARTTIME(6, KrbTime.class),
        ENDTIME(7, KrbTime.class),
        RENEW_TILL(8, KrbTime.class),
        SREALM(9, KrbString.class),
        SNAME(10, PrincipalName.class),
        CADDR(11, HostAddresses.class);

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
            return value - 1;
        }

        @Override
        public Class<? extends KrbType> getType() {
            return type;
        }
    };


    public EncryptionKey getKey();

    public void setKey(EncryptionKey key);

    public LastReq getLastReq();

    public void setLastReq(LastReq lastReq);

    public int getNonce();

    public void setNonce(int nonce);

    public KrbTime getKeyExpiration();

    public void setKeyExpiration(KrbTime keyExpiration);

    public TicketFlags getFlags();

    public void setFlags(TicketFlags flags);

    public KrbTime getAuthTime();

    public void setAuthTime(KrbTime authTime);

    public KrbTime getStartTime();

    public void setStartTime(KrbTime startTime);

    public KrbTime getEndTime();

    public void setEndTime(KrbTime endTime);

    public KrbTime getRenewTill();

    public void setRenewTill(KrbTime renewTill);

    public String getSrealm();

    public void setSrealm(String srealm);

    public PrincipalName getSname();

    public void setSname(PrincipalName sname);

    public HostAddresses getCaddr();

    public void setCaddr(HostAddresses caddr);
}
