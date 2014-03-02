package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.*;

/**
 Authenticator   ::= [APPLICATION 2] SEQUENCE  {
 authenticator-vno       [0] INTEGER (5),
 crealm                  [1] Realm,
 cname                   [2] PrincipalName,
 cksum                   [3] Checksum OPTIONAL,
 cusec                   [4] Microseconds,
 ctime                   [5] KrbTime,
 subkey                  [6] EncryptionKey OPTIONAL,
 seq-number              [7] UInt32 OPTIONAL,
 authorization-data      [8] AuthorizationData OPTIONAL
 }
 */
public interface Authenticator extends SequenceType {
    public static enum Tag implements KrbTag {
        AUTHENTICATOR_VNO(0, KrbInteger.class),
        CREALM(1, KrbString.class),
        CNAME(2, PrincipalName.class),
        CKSUM(3, Checksum.class),
        CUSEC(4, KrbInteger.class),
        CTIME(5, KrbTime.class),
        SUBKEY(6, EncryptionKey.class),
        SEQ_NUMBER(7, KrbInteger.class),
        AUTHORIZATION_DATA(8, AuthorizationData.class);

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

    public int getAuthenticatorVno();

    public void setAuthenticatorVno(int authenticatorVno);

    public String getCrealm();

    public void setCrealm(String crealm);

    public PrincipalName getCname();

    public void setCname(PrincipalName cname);

    public Checksum getCksum();

    public void setCksum(Checksum cksum);

    public int getCusec();

    public void setCusec(int cusec);

    public KrbTime getCtime();

    public void setCtime(KrbTime ctime);

    public EncryptionKey getSubKey();

    public void setSubKey(EncryptionKey subKey);

    public Integer getSeqNumber();

    public void setSeqNumber(Integer seqNumber);

    public AuthorizationData getAuthorizationData();

    public void setAuthorizationData(AuthorizationData authorizationData);
}
