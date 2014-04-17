package org.haox.kerb.spec.type.ap;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Ticket;

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
public class AuthenticatorImpl extends AbstractSequenceType implements Authenticator {
    public int getAuthenticatorVno() throws KrbException {
        KrbInteger value = getFieldAs(Tag.AUTHENTICATOR_VNO, KrbInteger.class);
        if (value != null) {
            return value.getValue().intValue();
        }
        return -1;
    }

    public void setAuthenticatorVno(int authenticatorVno) throws KrbException {
        setField(Tag.AUTHENTICATOR_VNO, KrbTypes.makeInteger(authenticatorVno));
    }

    public String getCrealm() throws KrbException {
        KrbString value = getFieldAs(Tag.CREALM, KrbString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    public void setCrealm(String crealm) throws KrbException {
        setField(Tag.CREALM, KrbTypes.makeString(crealm));
    }

    public PrincipalName getCname() throws KrbException {
        return getFieldAs(Tag.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) throws KrbException {
        setField(Tag.CNAME, cname);
    }

    public Checksum getCksum() throws KrbException {
        return getFieldAs(Tag.CKSUM, Checksum.class);
    }

    public void setCksum(Checksum cksum) throws KrbException {
        setField(Tag.CKSUM, cksum);
    }

    public int getCusec() throws KrbException {
        KrbInteger value = getFieldAs(Tag.CUSEC, KrbInteger.class);
        return value.getValue().intValue();
    }

    public void setCusec(int cusec) throws KrbException {
        setField(Tag.CUSEC, KrbTypes.makeInteger(cusec));
    }

    public KrbTime getCtime() throws KrbException {
        KrbInteger value = getFieldAs(Tag.CTIME, KrbInteger.class);
        return KrbTypes.makeTime(value.getValue().intValue());
    }

    public void setCtime(KrbTime ctime) throws KrbException {
        setField(Tag.CTIME, ctime);
    }

    public EncryptionKey getSubKey() throws KrbException {
        return getFieldAs(Tag.SUBKEY, EncryptionKey.class);
    }

    public void setSubKey(EncryptionKey subKey) throws KrbException {
        setField(Tag.SUBKEY, subKey);
    }

    public Integer getSeqNumber() throws KrbException {
        KrbInteger value = getFieldAs(Tag.SEQ_NUMBER, KrbInteger.class);
        return value.getValue().intValue();
    }

    public void setSeqNumber(Integer seqNumber) throws KrbException {
        setField(Tag.SEQ_NUMBER, KrbTypes.makeInteger(seqNumber));
    }

    public AuthorizationData getAuthorizationData() throws KrbException {
        return getFieldAs(Tag.AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) throws KrbException {
        setField(Tag.AUTHORIZATION_DATA, authorizationData);
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
