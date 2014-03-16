package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.common.AuthorizationData;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.LoginException;
import java.security.GeneralSecurityException;

public class KerberosTicket2 {
    private String serverPrincipalName;
    private String serverRealm;
    private Ticket ticket;

    public KerberosTicket2(Ticket ticket, ApOptions apOptions, KerberosKey[] keys)
            throws DecodingException, KrbException {
        this.ticket = ticket;

        EncryptionType etype = ticket.getEncryptedEncPart().getEType();
        byte[] crypt = ticket.getEncryptedEncPart().getCipher();

        if(keys == null) {
            try {
                keys = new KerberosCredentials().getKeys();
            } catch(LoginException e) {
                throw new DecodingException("kerberos.login.fail", null, e);
            }
        }

        KerberosKey serverKey = null;
        for(KerberosKey key : keys) {
            if(key.getKeyType() == etype.getValue())
                serverKey = key;
        }

        if(serverKey == null) {
            Object[] args = new Object[]{etype.getValue()};
            throw new DecodingException("kerberos.key.notfound", args, null);
        }

        byte[] decrypted = null;
        try {
            decrypted = KerberosEncData.decrypt(crypt, serverKey, serverKey.getKeyType());
            //encData = new KerberosEncData(decrypted, serverKey);
        } catch(GeneralSecurityException e) {
            Object[] args = new Object[]{serverKey.getKeyType()};
            throw new DecodingException("kerberos.decrypt.fail", args, e);
        }

        try {
            EncTicketPart encPart = KrbCodec.decode(decrypted, EncTicketPart.class);
            ticket.setEncPart(encPart);
        } catch (KrbException e) {
            e.printStackTrace();
        }
    }

    public String getUserPrincipalName() throws KrbException {
        return ticket.getEncPart().getCname().getName();
    }

    public String getUserRealm() throws KrbException {
        return ticket.getEncPart().getCrealm();
    }

    public String getServerPrincipalName() throws KrbException {
        return ticket.getSname().getName();
    }

    public String getServerRealm() throws KrbException {
        return ticket.getRealm();
    }

    public AuthorizationData getAuthorizationData() throws KrbException {
        return ticket.getEncPart().getAuthorizationData();
    }

    public Ticket getTicket() {
        return ticket;
    }
}
