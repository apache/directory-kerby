package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbFlags;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.ticket.Ticket;
import sun.security.krb5.internal.APOptions;

/**
 AP-REQ          ::= [APPLICATION 14] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (14),
 ap-options      [2] APOptions,
 ticket          [3] Ticket,
 authenticator   [4] EncryptedData -- Authenticator
 }
 */
public interface ApReq extends KrbMessage {
    public static enum Tag implements KrbTag {
        PVNO(0, KrbInteger.class),
        MSG_TYPE(1, KrbInteger.class),
        AP_OPTIONS(2, ApOptions.class),
        TICKET(3, Ticket.class),
        AUTHENTICATOR(4, Authenticator.class);

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

    public ApOptions getApOptions() throws KrbException;

    public void setApOptions(ApOptions apOptions) throws KrbException;

    public Ticket getTicket() throws KrbException;

    public void setTicket(Ticket ticket) throws KrbException;

    public Authenticator getAuthenticator();

    public void setAuthenticator(Authenticator authenticator);

    public EncryptedData getEncryptedAuthenticator() throws KrbException;

    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) throws KrbException;
}

