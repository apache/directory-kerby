package org.haox.kerb.spec.type.ap;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.AbstractKrbMessage;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.ticket.Ticket;

/**
 AP-REQ          ::= [APPLICATION 14] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (14),
 ap-options      [2] APOptions,
 ticket          [3] Ticket,
 authenticator   [4] EncryptedData -- Authenticator
 }
 */
public class ApReq extends AbstractKrbMessage {
    private static int AP_OPTIONS = 2;
    private static int TICKET = 3;
    private static int AUTHENTICATOR = 4;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, 1, Asn1Integer.class),
            new Asn1FieldInfo(AP_OPTIONS, 2, Ticket.class),
            new Asn1FieldInfo(AUTHENTICATOR, 3, Authenticator.class)
    };

    private Authenticator authenticator;

    public ApReq() throws KrbException {
        super(KrbMessageType.AP_REQ, fieldInfos);
    }

    public ApOptions getApOptions() throws KrbException {
        return getFieldAs(AP_OPTIONS, ApOptions.class);
    }

    public void setApOptions(ApOptions apOptions) throws KrbException {
        setFieldAs(AP_OPTIONS, apOptions);
    }

    public Ticket getTicket() throws KrbException {
        return getFieldAs(TICKET, Ticket.class);
    }

    public void setTicket(Ticket ticket) throws KrbException {
        setFieldAs(TICKET, ticket);
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public EncryptedData getEncryptedAuthenticator() throws KrbException {
        return getFieldAs(AUTHENTICATOR, EncryptedData.class);
    }

    public void setEncryptedAuthenticator(EncryptedData encryptedAuthenticator) throws KrbException {
        setFieldAs(AUTHENTICATOR, encryptedAuthenticator);
    }
}

