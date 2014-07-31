package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.common.EncryptionKey;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;

public class KerberosApRequest {
    private ApReq apReq;
    private KerberosTicket ticket;

    public KerberosApRequest(byte[] token, EncryptionKey key) throws IOException {
        if(token.length <= 0)
            throw new IOException("kerberos.request.empty");

        try {
            apReq = KrbCodec.decode(token, ApReq.class);
            ticket = new KerberosTicket(apReq.getTicket(), apReq.getApOptions(), key);
        } catch (KrbException e) {
            e.printStackTrace();
        }
    }

    public ApOptions getApOptions() throws KrbException {
        return apReq.getApOptions();
    }

    public KerberosTicket getTicket() {
        return ticket;
    }
}
