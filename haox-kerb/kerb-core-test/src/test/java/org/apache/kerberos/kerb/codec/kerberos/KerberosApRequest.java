package org.apache.kerberos.kerb.codec.kerberos;


import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.spec.ap.ApOptions;
import org.apache.kerberos.kerb.spec.ap.ApReq;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;

import java.io.IOException;

public class KerberosApRequest {
    private ApReq apReq;
    private KerberosTicket ticket;

    public KerberosApRequest(byte[] token, EncryptionKey key) throws Exception {
        if(token.length <= 0) {
            throw new IOException("kerberos request empty");
        }

        apReq = KrbCodec.decode(token, ApReq.class);
        ticket = new KerberosTicket(apReq.getTicket(), apReq.getApOptions(), key);
    }

    public ApOptions getApOptions() throws KrbException {
        return apReq.getApOptions();
    }

    public KerberosTicket getTicket() {
        return ticket;
    }
}
