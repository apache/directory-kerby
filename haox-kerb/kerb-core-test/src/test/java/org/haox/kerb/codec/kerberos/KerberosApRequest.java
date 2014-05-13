package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;

import javax.security.auth.kerberos.KerberosKey;

public class KerberosApRequest {
    private ApReq apReq;
    private KerberosTicket ticket;

    public KerberosApRequest(byte[] token, KerberosKey[] keys) throws DecodingException {
        if(token.length <= 0)
            throw new DecodingException("kerberos.request.empty", null, null);

        try {
            apReq = KrbCodec.decode(token, ApReq.class);
            ticket = new KerberosTicket(apReq.getTicket(), apReq.getApOptions(), keys);
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
