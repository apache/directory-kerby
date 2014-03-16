package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;

import javax.security.auth.kerberos.KerberosKey;

public class KerberosApRequest2 {
    private ApReq apReq;
    private KerberosTicket2 ticket;

    public KerberosApRequest2(byte[] token, KerberosKey[] keys) throws DecodingException {
        if(token.length <= 0)
            throw new DecodingException("kerberos.request.empty", null, null);

        try {
            apReq = KrbCodec.decode(token, ApReq.class);
            ticket = new KerberosTicket2(apReq.getTicket(), apReq.getApOptions(), keys);
        } catch (KrbException e) {
            e.printStackTrace();
        }
    }

    public ApOptions getApOptions() throws KrbException {
        return apReq.getApOptions();
    }

    public KerberosTicket2 getTicket() {
        return ticket;
    }
}
