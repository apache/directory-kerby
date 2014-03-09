package org.haox.kerb.codec.kerberos;

import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.ap.ApReq;

import javax.security.auth.kerberos.KerberosKey;

public class KerberosApRequest2 {

    private byte apOptions;
    private KerberosTicket ticket;

    public KerberosApRequest2(byte[] token, KerberosKey[] keys) throws DecodingException {
        if(token.length <= 0)
            throw new DecodingException("kerberos.request.empty", null, null);

        try {
            KrbCodec.decode(token, ApReq.class);
        } catch (KrbException e) {
            e.printStackTrace();
        }
    }

    public byte getApOptions() {
        return apOptions;
    }

    public KerberosTicket getTicket() {
        return ticket;
    }
}
