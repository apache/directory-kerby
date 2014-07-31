package org.haox.kerb.codec.kerberos;

import org.haox.asn1.Asn1InputBuffer;
import org.haox.asn1.type.Asn1Item;
import org.haox.kerb.spec.type.common.EncryptionKey;

import java.io.IOException;

public class KerberosToken {

    private KerberosApRequest apRequest;

    public KerberosToken(byte[] token) throws Exception {
        this(token, null);
    }

    public KerberosToken(byte[] token, EncryptionKey key) throws Exception {

        if(token.length <= 0)
            throw new IOException("kerberos.token.empty");

        Asn1InputBuffer buffer = new Asn1InputBuffer(token);

        Asn1Item value = (Asn1Item) buffer.read();
        if(! value.isAppSpecific() && ! value.isConstructed())
            throw new IOException("kerberos.token.malformed");

        buffer = new Asn1InputBuffer(value.getBodyContent());
        buffer.skipNext();

        buffer.skipBytes(2);

        apRequest = new KerberosApRequest(buffer.readAllLeftBytes(), key);
    }

    public KerberosApRequest getApRequest() {
        return apRequest;
    }
}
