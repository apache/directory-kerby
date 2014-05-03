package org.haox.kerb.codec.kerberos;

import org.haox.asn1.Asn1InputBuffer;
import org.haox.asn1.type.Asn1Item;
import org.haox.kerb.codec.DecodingException;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;

public class KerberosToken {

    private KerberosApRequest apRequest;

    public KerberosToken(byte[] token) throws DecodingException {
        this(token, null);
    }

    public KerberosToken(byte[] token, KerberosKey[] keys) throws DecodingException {

        if(token.length <= 0)
                    throw new DecodingException("kerberos.token.empty", null, null);

        try {
            Asn1InputBuffer buffer = new Asn1InputBuffer(token);

            Asn1Item value = (Asn1Item) buffer.read();
            if(! value.isAppSpecific() && ! value.isConstructed())
                throw new DecodingException("kerberos.token.malformed", null, null);

            buffer = new Asn1InputBuffer(value.getBodyContent());
            buffer.skipNext();

            buffer.skipBytes(2);

            apRequest = new KerberosApRequest(buffer.readAllLeftBytes(), keys);
        } catch(IOException e) {
            throw new DecodingException("kerberos.token.malformed", null, e);
        }
    }

    /*
    public KerberosToken(byte[] token, KerberosKey[] keys) throws DecodingException {

        if(token.length <= 0)
            throw new DecodingException("kerberos.token.empty", null, null);

        try {
            HaoxASN1InputStream.asn1Dump(token, true);
            HaoxASN1InputStream stream = new HaoxASN1InputStream(token);
            HaoxDERApplicationSpecific derToken = DecodingUtil.as(HaoxDERApplicationSpecific.class, stream);
            if(derToken == null || !derToken.isConstructed())
                throw new DecodingException("kerberos.token.malformed", null, null);

            stream = new HaoxASN1InputStream(derToken.getByteBuffer(), derToken.getLimit());
            DERObjectIdentifier kerberosOid = DecodingUtil.as(DERObjectIdentifier.class, stream);
            if(!kerberosOid.getId().equals(KerberosConstants.KERBEROS_OID))
                throw new DecodingException("kerberos.token.invalid", null, null);

            int read = 0;
            int readLow = stream.readByte() & 0xff;
            int readHigh = stream.readByte() & 0xff;
            read = (readHigh << 8) + readLow;
            if(read != 0x01)
                throw new DecodingException("kerberos.token.malformed", null, null);

            HaoxDERApplicationSpecific krbToken = DecodingUtil.as(HaoxDERApplicationSpecific.class, stream);
            if(krbToken == null || !krbToken.isConstructed())
                throw new DecodingException("kerberos.token.malformed", null, null);

            apRequest = new KerberosApRequest(HaoxASN1InputStream.fromByteBuffer(krbToken.getByteBuffer(), krbToken.getLimit()), keys);
        } catch(IOException e) {
            throw new DecodingException("kerberos.token.malformed", null, e);
        }
    }
*/
    public KerberosApRequest getApRequest() {
        return apRequest;
    }
}
