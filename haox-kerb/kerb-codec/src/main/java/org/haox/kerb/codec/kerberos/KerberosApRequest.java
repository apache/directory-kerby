package org.haox.kerb.codec.kerberos;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.DecodingUtil;

import javax.security.auth.kerberos.KerberosKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public class KerberosApRequest {

    private byte apOptions;
    private KerberosTicket ticket;

    public KerberosApRequest(byte[] token, KerberosKey[] keys) throws DecodingException {
        if(token.length <= 0)
            throw new DecodingException("kerberos.request.empty", null, null);

        ASN1Sequence sequence;
        try {
            ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
            sequence = DecodingUtil.as(ASN1Sequence.class, stream);
            stream.close();
        } catch(IOException e) {
            throw new DecodingException("kerberos.ticket.malformed", null, e);
        }

        Enumeration<?> fields = sequence.getObjects();
        while(fields.hasMoreElements()) {
            ASN1TaggedObject tagged = DecodingUtil.as(ASN1TaggedObject.class, fields.nextElement());
            switch (tagged.getTagNo()) {
            case 0:
                DERInteger pvno = DecodingUtil.as(DERInteger.class, tagged);
                if(!pvno.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_VERSION))) {
                    Object[] args = new Object[]{KerberosConstants.KERBEROS_VERSION, pvno};
                    throw new DecodingException("kerberos.version.invalid", args, null);
                }
                break;
            case 1:
                DERInteger msgType = DecodingUtil.as(DERInteger.class, tagged);
                if(!msgType.getValue().equals(new BigInteger(KerberosConstants.KERBEROS_AP_REQ)))
                    throw new DecodingException("kerberos.request.invalid", null, null);
                break;
            case 2:
                DERBitString bitString = DecodingUtil.as(DERBitString.class, tagged);
                apOptions = bitString.getBytes()[0];
                break;
            case 3:
                DERApplicationSpecific derTicket = DecodingUtil.as(DERApplicationSpecific.class,
                        tagged);
                if(!derTicket.isConstructed())
                    throw new DecodingException("kerberos.ticket.malformed", null, null);
                ticket = new KerberosTicket(derTicket.getContents(), apOptions, keys);
                break;
            case 4:
                // Let's ignore this for now
                break;
            default:
                Object[] args = new Object[]{tagged.getTagNo()};
                throw new DecodingException("kerberos.field.invalid", args, null);
            }
        }
    }

    public byte getApOptions() {
        return apOptions;
    }

    public KerberosTicket getTicket() {
        return ticket;
    }
}
