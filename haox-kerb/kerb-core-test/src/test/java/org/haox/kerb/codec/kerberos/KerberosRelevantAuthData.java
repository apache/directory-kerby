package org.haox.kerb.codec.kerberos;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.DecodingException;
import org.haox.kerb.codec.DecodingUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class KerberosRelevantAuthData extends KerberosAuthData {

    private List<KerberosAuthData> authorizations;

    public KerberosRelevantAuthData(byte[] token, Key key) throws DecodingException {
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(token));
        ASN1Sequence authSequence;
        try {
            authSequence = DecodingUtil.as(ASN1Sequence.class, stream);
            stream.close();
        } catch(IOException e) {
            throw new DecodingException("kerberos.ticket.malformed", null, e);
        }

        authorizations = new ArrayList<KerberosAuthData>();
        Enumeration<?> authElements = authSequence.getObjects();
        while(authElements.hasMoreElements()) {
            ASN1Sequence authElement = DecodingUtil.as(ASN1Sequence.class, authElements);
            DERInteger authType = DecodingUtil.as(DERInteger.class, DecodingUtil.as(
                    DERTaggedObject.class, authElement, 0));
            DEROctetString authData = DecodingUtil.as(DEROctetString.class, DecodingUtil.as(
                    DERTaggedObject.class, authElement, 1));

            authorizations.addAll(KerberosAuthData.parse(authType.getValue().intValue(), authData
                    .getOctets(), key));
        }
    }

    public List<KerberosAuthData> getAuthorizations() {
        return authorizations;
    }

}
