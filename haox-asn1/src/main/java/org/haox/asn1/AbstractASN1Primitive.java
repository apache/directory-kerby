package org.haox.asn1;

import java.io.IOException;

public class AbstractASN1Primitive extends ASN1Primitive
{
    protected AbstractASN1Primitive()
    {

    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    boolean isConstructed() {
        return false;
    }

    @Override
    int encodedLength() throws IOException {
        return 0;
    }

    @Override
    void encode(ASN1OutputStream out) throws IOException {

    }

    @Override
    boolean asn1Equals(ASN1Primitive o) {
        return false;
    }
}