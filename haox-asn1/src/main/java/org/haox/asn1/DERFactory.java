package org.haox.asn1;

public class DERFactory
{
    static final ASN1Sequence EMPTY_SEQUENCE = new DERSequence();
    static final ASN1Set EMPTY_SET = new DERSet();

    public static ASN1Sequence createSequence(ASN1EncodableVector v)
    {
        return v.size() < 1 ? EMPTY_SEQUENCE : new DLSequence(v);
    }

    public static ASN1Set createSet(ASN1EncodableVector v)
    {
        return v.size() < 1 ? EMPTY_SET : new DLSet(v);
    }
}
