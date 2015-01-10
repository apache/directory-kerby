package org.apache.kerberos.kerb.spec.kdc;

/**
EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
*/
public class EncAsRepPart extends EncKdcRepPart {
    public static final int TAG = 25;

    public EncAsRepPart() {
        super(TAG);
    }
}
