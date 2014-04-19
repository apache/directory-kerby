package org.haox.kerb.spec.type.kdc;

/**
EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
*/
public class EncAsRepPart extends EncKdcRepPart {
    public static final int TAG = 25;

    public EncAsRepPart() {
        super(TAG);
    }
}
