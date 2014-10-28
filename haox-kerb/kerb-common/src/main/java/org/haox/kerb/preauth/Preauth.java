package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

public interface Preauth {

    public String getName();

    public int getVersion();

    public PaDataType[] getPaTypes();

}
