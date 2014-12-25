package org.haox.kerb.preauth;

import org.haox.kerb.spec.pa.PaDataType;

public interface PreauthPluginMeta {

    public String getName();

    public int getVersion();

    public PaDataType[] getPaTypes();

}
