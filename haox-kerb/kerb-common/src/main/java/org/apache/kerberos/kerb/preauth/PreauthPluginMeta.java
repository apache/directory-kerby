package org.apache.kerberos.kerb.preauth;

import org.apache.kerberos.kerb.spec.pa.PaDataType;

public interface PreauthPluginMeta {

    public String getName();

    public int getVersion();

    public PaDataType[] getPaTypes();

}
