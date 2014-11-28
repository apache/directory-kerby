package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PreauthPluginMeta;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class AbstractPreauthPlugin implements KdcPreauth {

    private PreauthPluginMeta pluginMeta;
    protected KdcContext kdcContext;

    public AbstractPreauthPlugin(PreauthPluginMeta meta) {
        this.pluginMeta = meta;
    }

    @Override
    public String getName() {
        return pluginMeta.getName();
    }

    public int getVersion() {
        return pluginMeta.getVersion();
    }

    public PaDataType[] getPaTypes() {
        return pluginMeta.getPaTypes();
    }

    public void init(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
    }

    @Override
    public void provideEData(PreauthContext preauthContext) throws KrbException {

    }

    @Override
    public void verify(PreauthContext preauthContext, PaDataEntry paData) throws KrbException {

    }

    @Override
    public void providePaData(PreauthContext preauthContext, PaData paData) {

    }

    @Override
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType) {
        return null;
    }

    @Override
    public void destroy() {

    }
}
