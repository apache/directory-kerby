package org.apache.kerberos.kerb.server.preauth;

import org.apache.kerberos.kerb.preauth.PaFlags;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.PreauthPluginMeta;
import org.apache.kerberos.kerb.server.KdcContext;
import org.apache.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class AbstractPreauthPlugin implements KdcPreauth {

    private PreauthPluginMeta pluginMeta;

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

    @Override
    public void initWith(KdcContext kdcContext) {

    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        return null;
    }

    @Override
    public void provideEdata(KdcRequest kdcRequest, PluginRequestContext requestContext,
            PaData outPaData) throws KrbException {

    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {
        return false;
    }

    @Override
    public void providePaData(KdcRequest kdcRequest, PluginRequestContext requestContext,
                              PaData paData) {

    }

    @Override
    public PaFlags getFlags(KdcRequest kdcRequest, PluginRequestContext requestContext,
                            PaDataType paType) {
        return null;
    }

    @Override
    public void destroy() {

    }
}
