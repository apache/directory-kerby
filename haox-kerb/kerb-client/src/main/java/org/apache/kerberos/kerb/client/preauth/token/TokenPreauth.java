package org.apache.kerberos.kerb.client.preauth.token;

import org.apache.kerberos.kerb.client.KrbContext;
import org.apache.kerberos.kerb.client.KrbOption;
import org.apache.kerberos.kerb.client.KrbOptions;
import org.apache.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerberos.kerb.preauth.PaFlag;
import org.apache.kerberos.kerb.preauth.PaFlags;
import org.apache.kerberos.kerb.preauth.token.TokenPreauthMeta;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
import org.haox.token.KerbToken;

import java.util.Collections;
import java.util.List;

public class TokenPreauth extends AbstractPreauthPlugin {

    private TokenContext tokenContext;

    public TokenPreauth() {
        super(new TokenPreauthMeta());
    }

    public void init(KrbContext context) {
        super.init(context);
        this.tokenContext = new TokenContext();
    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        TokenRequestContext reqCtx = new TokenRequestContext();

        return reqCtx;
    }

    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) {

    }

    @Override
    public List<EncryptionType> getEncTypes(KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KrbOptions options) {

        tokenContext.usingIdToken = options.getBooleanOption(KrbOption.TOKEN_USING_IDTOKEN);
        if (tokenContext.usingIdToken) {
            if (options.contains(KrbOption.TOKEN_USER_ID_TOKEN)) {
                tokenContext.token =
                        (KerbToken) options.getOptionValue(KrbOption.TOKEN_USER_ID_TOKEN);
            }
        } else {
            if (options.contains(KrbOption.TOKEN_USER_AC_TOKEN)) {
                tokenContext.token =
                        (KerbToken) options.getOptionValue(KrbOption.TOKEN_USER_AC_TOKEN);
            }
        }

    }

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException {

        return false;
    }

    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaDataType preauthType,
                         PaData errPadata,
                         PaData outPadata) {
        return false;
    }

    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }
}
