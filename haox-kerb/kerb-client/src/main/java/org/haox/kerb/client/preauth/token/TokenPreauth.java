package org.haox.kerb.client.preauth.token;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.AbstractPreauthPlugin;
import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.token.TokenPreauthMeta;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
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
    public PluginRequestContext initRequestContext(KrbContext krbContext,
                                                    KdcRequest kdcRequest) {
        TokenRequestContext reqCtx = new TokenRequestContext();

        return reqCtx;
    }

    @Override
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) {

    }

    @Override
    public List<EncryptionType> getEncTypes(KrbContext krbContext,
                                            KdcRequest kdcRequest,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KrbContext krbContext,
                                  KdcRequest kdcRequest,
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

    public void tryFirst(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KrbContext krbContext,
                        KdcRequest kdcRequest,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException {

        return false;
    }

    @Override
    public boolean tryAgain(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaDataType preauthType,
                         PaData errPadata,
                         PaData outPadata) {
        return false;
    }

    @Override
    public PaFlags getFlags(KrbContext krbContext,
                            PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    @Override
    public void destroy(KrbContext krbContext) {

    }

}
