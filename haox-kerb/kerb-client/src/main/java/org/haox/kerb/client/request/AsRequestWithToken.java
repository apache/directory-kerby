package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.token.KerbToken;

public class AsRequestWithToken extends AsRequest {

    private KerbToken token;

    public AsRequestWithToken(KrbContext context) {
        super(context);
    }

    public void setToken(KerbToken token) {
        this.token = token;
    }

    @Override
    public void process() throws KrbException {
        throw new RuntimeException("To be implemented");
    }

    @Override
    protected KrbOptions getPreauthOptions() {
        KrbOptions results = new KrbOptions();

        KrbOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.TOKEN_USER_ID_TOKEN));

        return results;
    }
}
