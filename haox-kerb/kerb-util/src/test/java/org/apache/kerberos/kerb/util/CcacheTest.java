package org.apache.kerberos.kerb.util;

import org.apache.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerberos.kerb.spec.common.PrincipalName;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

/*
Default principal: drankye@SH.INTEL.COM

Valid starting       Expires              Service principal
08/05/2014 00:13:17  08/05/2014 10:13:17  krbtgt/SH.INTEL.COM@SH.INTEL.COM
        Flags: FIA, Etype (skey, tkt): des3-cbc-sha1, des3-cbc-sha1
 */
public class CcacheTest {

    private CredentialCache cc;

    @Before
    public void setUp() throws IOException {
        InputStream cis = CcacheTest.class.getResourceAsStream("/test.cc");
        cc = new CredentialCache();
        cc.load(cis);
    }

    @Test
    public void testCc() {
        Assert.assertNotNull(cc);

        PrincipalName princ = cc.getPrimaryPrincipal();
        Assert.assertNotNull(princ);
        Assert.assertTrue(princ.getName().equals("drankye@SH.INTEL.COM"));
    }
}
