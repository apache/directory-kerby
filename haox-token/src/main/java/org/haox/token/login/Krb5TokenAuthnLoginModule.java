package org.haox.token.login;

import com.sun.security.auth.module.Krb5LoginModule;
import org.haox.token.KerbToken;
import org.haox.token.TokenCache;
import org.haox.token.TokenTool;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * Beside the ones Krb5LoginModule supports, additionally supported configurations for token:
 * useToken: true/false
 * token: your-token-value
 * useDefaultTokenCache: true/false
 * tokenCache: your-token-cache-file
 */
public class Krb5TokenAuthnLoginModule implements LoginModule {
    Krb5LoginModule krb5LoginModule;

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map sharedState;
    private Map<String, ?> options;

    // configurable option
    private boolean useToken = false;
    private boolean useDefaultTokenCache = false;
    private String tokenCacheName = null;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;

    private String token = null;
    private File ccacheFile;
    private static final String TOKEN = ".tokenauth.token";

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;

        // initialize any configured options
        useToken = "true".equalsIgnoreCase((String)options.get("useToken"));
        token = (String)options.get("token");
        tokenCacheName = (String)options.get("tokenCache");
        useDefaultTokenCache = "true".equalsIgnoreCase((String)options.get
                ("useDefaultTokenCache"));
    }

    @Override
    public boolean login() throws LoginException {
        validateConfiguration();

        Map<String, ?> krbOptions = this.options;
        Map krbSharedState = this.sharedState;

        if (useToken) {
            boolean result = tokenLogin();
            if (! result) {
                return false;
            }

            Map<String, Object> newOptions = new HashMap<String, Object>();
            newOptions.putAll(this.options);
            newOptions.put("useTicketCache", "true");
            newOptions.put("ticketCache", ccacheFile.getAbsolutePath());
            krbOptions = newOptions;

            Map newSharedState = new HashMap();
            newSharedState.putAll(this.sharedState);
            krbSharedState = newSharedState;
        }

        krb5LoginModule = new Krb5LoginModule();
        krb5LoginModule.initialize(subject, null, krbSharedState, krbOptions);
        succeeded = krb5LoginModule.login();

        return succeeded;
    }

    private boolean tokenLogin() throws LoginException {
        doTokenLogin();
        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        boolean result = krb5LoginModule.commit();
        if (result && useToken) {
            try {
                KerbToken krbToken = TokenTool.fromJwtToken(token);
                subject.getPublicCredentials().add(krbToken); // better put in private set?
            } catch (ParseException e) {
                throwWith("Failed to convert from JWT token", e);
            }
        }
        return result;
    }

    @Override
    public boolean abort() throws LoginException {
        return krb5LoginModule.abort();
    }

    @Override
    public boolean logout() throws LoginException {
        return krb5LoginModule.logout();
    }

    private void doTokenLogin() throws LoginException {
        if (token == null) {
            token = TokenCache.readToken(tokenCacheName);
            if (token == null) {
                throw new LoginException("No valid token was found in token cache: " + tokenCacheName);
            }
        }

        try {
            ccacheFile = makeCcacheFile();
        } catch (IOException e) {
            throwWith("Failed to create tmp ccache file", e);
        }

        String[] tokenInitCmd = null;
        if (useDefaultTokenCache && token == null) {
            tokenInitCmd = new String[] {
                    "ktinit.sh", "-c", ccacheFile.getAbsolutePath()
            };
        } else {
            tokenInitCmd = new String[] {
                    "ktinit.sh", "-t", token, "-c", ccacheFile.getAbsolutePath()
            };
        }

        Process proc = null;
        BufferedReader reader;
        try {
            proc = Runtime.getRuntime().exec(tokenInitCmd);
        } catch (IOException e) {
            throwWith("Failed to do token init with token: " + token, e);
        }

        int exitCode = 1;
        reader = new BufferedReader(new InputStreamReader(
                proc.getInputStream()));
        try {
            exitCode = proc.waitFor();
        } catch (InterruptedException e) {
            throwWith("Failed to do token init with token: " + token, e);
        }

        if (exitCode != 0) {
            String errors = "";
            StringBuffer lines = new StringBuffer();
            String line;
            try {
                while (reader.ready()) {
                    line = reader.readLine();
                    lines.append(line).append("\n");
                }
                errors = lines.toString();
            } catch (IOException e) {
                errors = e.getMessage();
            }
            throw new RuntimeException(errors);
        }
    }

    private void validateConfiguration() throws LoginException {
        if (! useToken) return;

        String error = "";
        if (useDefaultTokenCache) {
            if (token != null || tokenCacheName != null) {
                error = "useDefaultTokenCache is specified, but token or tokenCacheName is also specified";
            }
        } else {
            if (token == null && tokenCacheName == null) {
                error = "useToken is specified but no token or token cache is provided";
            } else if (token != null && tokenCacheName != null) {
                error = "either token or token cache should be provided but not both";
            }
        }

        if (! error.isEmpty()) {
            throw new LoginException(error);
        }
    }

    private File makeCcacheFile() throws IOException {
        File ccacheFile = File.createTempFile("/tmp/krb5cc_token", ".tmp");
        ccacheFile.setExecutable(false);
        ccacheFile.setReadable(true);
        ccacheFile.setWritable(true);

        return ccacheFile;
    }

    private void cleanup() {
        if (useToken) {
            if (ccacheFile != null && ccacheFile.exists()) {
                ccacheFile.delete();
            }
        }
    }

    private void throwWith(String error, Exception cause) throws LoginException {
        LoginException le = new LoginException(error);
        le.initCause(cause);
        throw le;
    }
}
