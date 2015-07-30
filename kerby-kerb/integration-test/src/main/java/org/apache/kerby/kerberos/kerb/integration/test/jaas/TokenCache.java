/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.integration.test.jaas;


import org.apache.commons.io.output.FileWriterWithEncoding;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.nio.charset.Charset;

/**
 * This class provides APIs for converting token cache file with token string.
 */
public class TokenCache {
    private static final String DEFAULT_TOKEN_CACHE_PATH = ".tokenauth";
    private static final String TOKEN_CACHE_FILE = ".tokenauth.token";

    /**
     * Obtain token string from token cache file.
     *
     * @param tokenCacheFile The file stored token
     * @return Token string
     */
    public static String readToken(String tokenCacheFile) {
        File cacheFile;

        if (tokenCacheFile != null && !tokenCacheFile.isEmpty()) {
            cacheFile = new File(tokenCacheFile);
            if (!cacheFile.exists()) {
                throw new RuntimeException("Invalid token cache specified: " + tokenCacheFile);
            }
        } else {
            cacheFile = getDefaultTokenCache();
            if (!cacheFile.exists()) {
                throw new RuntimeException("No token cache available by default");
            }
        }

        String token = null;
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(cacheFile), Charset.forName("UTF-8")));
            String line = reader.readLine();
            reader.close();
            if (line != null) {
                token = line;
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        return token;
    }

    /**
     * Write the token string to token cache file.
     *
     * @param token The token string
     */
    public static void writeToken(String token) {
        File cacheFile = getDefaultTokenCache();

        try {
            Writer writer = new FileWriterWithEncoding(cacheFile, Charset.forName("UTF-8"));
            writer.write(token);
            writer.flush();
            writer.close();
            // sets read-write permissions to owner only
            cacheFile.setReadable(false, false);
            cacheFile.setReadable(true, true);
            if (!cacheFile.setWritable(true, true)) {
                throw new KrbException("Cache file is not readable.");
            }
        } catch (IOException ioe) {
            // if case of any error we just delete the cache, if user-only
            // write permissions are not properly set a security exception
            // is thrown and the file will be deleted.
            if (cacheFile.delete()) {
                System.err.println("Cache file is deleted.");
            }
        } catch (KrbException e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the default token cache.
     *
     * @return  The default token cache
     */
    public static File getDefaultTokenCache() {
        String homeDir = System.getProperty("user.home", DEFAULT_TOKEN_CACHE_PATH);
        return new File(homeDir, TOKEN_CACHE_FILE);
    }
}
