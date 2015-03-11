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
package org.apache.kerby.token;

import java.io.*;

public class TokenCache {
    private static final String DEFAULT_TOKEN_CACHE_PATH = ".tokenauth";
    private static final String TOKEN_CACHE_FILE = ".tokenauth.token";

    public static String readToken(String tokenCacheFile) {
        File cacheFile = null;

        if (tokenCacheFile != null && ! tokenCacheFile.isEmpty()) {
            cacheFile = new File(tokenCacheFile);
            if (!cacheFile.exists()) {
                throw new RuntimeException("Invalid token cache specified: " + tokenCacheFile);
            };
        } else {
            cacheFile = getDefaultTokenCache();
            if (!cacheFile.exists()) {
                throw new RuntimeException("No token cache available by default");
            };
        }

        String token = null;
        try {
            BufferedReader reader = new BufferedReader(new FileReader(cacheFile));
            String line = reader.readLine();
            reader.close();
            if (line != null) {
                token = line;
            }
        } catch (IOException ex) {
            //NOP
        }

        return token;
    }

    public static void writeToken(String token) {
        File cacheFile = getDefaultTokenCache();

        try {
            Writer writer = new FileWriter(cacheFile);
            writer.write(token.toString());
            writer.close();
            // sets read-write permissions to owner only
            cacheFile.setReadable(false, false);
            cacheFile.setReadable(true, true);
            cacheFile.setWritable(true, true);
        }
        catch (IOException ioe) {
            // if case of any error we just delete the cache, if user-only
            // write permissions are not properly set a security exception
            // is thrown and the file will be deleted.
            cacheFile.delete();
        }
    }

    public static File getDefaultTokenCache() {
        String homeDir = System.getProperty("user.home", DEFAULT_TOKEN_CACHE_PATH);
        return new File(homeDir, TOKEN_CACHE_FILE);
    }
}
