/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.server;

import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.http.HttpConfig.Policy;
import org.apache.hadoop.net.NetUtils;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.util.URLConnectionFactory;
import org.apache.kerby.has.server.web.WebConfigKey;
import org.apache.kerby.has.server.web.WebServer;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Collection;

@RunWith(value = Parameterized.class)
public class TestWebServer {
  private static final String KEY_STORE_DIR = TestUtil.getTempPath("keystore");
  private static File keyStoreDir = new File(KEY_STORE_DIR);
  private static HasConfig httpsConf;
  private static URLConnectionFactory connectionFactory;

  @Parameterized.Parameters
  public static Collection<Object[]> policy() {
    Object[][] params = new Object[][]{{Policy.HTTP_ONLY},
        {Policy.HTTPS_ONLY}, {Policy.HTTP_AND_HTTPS}};
    return Arrays.asList(params);
  }

  private final Policy policy;

  public TestWebServer(Policy policy) {
    super();
    this.policy = policy;
  }

  @Before
  public void setUp() throws Exception {
    httpsConf = new HasConfig();
    // Create test keystore dir.
    if (!keyStoreDir.exists() && !keyStoreDir.mkdirs()) {
        System.err.println("Failed to create keystore-dir.");
        System.exit(3);
    }
    String sslConfDir = TestUtil.getClasspathDir(TestWebServer.class);
    TestUtil.setupSSLConfig(KEY_STORE_DIR, sslConfDir, httpsConf, false);
    connectionFactory = URLConnectionFactory.newDefaultURLConnectionFactory(httpsConf);
  }

  @After
  public void tearDown() throws Exception {
    FileUtil.fullyDelete(keyStoreDir);
  }

  @Test
  public void testHttpPolicy() throws Exception {
    httpsConf.setString(WebConfigKey.HAS_HTTP_POLICY_KEY, policy.name());
    httpsConf.setString(WebConfigKey.HAS_HTTP_ADDRESS_KEY, "localhost:11236");
    httpsConf.setString(WebConfigKey.HAS_HTTPS_ADDRESS_KEY, "localhost:19278");
    httpsConf.setString(WebConfigKey.HAS_AUTHENTICATION_FILTER_AUTH_TYPE, "simple");

    WebServer server = null;
    try {
      server = new WebServer(httpsConf);
      server.start();

      Assert.assertTrue(implies(policy.isHttpEnabled(),
          canAccess("http", server.getHttpAddress())));
      Assert.assertTrue(implies(!policy.isHttpEnabled(),
          server.getHttpAddress() == null));

      Assert.assertTrue(implies(policy.isHttpsEnabled(),
          canAccess("https", server.getHttpsAddress())));
      Assert.assertTrue(implies(!policy.isHttpsEnabled(),
          server.getHttpsAddress() == null));
    } finally {
      if (server != null) {
        server.stop();
      }
    }
  }

  private static boolean canAccess(String scheme, InetSocketAddress address) {
    if (address == null) {
      return false;
    }
    try {
      URL url = new URL(scheme + "://" + NetUtils.getHostPortString(address));
      URLConnection conn = connectionFactory.openConnection(url);
      conn.connect();
      conn.getContent();
    } catch (Exception e) {
      return false;
    }
    return true;
  }

  private static boolean implies(boolean a, boolean b) {
    return !a || b;
  }
}
