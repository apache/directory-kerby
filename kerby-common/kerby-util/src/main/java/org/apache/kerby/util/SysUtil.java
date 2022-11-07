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
package org.apache.kerby.util;

import java.io.File;

/**
 * A system related utility.
 */
public final class SysUtil {
    private SysUtil() { }

    public static File getTempDir() {
        String tmpDir = System.getProperty("java.io.tmpdir");
        return new File(tmpDir);
    }

  /**
   * A public static variable to indicate the current java vendor is
   * IBM and the type is Java Technology Edition which provides its
   * own implementations of many security packages and Cipher suites.
   * Note that these are not provided in Semeru runtimes:
   * See https://developer.ibm.com/languages/java/semeru-runtimes/
   * The class used is present in any supported IBM JTE Runtimes.
   */
  public static final boolean IBM_JAVA = shouldUseIbmSecurity();

  private static boolean shouldUseIbmSecurity() {
    if (!System.getProperty("java.vendor").contains("IBM")) {
      return false;
    }

    try {
      Class.forName("com.ibm.security.auth.module.JAASLoginModule",
        false,
        SysUtil.class.getClassLoader());
      return true;
    } catch (Exception ignored) { }

    return false;
  }

}
