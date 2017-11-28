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

package org.apache.kerby.has.common.util;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

import java.util.Locale;

/**
 * General string utils
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class StringUtils {

  /**
   * Converts all of the characters in this String to lower case with
   * Locale.ENGLISH.
   *
   * @param str  string to be converted
   * @return     the str, converted to lowercase.
   */
  public static String toLowerCase(String str) {
    return str.toLowerCase(Locale.ENGLISH);
  }

  /**
   * Converts all of the characters in this String to upper case with
   * Locale.ENGLISH.
   *
   * @param str  string to be converted
   * @return     the str, converted to uppercase.
   */
  public static String toUpperCase(String str) {
    return str.toUpperCase(Locale.ENGLISH);
  }

}
