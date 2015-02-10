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
package org.apache.kerby.kerberos.kerb.client.preauth;

import java.util.ArrayList;
import java.util.List;

public class UserResponser {

    private final List<UserResponseItem> items = new ArrayList<UserResponseItem>(1);

    /**
     * Let customize an interface like CMD or WEB UI to selectively respond all the questions
     */
    public void respondQuestions() {
        // TODO
    }

    public UserResponseItem findQuestion(String question) {
        for (UserResponseItem ri : items) {
            if (ri.question.equals(question)) {
                return ri;
            }
        }
        return null;
    }

    public void askQuestion(String question, String challenge) {
        UserResponseItem ri = findQuestion(question);
        if (ri == null) {
            items.add(new UserResponseItem(question, challenge));
        } else {
            ri.challenge = challenge;
        }
    }

    public String getChallenge(String question) {
        UserResponseItem ri = findQuestion(question);
        if (ri != null) {
            return ri.challenge;
        }
        return null;
    }

    public void setAnswer(String question, String answer) {
        UserResponseItem ri = findQuestion(question);
        if (ri == null) {
            throw new IllegalArgumentException("Question isn't exist for the answer");
        }
        ri.answer = answer;
    }

    public String getAnswer(String question) {
        UserResponseItem ri = findQuestion(question);
        if (ri != null) {
            return ri.answer;
        }
        return null;
    }
}
