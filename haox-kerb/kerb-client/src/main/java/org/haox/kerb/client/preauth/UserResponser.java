package org.haox.kerb.client.preauth;

import java.util.ArrayList;
import java.util.List;

public class UserResponser {

    private List<UserResponseItem> items = new ArrayList<UserResponseItem>(1);

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
