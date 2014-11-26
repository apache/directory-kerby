package org.haox.kerb.client.preauth;

import java.util.ArrayList;
import java.util.List;

public class ResponseItems {

    private List<ResponseItem> items = new ArrayList<ResponseItem>(1);

    public ResponseItem findQuestion(String question) {
        for (ResponseItem ri : items) {
            if (ri.question.equals(question)) {
                return ri;
            }
        }
        return null;
    }

    public void askQuestion(String question, String challenge) {
        ResponseItem ri = findQuestion(question);
        if (ri == null) {
            items.add(new ResponseItem(question, challenge));
        } else {
            ri.challenge = challenge;
        }
    }

    public String getChallenge(String question) {
        ResponseItem ri = findQuestion(question);
        if (ri != null) {
            return ri.challenge;
        }
        return null;
    }

    public void setAnswer(String question, String answer) {
        ResponseItem ri = findQuestion(question);
        if (ri == null) {
            throw new IllegalArgumentException("Question isn't exist for the answer");
        }
        ri.answer = answer;
    }

    public String getAnswer(String question) {
        ResponseItem ri = findQuestion(question);
        if (ri != null) {
            return ri.answer;
        }
        return null;
    }
}
