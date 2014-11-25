package org.haox.kerb.client.preauth;

public class ResponseItem {
    protected String question;
    protected String challenge;
    protected String answer;

    public ResponseItem(String question, String challenge) {
        this.question = question;
        this.challenge = challenge;
    }
}
