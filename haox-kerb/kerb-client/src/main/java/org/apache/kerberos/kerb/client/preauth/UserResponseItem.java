package org.apache.kerberos.kerb.client.preauth;

public class UserResponseItem {
    protected String question;
    protected String challenge;
    protected String answer;

    public UserResponseItem(String question, String challenge) {
        this.question = question;
        this.challenge = challenge;
    }
}
