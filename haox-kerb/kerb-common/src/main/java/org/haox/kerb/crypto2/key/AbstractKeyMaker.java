package org.haox.kerb.crypto2.key;

public abstract class AbstractKeyMaker implements KeyMaker {

    protected static char[] makePasswdSalt(String password, String salt) {
        char[] result = new char[password.length() + salt.length()];
        System.arraycopy(password.toCharArray(), 0, result, 0, password.length());
        System.arraycopy(salt.toCharArray(), 0, result, password.length(), salt.length());

        return result;
    }
}
