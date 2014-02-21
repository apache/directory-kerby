package org.haox.kerb;

import java.util.ArrayList;
import java.util.List;

public class AuthenticatedUser {

    public static final String SESSION_ATTRIBUTE_NAME = "org.haox.kerb.sso.user";

    private String name;
    private String domain;
    private List<String> groups;

    public AuthenticatedUser(String name, String domain, List<String> groups) {
        String username = name;
        String userdomain = domain;
        if(name.contains("@") && domain == null) {
            String[] split = name.split("@");
            if(split.length > 0)
                username = split[0];
            if(split.length > 1)
                userdomain = split[1];
        }

        this.name = username;
        this.domain = userdomain;
        this.groups = groups;
    }

    public AuthenticatedUser(String name, String domain) {
        this(name, domain, new ArrayList<String>());
    }

    public AuthenticatedUser(String name) {
        this(name, null, new ArrayList<String>());
    }

    public String getName() {
        return name;
    }

    public String getDomain() {
        return domain;
    }

    public List<String> getGroups() {
        return groups;
    }

}