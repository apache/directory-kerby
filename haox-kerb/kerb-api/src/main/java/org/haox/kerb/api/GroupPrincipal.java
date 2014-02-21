/*
 * Created on 17 mai 2005 by jerome
 */
package org.haox.kerb;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * @author jerome
 * 
 */
public class GroupPrincipal implements Group {

    private String name;

    private Set members = new HashSet();

    public GroupPrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String toString() {
        return name;
    }

    public boolean addMember(Principal user) {
        members.add(user);
        return true;
    }

    public boolean isMember(Principal member) {
        return members.contains(member);
    }

    public boolean removeMember(Principal user) {
        members.remove(user);
        return true;
    }

    public Enumeration members() {
        return Collections.enumeration(members);
    }

}
