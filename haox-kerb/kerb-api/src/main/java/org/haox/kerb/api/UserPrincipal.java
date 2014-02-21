/*
 * Created on 17 mai 2005 by jerome
 */
package org.haox.kerb;

import java.security.Principal;

/**
 * @author jerome
 * 
 */
public class UserPrincipal implements Principal {

    private String name;

    public UserPrincipal(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String toString() {
        return name;
    }

    public boolean equals(Object obj) {
        if(obj instanceof Principal)
            return name.equals(((Principal)obj).getName());
        return false;
    }

    public int hashCode() {
        return name.hashCode();
    }

}
