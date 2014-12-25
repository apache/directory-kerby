package org.haox.token;

import java.util.Map;

public class KerbToken {

  private Map<String, Object> attributes;

  public KerbToken(Map<String, Object> attributes) {
    this.attributes = attributes;
  }

  public Map<String, Object> getAttributes() {
    return attributes;
  }

  public String getPrincipal() {
    return (String) attributes.get("sub");
  }

  public String[] getGroups() {
    String grp = (String) attributes.get("group");
    if (grp != null) {
      return new String[] { grp };
    }
    return new String[0];
  }
}
