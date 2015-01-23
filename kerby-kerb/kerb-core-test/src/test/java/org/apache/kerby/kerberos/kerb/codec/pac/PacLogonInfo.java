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
package org.apache.kerby.kerberos.kerb.codec.pac;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Date;

public class PacLogonInfo {

    private Date logonTime;
    private Date logoffTime;
    private Date kickOffTime;
    private Date pwdLastChangeTime;
    private Date pwdCanChangeTime;
    private Date pwdMustChangeTime;
    private short logonCount;
    private short badPasswordCount;
    private String userName;
    private String userDisplayName;
    private String logonScript;
    private String profilePath;
    private String homeDirectory;
    private String homeDrive;
    private String serverName;
    private String domainName;
    private PacSid userSid;
    private PacSid groupSid;
    private PacSid[] groupSids;
    private PacSid[] resourceGroupSids;
    private PacSid[] extraSids;
    private int userAccountControl;
    private int userFlags;

    public PacLogonInfo(byte[] data) throws IOException {
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(data)));

            // Skip firsts
            pacStream.skipBytes(20);

            // Dates
            logonTime = pacStream.readFiletime();
            logoffTime = pacStream.readFiletime();
            kickOffTime = pacStream.readFiletime();
            pwdLastChangeTime = pacStream.readFiletime();
            pwdCanChangeTime = pacStream.readFiletime();
            pwdMustChangeTime = pacStream.readFiletime();

            // User related strings as UnicodeStrings
            PacUnicodeString userNameString = pacStream.readUnicodeString();
            PacUnicodeString userDisplayNameString = pacStream.readUnicodeString();
            PacUnicodeString logonScriptString = pacStream.readUnicodeString();
            PacUnicodeString profilePathString = pacStream.readUnicodeString();
            PacUnicodeString homeDirectoryString = pacStream.readUnicodeString();
            PacUnicodeString homeDriveString = pacStream.readUnicodeString();

            // Some counts
            logonCount = pacStream.readShort();
            badPasswordCount = pacStream.readShort();

            // IDs for user
            PacSid userId = pacStream.readId();
            PacSid groupId = pacStream.readId();

            // Groups information
            int groupCount = pacStream.readInt();
            int groupPointer = pacStream.readInt();

            // User flags about PAC Logon Info content
            userFlags = pacStream.readInt();
            boolean hasExtraSids = (userFlags & PacConstants.LOGON_EXTRA_SIDS) == PacConstants.LOGON_EXTRA_SIDS;
            boolean hasResourceGroups = (userFlags & PacConstants.LOGON_RESOURCE_GROUPS) == PacConstants.LOGON_RESOURCE_GROUPS;

            // Skip some reserved fields (User Session Key)
            pacStream.skipBytes(16);

            // Server related strings as UnicodeStrings
            PacUnicodeString serverNameString = pacStream.readUnicodeString();
            PacUnicodeString domainNameString = pacStream.readUnicodeString();

            // ID for domain (used with relative IDs to get SIDs)
            int domainIdPointer = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(8);

            userAccountControl = pacStream.readInt();

            // Skip some reserved fields
            pacStream.skipBytes(28);

            // Extra SIDs information
            int extraSidCount = pacStream.readInt();
            int extraSidPointer = pacStream.readInt();

            // ID for resource groups domain (used with IDs to get SIDs)
            int resourceDomainIdPointer = pacStream.readInt();

            // Resource groups information
            int resourceGroupCount = pacStream.readInt();
            int resourceGroupPointer = pacStream.readInt();

            // User related strings
            userName = userNameString.check(pacStream.readString());
            userDisplayName = userDisplayNameString.check(pacStream.readString());
            logonScript = logonScriptString.check(pacStream.readString());
            profilePath = profilePathString.check(pacStream.readString());
            homeDirectory = homeDirectoryString.check(pacStream.readString());
            homeDrive = homeDriveString.check(pacStream.readString());

            // Groups data
            PacGroup[] groups = new PacGroup[0];
            if(groupPointer != 0) {
                int realGroupCount = pacStream.readInt();
                if(realGroupCount != groupCount) {
                    Object[] args = new Object[]{groupCount, realGroupCount};
                    throw new IOException("pac.groups.invalid.size");
                }
                groups = new PacGroup[groupCount];
                for(int i = 0; i < groupCount; i++) {
                    pacStream.align(4);
                    PacSid id = pacStream.readId();
                    int attributes = pacStream.readInt();
                    groups[i] = new PacGroup(id, attributes);
                }
            }

            // Server related strings
            serverName = serverNameString.check(pacStream.readString());
            domainName = domainNameString.check(pacStream.readString());

            // ID for domain (used with relative IDs to get SIDs)
            PacSid domainId = null;
            if(domainIdPointer != 0)
                domainId = pacStream.readSid();

            // Extra SIDs data
            PacSidAttributes[] extraSidAtts = new PacSidAttributes[0];
            if(hasExtraSids && extraSidPointer != 0) {
                int realExtraSidCount = pacStream.readInt();
                if(realExtraSidCount != extraSidCount) {
                    Object[] args = new Object[]{extraSidCount, realExtraSidCount};
                    throw new IOException("pac.extrasids.invalid.size");
                }
                extraSidAtts = new PacSidAttributes[extraSidCount];
                int[] pointers = new int[extraSidCount];
                int[] attributes = new int[extraSidCount];
                for(int i = 0; i < extraSidCount; i++) {
                    pointers[i] = pacStream.readInt();
                    attributes[i] = pacStream.readInt();
                }
                for(int i = 0; i < extraSidCount; i++) {
                    PacSid sid = (pointers[i] != 0) ? pacStream.readSid() : null;
                    extraSidAtts[i] = new PacSidAttributes(sid, attributes[i]);
                }
            }

            // ID for resource domain (used with relative IDs to get SIDs)
            PacSid resourceDomainId = null;
            if(resourceDomainIdPointer != 0)
                resourceDomainId = pacStream.readSid();

            // Resource groups data
            PacGroup[] resourceGroups = new PacGroup[0];
            if(hasResourceGroups && resourceGroupPointer != 0) {
                int realResourceGroupCount = pacStream.readInt();
                if(realResourceGroupCount != resourceGroupCount) {
                    Object[] args = new Object[]{resourceGroupCount, realResourceGroupCount};
                    throw new IOException("pac.resourcegroups.invalid.size");
                }
                resourceGroups = new PacGroup[resourceGroupCount];
                for(int i = 0; i < resourceGroupCount; i++) {
                    PacSid id = pacStream.readSid();
                    int attributes = pacStream.readInt();
                    resourceGroups[i] = new PacGroup(id, attributes);
                }
            }

            // Extract Extra SIDs
            extraSids = new PacSid[extraSidAtts.length];
            for(int i = 0; i < extraSidAtts.length; i++) {
                extraSids[i] = extraSidAtts[i].getId();
            }

            // Compute Resource Group IDs with Resource Domain ID to get SIDs
            resourceGroupSids = new PacSid[resourceGroups.length];
            for(int i = 0; i < resourceGroups.length; i++) {
                resourceGroupSids[i] = PacSid.append(resourceDomainId, resourceGroups[i].getId());
            }

            // Compute User IDs with Domain ID to get User SIDs
            // First extra is user if userId is empty
            if(!userId.isEmpty() && !userId.isBlank()) {
                userSid = PacSid.append(domainId, userId);
            } else if(extraSids.length > 0) {
                userSid = extraSids[0];
            }
            groupSid = PacSid.append(domainId, groupId);

            // Compute Group IDs with Domain ID to get Group SIDs
            groupSids = new PacSid[groups.length];
            for(int i = 0; i < groups.length; i++) {
                groupSids[i] = PacSid.append(domainId, groups[i].getId());
            }
        } catch(IOException e) {
            throw new IOException("pac.logoninfo.malformed", e);
        }
    }

    public Date getLogonTime() {
        return logonTime;
    }

    public Date getLogoffTime() {
        return logoffTime;
    }

    public Date getKickOffTime() {
        return kickOffTime;
    }

    public Date getPwdLastChangeTime() {
        return pwdLastChangeTime;
    }

    public Date getPwdCanChangeTime() {
        return pwdCanChangeTime;
    }

    public Date getPwdMustChangeTime() {
        return pwdMustChangeTime;
    }

    public short getLogonCount() {
        return logonCount;
    }

    public short getBadPasswordCount() {
        return badPasswordCount;
    }

    public String getUserName() {
        return userName;
    }

    public String getUserDisplayName() {
        return userDisplayName;
    }

    public String getLogonScript() {
        return logonScript;
    }

    public String getProfilePath() {
        return profilePath;
    }

    public String getHomeDirectory() {
        return homeDirectory;
    }

    public String getHomeDrive() {
        return homeDrive;
    }

    public String getServerName() {
        return serverName;
    }

    public String getDomainName() {
        return domainName;
    }

    public PacSid getUserSid() {
        return userSid;
    }

    public PacSid getGroupSid() {
        return groupSid;
    }

    public PacSid[] getGroupSids() {
        return groupSids;
    }

    public PacSid[] getResourceGroupSids() {
        return resourceGroupSids;
    }

    public PacSid[] getExtraSids() {
        return extraSids;
    }

    public int getUserAccountControl() {
        return userAccountControl;
    }

    public int getUserFlags() {
        return userFlags;
    }

}
