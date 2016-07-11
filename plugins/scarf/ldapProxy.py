'''
Created on 11 May 2016
Based on a PERL module written by Derek Ross, SCD

@author: Shirley Crompton, Research Data Group, SCD
'''

import ldap
import re
import os.system
#from plugins import scarf

class ldapProxy(object):
    '''
    Ldap proxy to synchronise authorisation group information for the imported data files.

    '''


    def __init__(self, config, logger):
        '''
        Construct and initialise
        
        '''
        self.logger = logger
        self.config = config
        self.scarfDescs = self.getAttribute('LDAP_ADD_USER_DESC') #guard for none
        self.baseUserDN = self.config.get('scarf','LDAP_BASE_USER_DN')
        self.baseGrpDN = self.config.get('scarf','LDAP_BASE_GRP_DN')
        self.userAttrs = self.getAttribute('LDAP_USER_ATTRS') #can be none
        self.grpAttrs = self.config.get('scarf','LDAP_GPR_ATTRS') 
        self.addOU = self.config.get('scarf','LDAP_ADD_OU')
        self.gidAttribute = self.config.get('scarf','LDAP_ADD_GRP_ID_ATTR')
        self.uidAttribute = self.config.get('scarf','LDAP_ADD_USER_ID_ATTR')
        self.userPrefix = self.config.get('scarf','LDAP_USER_PREFIX')
        self.homeDir = self.config.get('scarf','LDAP_USER_HOME_DIR') #ALL DLS user use this location
        self.DLS_gid = self.config.get('scarf','LDAP_DLS_GID') #All DLS scarf a/c belongs to this group
        self.connected = False
    
    def connect(self):
        '''
        Open a connection and bind to the ldap server        
        '''
        try:
            self.connection = ldap.initialize(self.config.get('scarf','LDAP_URL'))
            #self.ldaproxy.protocol_version = ldap.VERSION3
            self.connection.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
            self.connection.set_option(ldap.OPT_NETWORK_TIMEOUT, self.config.get('scarf','LDAP_TIMEOUT')) #for connecting to server operations
            self.connection.set_option(ldap.TIMEOUT, self.config.get('scarf','LDAP_TIMEOUT')) #for ldap operations
            self.connection = ldap.ldapobject.ReconnectLDAPObject(self.config.get('scarf','LDAP_URL'),trace_level=1,retry_max=3)            
            self.connection.simple_bind(self.config.get('scarf','LDAP_USER'), self.config.get('scarf','LDAP_PASSWORD'))
            self.connected = True
            self.logger.info("Successfully bound to %s" % self.config.get('scarf','LDAP_URL'))
            
        except (ldap.SERVER_DOWN, ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX), err:
            self.logger.error("Error connecting: %s" % err)
            raise   #push up    
        
    def getGroup(self, grpName):
        '''
        Check if the group exists.  If group exists, return a dictionary of dn:list of members' UIDs, else None
        ''' 
        term = '(cn=%s)' % grpName #assertion syntax, operator in front
        scope = ldap.SCOPE_SUBTREE
        try:
            result = self.connection.search_s(self.baseGrpDN, scope, term, self.grpAttrs)
            
            if len(result) == 0:
                self.logger.debug('No scarf account found for visit group(%s)...' % grpName)
                return None
            
            if len(result) > 1:
                raise ValueError('More than 1 LDAP group account retrieved for %s!!!' % grpName)
            
            #handle the result
            dn, attributes = result[0]
            #return {attributes['gidNumber'][0]:attributes['memberUid']}
            return {dn:attributes['memberUid']}
        
        except (ValueError, ldap.LDAPError), error_message:
            self.logger.error("Error verifying visitId(%s): %s " %(grpName, error_message))
            raise
        
        
             
        
    def getUser(self, fedid):
        '''
        Check if user has a scarf account and the correct scarf resource allocated.
        If the user exists, the user ldap uid is returned.     
        '''
        term = '(&(name=%s)(objectClass=posixAccount))' % fedid #assertion syntax, operator in front
        scope = ldap.SCOPE_SUBTREE
        try:
            #userAttrs can be None
            result = self.connection.search_s(self.baseUserDN,scope,term,self.userAttrs) #userAttrs can be None
            
            if len(result) == 0:
                self.logger.debug('No scarf account found for user(%s)...') % fedid
                return None
            
            if len(result) > 1:
                raise ValueError('More than 1 LDAP posixAccount retrieved for %s!!!' % fedid)
            
            #handle the result
            dn, attributes = result[0]
            if 'posixAccount' not in attributes['objectClass']:
                raise ValueError('LDAP record retrieved for for %s is not a posixAccount ' % fedid)
            
            #check description.....
            pendingDesc = []
            for entry in self.scarfDescs:
                if entry not in attributes['description']:
                    #need to modify the existing scarf record to add the description
                    pendingDesc.append(entry)
            
            if len(pendingDesc) > 0:
                self.addDesc(self.connection, dn, pendingDesc) 
            
            return attributes['uid'][0] #uid is the same as cn
        
        except (ValueError, ldap.LDAPError), error_message:
            self.logger.error("Error verifying user(%s): %s " %(fedid, error_message))
            

    
    def disconnect(self):
        '''
        Disconnect 
        '''
        if self.connected:
            self.connection.unbind_s()
            self.connected = False
    
    def addUser(self, fedid):
        '''
        add a scarf user and create the home directory folder.  All DLS scarf users belong the the default DLS group.
        '''
        #If you are generating the LDAP filter dynamically (or letting users specify the filter), then you may want to use the escape_filter_chars() and filter_format() functions in the ldap.filter module to keep your filter strings safely escaped.
        #compare_s method returns  true1/false0 if a DN exists/not (only if you know the DN)
        baseUserDN = self.addOU + self.baseUserDN
        try:
            newUidNum = self.getNextLDAPId(self.connection, baseUserDN, self.uidAttribute)
            if newUidNum is None:
                raise ValueError('Failed to retrieve new uid number from ldap, cannot add user(%s)!' % fedid)
            else:
                #compile CN
                baseNumPart = 10**(8-len(self.userPrefix))
                cn = self.uidAttribute + str(newUidNum % baseNumPart).zfill(8-len(self.userPrefix)) #e.g. fac00058
                self.logger.debug('Compiled CN(%s) for user($s)....' %(cn, fedid))
                descs = self.scarfDescs # a list                
                dn = 'cn=' + cn + ',' + baseUserDN 
                homeDir = self.homeDir + '/' + cn 
                #list of list of attribute:valueList               
                add_record = [
                     ('objectclass', ['top','inetOrgPerson','posixAccount','extensibleObject']),
                     ('name',[fedid]),
                     ('description',descs),
                     ('cn', [cn] ),
                     ('sn', [cn]),
                     ('uid',[cn]),
                     ('uidNumber', [newUidNum]),
                     ('loginShell',['/bin/bash']),
                     ('gidNumber',[self.DLS_gid]),  #all dls user belong to this primary group
                     ('homeDirectory',[homeDir]) 
                ]                
                self.connection.add_s(dn, add_record)
                
                self.logger.info("Setting up %s's scarf home directory at %s...." %(fedid, homeDir))
                #check if cn starts with a lowercase char
                if re.match('|^a-z|', cn) == None:
                    raise OSError('ScarfId does not starts with a lower case character....')  
                else:
                    if os.system("cp -a /etc/skel %s" % homeDir) == 0 and os.system("chown -R %s:%s %s" %(cn,self.DLS_gid,homeDir)) == 0:                    
                        self.logger.info("copied default files and created %s's home directory at %s, also chown'ed user and group permission...." %(fedid, homeDir))
                    else:
                        self.logger.warn("Unable to create %s's home directory or chown user/group permission...." %(fedid, homeDir))
                
                return cn
            
        except (ValueError, ldap.LDAPError, OSError), err:
            #catch all errors, includes ldap.ALREADY_EXISTS. ldap.INSUFFICIENT_ACCESS
            self.logger.error('Error trying to add a ldap user(%s): %s....'% (fedid, err))
            raise
    
        
    def addGroup(self, grpName):
        '''
        add a scarf group. The group name is the icat investigation visitId with all '-' changed to '_'
        returns the new group dn
        '''
        baseGrpDN = self.addOU + self.baseGrpDN
        try:
            newGidNum = self.getNextLDAPId(self.connection, baseGrpDN, self.gidAttribute)
            if newGidNum is None:
                raise ValueError('Failed to retrieve new gid number from ldap, cannot add group(%s)!' % grpName)
            else:
                dn = 'cn=' + grpName + ',' + baseGrpDN 
                #list of list of attribute:valueList               
                add_record = [
                     ('objectclass', ['top','posixGroup']),
                     ('cn', [grpName] ),
                     ('gidNumber', [newGidNum] ),
                ]                
                self.connection.add_s(dn, add_record)
                #return newGidNum
                return dn
            
        except (ValueError, ldap.LDAPError), err:
            #catch all errors, includes ldap.ALREADY_EXISTS. ldap.INSUFFICIENT_ACCESS
            self.logger.error('Error trying to add a ldap group(%s): %s....'% (dn, err))
            raise        
        
        
    def getDescs(self):
        '''
        Extract the scarf descriptions list from the configuration object
        '''
        desc = self.config.get('scarf','LDAP_ADD_USER_DESC') #self.scarfDescs
        descriptions = desc.split(',')
        for index in range(len(descriptions)):
            d1 = descriptions[index].strip()
            #print 'd1:%s' % d1
            if d1 != descriptions[index]:
                self.logger.debug("Replacing '%s' with '%s' ...." %(descriptions[index], d1))
                descriptions[index] = d1 
                
        return descriptions     
     
    def getUserAttrs(self):
        '''
        Extract the scarf user attributes to return in a search from the configuration object
        '''
        attrs = self.config.get('scarf','LDAP_USER_ATTRS') #a String
        attributes = attrs.split(',')
        return attributes
    
    def getAttribute(self, attribute):
        '''
        Extract a scarf attribute from the configuration object and format the values into a list
        '''
        attr = self.config.get('scarf', attribute) # a String
        if attr is not None:
            values = attr.split(',')
            for index in range(len(values)):
                d1 = values[index].strip()
                #print 'd1:%s' % d1
                if d1 != values[index]:
                    self.logger.debug("Converting %s, replacing '%s' with '%s' ...." %(attribute, values[index], d1))
                    values[index] = d1 
                
            return values 
        else:
            return None

    def addDesc(self, dn, pendingDesc):
        '''
        add ldap descripton/s to the target DN
        The description shows the SCARF resource permitted
        ''' 
        try:
            mod_desc = [(ldap.MOD_ADD, 'description', pendingDesc)] # pendingDesc should be a list ['',''] but can use '' if only 1 value
            self.connection.modify_s(dn, mod_desc)
        except ldap.LDAPError, error_message:
            self.logger.error("Error adding description. %s " % error_message)
            raise
        
    def getNextLDAPId(self, dn, attribute):
        '''
        Get the next available LDAP id for creating a new group or user
        Mock a transaction to increment the available LDAP id
        ''' 
        try:
            for index in range(5):    # only try 5 times
                currentId = self.getAvailableLDAPId(self.connection,dn,attribute)
                #self.logger.debug('Next %s for %s is %s' %(attribute[0],dn,currentId))
                nextId = int(currentId) + 1 
                #need to update the ldap value to the next one.  Replace the attribute with the values list
                self.logger.debug('%i try at updating the %s number to %i' %(index, attribute[0], nextId))
                try:                    
                    #mock transaction: first delete, then add
                    #assuming that if currentId not exist, MOD_DELETE will throw NO_SUCH_ATTRIBUTE error and abort before add
                    mod_spec = [(ldap.MOD_DELETE, attribute[0], [currentId]),(ldap.MOD_ADD, attribute[0], [str(nextId)])]
                    self.connection.modify_s(dn, mod_spec)
                    return nextId
                    #break
                except ldap.NO_SUCH_ATTRIBUTE, err:
                    self.logger.debug('%i try: Failed to update the %s for %s with the next value %i: %s' %(index,attribute[0],dn,nextId,err))
                    continue
                except Exception, e:
                    self.logger.debug('%i try: Failed to update the %s for %s with the next value %i: %s' %(index,attribute[0],dn,nextId,str(e)))
                    continue
            
            if index == 4:  #python does not increment the index if limit reached
                raise IndexError('Failed to update the %s for %s with the next value %i after %i try!' %(attribute[0],dn,nextId,index+1))

        except (ValueError,ldap.LDAPError, IndexError), error_message:
            self.logger.error("Error getting the next %s id: %s " %(attribute, error_message))
            raise   
            
    def getAvailableLDAPId(self, dn, attr):
        '''
        Get the next available LDAP id for creating a new group or user
        '''
        param = 'objectClass=*'
        scope = ldap.SCOPE_BASE #stop at base, no drill down
        
        try:
            result = self.connection.search_s(dn,scope,param,attr)
            if len(result) != 1:
                raise ValueError('Error retrieving next %s, expecting 1 record but %d of records retrieved!' %(attr[0],len(result)))
            
            dn, entry = result[0]
            currentId = entry[attr[0]][0] #first value on the specified attribute
            self.logger.debug('Current %s for %s is %s' %(attr[0],dn,currentId))
            return currentId
              
        except (ValueError,ldap.LDAPError), error_message:
            self.logger.error("Error getting the next %s id: %s " %(attr, error_message))
            raise 
        
    def addGroupMembers(self, dn, uids):
        '''
        Add the list of member UIDs to a ldap group
        '''        
        try:
            mod_desc = [(ldap.MOD_ADD, 'memberUid', uids)]
            self.connection.modify_s(dn, mod_desc)           
            
        except ldap.LDAPError, err:
            self.logger.error('Error adding new members to ldap group dn(%s): %s!!!' %(dn, err))
            raise