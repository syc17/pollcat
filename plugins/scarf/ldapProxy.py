'''
Created on 11 May 2016

@author: Shirley Crompton, Research Data Group, SCD
'''

import ldap
import ldap.modlist as modlist
from statsmodels.tsa.arima_process import err1
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
        self.scarfDescs = self.getScarfAttribute('LDAP_ADD_USER_DESC') #guard for none
        self.baseUserDN = self.config.get('scarf','LDAP_BASE_USER_DN')
        self.baseGrpDN = self.config.get('scarf','LDAP_BASE_GRP_DN')
        self.userAttrs = self.getScarfAttribute('LDAP_USER_ATTRS') #can be none
    
    def connect(self):
        '''
        Open a connection and bind to the ldap server        
        '''
        try:
            ldapproxy = ldap.initialize(self.config.get('scarf','LDAP_URL'))
            #self.ldaproxy.protocol_version = ldap.VERSION3
            ldapproxy.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
            ldapproxy.set_option(ldap.OPT_NETWORK_TIMEOUT, self.config.get('scarf','LDAP_TIMEOUT')) #for connecting to server operations
            ldapproxy.set_option(ldap.TIMEOUT, self.config.get('scarf','LDAP_TIMEOUT')) #for ldap operations
            ldapproxy = ldap.ldapobject.ReconnectLDAPObject(self.config.get('scarf','LDAP_URL'),trace_level=1,retry_max=3)            
            ldapproxy.simple_bind(self.config.get('scarf','LDAP_USER'), self.config.get('scarf','LDAP_PASSWORD'))
            self.logger.info("Successfully bound to %s" % self.config.get('scarf','LDAP_URL'))
            
            return ldapproxy        #none is returned if exception    
        except (ldap.SERVER_DOWN, ldap.INVALID_CREDENTIALS, ldap.INVALID_DN_SYNTAX), err:
            self.logger.error("Error connecting: %s" % err)
            raise   #push up         
        
    def getUser(self, connection, fedid):
        '''
        Check if user has a scarf account and the correct scarf resource allocated.
        If the user exists, the user DN is returned.     
        '''
        term = '(&(name=%s)(objectClass=posixAccount))' % fedid #assertion syntax, operator in front
        scope = ldap.SCOPE_SUBTREE
        try:
            #userAttrs can be None
            result = connection.search_s(self.base,scope,term,self.userAttrs) #userAttrs can be None
            
            if len(result == 0):
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
                    #need to modify the existing scarf record to add the descriptin
                    pendingDesc.append(entry)
            
            if len(pendingDesc) > 0:
                self.addDesc(connection, dn, pendingDesc) 
            
            return dn
        
        except (ValueError, ldap.LDAPError), error_message:
            self.logger.error("Error verifyig user(%s): %s " %(fedid, error_message))
            raise

    
    def disconnect(self, connection):
        '''
        Disconnect 
        '''
        connection.unbind_s()
    
    def addUser(self, fedid):
        '''
        add a scarf user
        '''
        #If you are generating the LDAP filter dynamically (or letting users specify the filter), then you may want to use the escape_filter_chars() and filter_format() functions in the ldap.filter module to keep your filter strings safely escaped.
        #compare_s method returns  true1/false0 if a DN exists/not (only if you know the DN)
        
    def addGroup(self, visitId):
        '''
        add a scarf group
        '''
    def getDescs(self):
        '''
        Extract the scarf descriptions list from the configuration object
        '''
        desc = self.config.get('scarf','LDAP_ADD_USER_DESC')
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
        attrs = self.config.get('scarf','LDAP_USER_ATTRS')
        attributes = attrs.split(',')
        return attributes
    
    def getAttribute(self, attribute):
        '''
        Extract a scarf attribute from the configuration object and format the values
        '''
        attr = self.config.get('scarf', attribute)
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

    def addDesc(self, connection, dn, pendingDesc):
        '''
        add ldap descripton/s to the target DN
        The description shows the SCARF resource permitted
        ''' 
        try:
            mod_desc = [(ldap.MOD_ADD, 'description', pendingDesc)] # pendingDesc should be a list ['',''] but can use '' if only 1 value
            connection.modify_s(dn, mod_desc)
        except ldap.LDAPError, error_message:
            self.logger.error("Error adding description. %s " % error_message)
            raise
        
    def getNextLDAPId(self, connection, dn, attribute):
        '''
        Get the next available LDAP id for creating a new group or user
        Mock a transaction to increment the available LDAP id
        ''' 
        #param = 'objectClass=*'
        #scope = ldap.SCOPE_BASE #stop at base, no drill down      
        
        try:
            #result = connection.search_s(dn,scope,param,attribute)   #attribute should be a list ['','']                     
            #if len(result) != 1:
            #    raise ValueError('Error retrieving next %s, expecting 1 record but %d of records retrieved!' %(attribute[0],len(result)))
                
            #dn, entry = result[0]
            #currentId = entry[attribute[0]][0]
            currentId = self.getAvailableLDAPId(connection,dn,attribute)
            self.logger.debug('Next %s for %s is %s' %(attribute[0],dn,currentId))
            nextId = int(currentId) + 1 
            #values = [str(nextId)] #format into a list
            values = str(nextId) #only 1 value can use String
            #need to update the ldap value to the next one.  Replace the attribute with the values list
            self.success = False
            
            for index in range(5):    # try 5 times
                self.logger.debug('%i try at updating the %s number to %i' %(index, attribute[0], nextId))
                try:
                    mod_spec = [(ldap.MOD_DELETE, attribute[0], entry)]
                    connection.modify_s(dn, mod_spec)
                    self.success = True
                except ldap.NO_SUCH_ATTRIBUTE, err:
                    self.logger.debug('%i try: Failed to update the %s for %s with the next value %i' %(index,attribute[0],dn,nextId))
                    continue
                except:
                    #self.logger.
                    pass
            
            ##needs to do  delete first then update
            mod_spec = [(ldap.MOD_DELETE, attr2retrieve[0], entry),(ldap.MOD_ADD, attr2retrieve[0], values)]
            connection.modify_s(dn, mod_spec)
            #NO_SUCH_ATTRIBUTE  if delete cannot find the object.....
            # https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2 (example for MOD_DELETE
            #retry : https://julien.danjou.info/blog/2015/python-retrying
            
            
            
            
            
        except (ValueError,ldap.LDAPError), error_message:
            self.logger.error("Error getting the next %s id: %s " %(attribute, error_message))
            raise   
            
    def getAvailableLDAPId(self, connection, dn, attr):
        '''
        Get the next available LDAP id for creating a new group or user
        '''
        param = 'objectClass=*'
        scope = ldap.SCOPE_BASE #stop at base, no drill down
        
        try:
            result = connection.search_s(dn,scope,param,attr)
            if len(result) != 1:
                raise ValueError('Error retrieving next %s, expecting 1 record but %d of records retrieved!' %(attribute[0],len(result)))
            
            dn, entry = result[0]
            currentId = entry[attr[0]][0] #first value on the specified attribute
            self.logger.debug('Next %s for %s is %s' %(attr[0],dn,currentId))
            #nextId = int(currentId) + 1 
            #res = {"dn":dn,"curId":currentId}
            return currentId
              
        except (ValueError,ldap.LDAPError), error_message:
            self.logger.error("Error getting the next %s id: %s " %(attr, error_message))
            raise   