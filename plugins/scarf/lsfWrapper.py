'''
Created on 3 Aug 2016

@author: Shirley Crompton, Research Data Group, SCD
'''

import shlex
#dls-ids runs python 2.6, needs to use Popen, not subprocess.check_output
from subprocess import PIPE, Popen

class LsfProxy(object):
    '''
    This is a wrapper for interacting with LSF via command line. 
    As a prerequisite, the environment must be configured correctly before the LSF commands can be called.
    Ensure that the /etc/profile.modules file is run on pollcat starts up.  
    The Scarf account cn is used as name.
    '''

    def __init__(self, config, logger):
        '''
        Constructor
        '''
        self.logger = logger
        self.config = config
        self.lsfParentGroup = self.config.get('scarf','LSF_PARENT_GRP') #default parent group: diamond
        self.lsfGrpPrefix = self.config.get('scarf','LSF_GRP_PREFIX') #lsf grp pattern <LSF_GRP_PREFIX><icat visitId>, e.g. diag_mt8618-8  
        
    def checkGroup(self, grpName):
        '''
        Check if a LSF group with the provided name already exists.
        If exists, returns a list of the members.  Else, return none.
        '''
        cmd = 'bugroup -w %s' %grpName
        
        try:
            proc = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
            result = proc.communicate()
            rc = proc.wait()
            
            if rc == 0:
                #parse the input for the list of members.  There should be at least 1 member 
                return self.parseMembers(grpName, result.split())                
            else:
                raise ValueError(result)            
#                   
        except (OSError, ValueError), err:
            self.logger.error('Error checking LSF Group(%s): %s' % (grpName, err))
            raise
        
        
    
    def addGroup(self, grpName, grpMembers):
        '''
        Add a LSF group with the given name and the provided list of members to the group. 
        At least one member must be provided to create a new group.
        '''
        cmd ='bconf create usergroup=%s "GROUP_MEMBER=%s"' % (grpName, ' '.join(grpMembers))
        #has to use cmd as a String as grpMembers may contain whitespaces
        try:
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
            result = proc.communicate()
            rc = proc.wait() #0 is OK, 1 is error, result contains errmsg
            if rc == 0:
                self.logger.info('Added LSF group(%s) with members(%s)' % (grpName, grpMembers))
            else:                
                raise ValueError(result)                       
            
        except (OSError, ValueError), err:
            self.logger.error('Error adding LSF Group(%s): %s' % (grpName, err))
            raise       
        
        
    
    def addMembers(self, grpName, grpMembers):
        '''
        Add the provided list of members to an existing LSF group.
        '''
        cmd = 'bconf addmember usergroup=%s "GROUP_MEMBER=%s"' %(grpName, ' '.join(grpMembers))
        #has to use cmd as a String as grpMembers may contain whitespaces
        try:
            proc = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
            result = proc.communicate()
            rc = proc.wait() #0 is OK, 1 is error, result contains errmsg
            if rc == 0:
                self.logger.info('Added member/s to lsf group(%s)' % grpName)
            else:                
                raise ValueError(result)
            
        except (OSError, ValueError), err:
            self.logger.error('Error adding member/s to LSF Group(%s): %s' % (grpName, err))
            raise     
               
    
    def parseMembers(self, grpName, memList):
        '''
        Parse the LSF bugroup output and extract the member list
        '''        
        start = 0
        stop = 0
        
        for index, item in enumerate(memList):
            if item == grpName:
                start = index + 1
            elif item == '(':
                stop = index
                break            
        #there will at least be one member as this is the rule when creating a usergroup in LSF
        return memList[start:stop:]
    
        
        
            