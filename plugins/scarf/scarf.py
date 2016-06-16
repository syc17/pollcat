import re
import os
import sys

import shutil

from pollcat import chunks, getICAT
from common import *

import ldapProxy
from icat.exception import ICATError
from icat.entities import Datafile

"""
SCARF Plugin for PollCAT
"""

class Plugin(object):

    def __init__(self, request, datafileIds, config, logger):
        '''
        Initialise class
        '''
        self.request = request
        self.datafileIds = datafileIds
        self.config = config
        self.logger = logger
        # merge scarf config with main pollcat config
        self.config.read('plugins/scarf/scarf.config')
        #common variables
        self.df_locations = {}
        self.df_visitIds = {}
        self.visitId_users = {}


    def run(self):  
        '''
        Run the plugin, create the LDAP authorisation structure and LSF account, copy the files across and set file permissions
        DLS stores their data in this folder structure and this is stored in Datafile.location attribute for each data file}
        
        /dls/<beamline>/data/<year>/<visitId>/*/<datafile.name>
        
        e.g. dls/x01/data/2014/x5022-2/processing/tmp/r0008/001/submit.pbs
             with datafile.name = submit.pbs
        
        and visitId = x5022-2        
        The visitId is capitalised in Dataset and Investigation, i.e. X5022-2               
        '''
        icatClient = getICAT(self.config)
        
        for dfId in self.datafileIds:    
            '''
            First get info on the each file's visit-id, location and associated users
            we only need to create a visit-id group in LDAP once
            '''        
            try:    
                '''
                get each file's location
                '''                
                datafile = icatClient.search('SELECT df FROM Datafile WHERE df.id=%s' % str(dfId))
                location = datafile[0].location
                self.df_locations[dfId] = location; #add an entry, each location is unique
            except(ValueError, ICATError), err:
                self.logger.error('%s retrieving datafile(%s) location....Skipping this file' %(err, str(dfId)))
                continue            
                       
            visitId = self.getVisitId(self.location)
            if visitId not in self.df_visitIds:
                '''
                only add it if not already, may not need to cache it as already in location????
                '''
                self.df_visitIds[dfId] = visitId
            
            if visitId not in self.visitId_users:
                '''
                only query icat if we have not retrieved the users for this visitId
                '''
                try:
                    '''
                    get the users associated with the visitId. Capitalise visitId.
                    '''
                    users = icatClient.search("SELECT u FROM User u JOIN u.investigationUsers iu JOIN iu.investigation inv WHERE inv.visitId = '%s'" % visitId.upper())
                    if len(users) > 0:
                        self.visitId_users[visitId] = users
                    else:
                        self.logger.debug('No users retrieved for visitId = %s' % visitId) 
                         
                except (ValueError, ICATError), err:
                    self.logger.error('Error %s retrieving users by visitId(%s) ....Skipping this file' %(err, str(self.visitId)))
                    continue
            
            
        for vId in self.visitId_users:
            '''
            create the file users, groups and configure the LDAP authorisation structure and LSF acct
            '''
            
            
            
            grpName = vId.replace('-','_') #swap all - to _
            self.createUser(grpName, self.visitId_users(vId))   
            
        #?????????        
        self.grp_members = self.configLdap(self.request['userName'])   #we need the list of scarf users associated with the visitid
        #
         
        self.createuser(self.grp_members)   
        self.copydata(self.request['userName'], self.request['fileName'], self.datafileIds)
        

    def createuser(self, visit_Id, grp_members): 
        '''
        Create local file user accounts for requester and all investigation_users who already have a SCARF account
        glassfish group has already been created.  It has 1 user (glassfish, uid = 50548)
        '''
        self.logger.debug("Attempting to create group(%s) with (%d) users..." %(visit_Id, len(grp_members)))
        
    
        if re.match('^[\w-]+$', username) == None:
            raise OSError("Username contains non-alphanumeric characters")

        params = (
            username,
            self.config.get('scarf', 'DESTINATION'),
            username
        ) 

        if os.system("useradd %s -d %s/%s" % params) == 0:
            self.logger.info("Creating new local user account for: %s" % username)
        else:
            self.logger.warn("Unable to create locate user account for: %s" % username)
            
        #may need to add visitID group and set permission
    
    
    def copydata(self, username, downloadname, datafileIds):
        '''
        Copy requested data from the source to the target folders
        '''
        SOURCE = self.config.get('scarf', 'SOURCE')
        DESTINATION = self.config.get('scarf', 'DESTINATION') #needs to change visitId's - to _
    
        if os.path.exists(DESTINATION + '/' + username + '/' + downloadname):
            self.logger.warn("Download name already exists. Changing to %s_2" % downloadname)
            downloadname = downloadname + "_2"
    
        for ids in chunks(datafileIds, int(self.config.get('scarf', 'LOCATION_CHUNKS'))):
            query = 'SELECT df.location FROM Datafile df WHERE df.id IN (%s)' % ids
            for location in getICAT(self.config).search(query):
                source = "%s/%s" % (SOURCE, location)
                destination = "%s/%s/%s/%s" % (DESTINATION, username, downloadname, location)
    
                self.destination_dir = os.path.dirname(destination)
                if not os.path.isdir(self.destination_dir):
                    self.logger.debug("Creating directory %s" % self.destination_dir)
                    os.makedirs(self.destination_dir)
            
                self.logger.debug("Copying file %s -> %s" % (source, destination))
                shutil.copy(source, destination)

    def configLdap(self, username):
        '''
        Configure ldap authorisation 
        '''
        proxy = ldapProxy(self.config, self.logger)
                
        
    def getVisitId(self, location): 
        '''
        extract visitId, which is the fifth element in the tokenized path
        '''
        os.sep = '/'
        path_list = location.split(os.sep)
        visitId = path_list[5]     #.replace('-','_') #swap all - to _        
        self.logger.info('location(%s) has visitId = %s' %(location, visitId))        
        return visitId
        