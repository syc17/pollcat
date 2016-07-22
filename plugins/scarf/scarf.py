import common
import re
import os
import shutil

from plugins.scarf import ldapWrapper
from icat.exception import ICATError

"""
SCARF Plugin for PollCAT
@author: Shirley Crompton, Research Data Group, SCD
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
        self.destination = self.config.get('scarf','DATA_DESTINATION')        
        self.source = self.config.get('scarf','DATA_SOURCE')
        self.locationChunks = int(self.config.get('scarf', 'LOCATION_CHUNKS'))
        self.dlsDefaultUser = 'glassfish' # both for os group and os user
         
        self.numFilesCopied = 0
        # common variable lists
        self.skippedDFids = []      #int
        self.skippedVisitIds = []   #String
        # common variable maps        
        self.df_locations = {}  #dfId:icat.location  
        self.visitId_dfIds = {} #visitId:[difIds]
        self.visitId_users = {} #visitId:[icat.user]

    def run(self):  
        '''
        Run the plugin, create the LDAP authorisation structure and LSF account, copy the files across and set file permissions
        
        '''
        icatClient = common.IcatClient(self.config)
        self.configLdap()
        
        for dfId in self.datafileIds:  #dfId is an int, icat.datafile.id  
            '''
            First get info on the each file's visit-id, location and associated users
            we only need to create a visit-id group in LDAP and the OS once
            '''        
            try:    
                '''
                get each file's location
                '''                
                datafile = icatClient.getInstance().search('SELECT df FROM Datafile df WHERE df.id=%s' % str(dfId))
                location = datafile[0].location
                self.df_locations[dfId] = location; #add an entry, each location is unique
            except(ValueError, ICATError), err:
                self.skippedDFids.append(dfId)
                self.logger.error("%s retrieving datafile(%i)'s location....Skipping this file" %(err, dfId))
                continue            
            
            self.logger.info("About to extract visit id from ")           
            visitId = self.getVisitId(self.df_locations[dfId])           
            self.visitId_dfIds.setdefault(visitId,[]).append(dfId)
            
            
            if visitId not in self.visitId_users:
                '''
                only query icat if we have not retrieved the users for this visitId
                '''
                try:
                    '''
                    get the users associated with the visitId. Capitalise visitId.
                    '''
                    users = icatClient.getInstance().search("SELECT u FROM User u JOIN u.investigationUsers iu JOIN iu.investigation inv WHERE inv.visitId = '%s'" % visitId.upper())
                    if len(users) > 0:
                        self.visitId_users[visitId] = users
                    else:
                        self.visitId_users[visitId] = None
                        self.logger.debug('No users retrieved for visitId = %s' % visitId)
                         
                except (ValueError, ICATError), err:
                    self.skippedVisitIds.append(visitId)
                    self.logger.error('Error %s retrieving users by visitId(%s) ....Skipping this visitId' %(err, str(self.visitId)))
                    continue
        #finished processing all files in the request.  We have the users associated with the visitId plus each file's location   
        self.logger.info('Finished processing all files in the request.  About to process LDAP entries....')
            
        for vId in self.visitId_users.keys():
            '''
            create the LDAP authorisation structure, LSF acct 
            '''
            if vId in self.skippedVisitIds: #had icat query error
                self.logger.warn('Not processing SCARF and LSF accounts for visitId(%s) as it is in the skipped list!' %vId)
                continue
            
            visit_id = vId 
            users = self.visitId_users[vId]
            
            self.logger.info("About to process visitId %s and synchronise LDAP entries...." % visit_id)
            
            if users is None:
                self.logger.warn('No icat users for visit_id(%s)' % visit_id)   
                continue   
            #create a new map of filtered users' fedid:uid or uid=None for user w/o a scarf a/c.  Assume that there will always be icat investigationUsers
            #python 2.6 syntax
            icat_grpMems = dict((user.name, self.getUid(user, visit_id)) for user in users) #fedid:uid            
            #python 2.7 syntax
            #icat_grpMems = {user.name : self.getUid(user, visit_id) for user in users} #fedid:uid
            #check if the requester has scarf a/c
            try:
                if self.request['userName'] not in icat_grpMems.keys():
                    self.logger.debug("self.request['userName'] not currently contained in icat_grpMems...")
                else:
                    if icat_grpMems[self.request['userName']] is None: #assume requester is a member of the investigationUsers: DLS has no public data.
                        icat_grpMems[self.request['userName']] = self.proxy.addUser(self.request['userName']) #update dictionary
                    
            except (ldapWrapper.ldap.LDAPError, OSError), err:
                #self.skippedVisitIds.append(visit_id)
                #self.logger.error('Error adding requester(%s) to ldapWrapper: %s!!!!  Skipping this %s' %(self.request['userName'], err, visit_id)) 
                self.logger.warn('Error adding requester(%s) to ldapWrapper: %s!!!!' %(self.request['userName'], err))
                continue
            
            ldap_grpName = visit_id.replace('-','_') #swap all - to _
            #check if this group exists in ldapWrapper, if yes, don't need to re-create it
            try:
                if self.proxy.connected is False:
                    self.proxy.connect()            
                ldap_grp_memUIDs = self.proxy.getGroup(ldap_grpName) # #Dict[dn:uids] could be None if group not found.  
                
                if ldap_grp_memUIDs is None:
                    #create the group, can add grp members later
                    dn = self.proxy.addGroup(ldap_grpName) #gidNum is an int
                    # add all the uids to ldapWrapper group a/c
                    self.proxy.addGroupMembers(dn, [x for x in icat_grpMems.values() if x is not None]) 
                
                else: # check if we need to add users to the ldapWrapper group, we do no remove existing ldapWrapper grp members!!!
                    uidsToAdd = list(set([x for x in icat_grpMems.values() if x is not None])).difference(ldap_grp_memUIDs.values()) #empty list returned if all included
                    if uidsToAdd:   #if list is not empty
                        self.proxy.addGroupMembers(ldap_grp_memUIDs.key()[0], uidsToAdd)                        
                    else:
                        self.logger.debug('No new members to add to ldapWrapper group(%s)...' %ldap_grpName)                
                
                #################TODO: the LSF group, membership can only be compared after we have checked if the grp members have SCARF a/c 
                
                ###### 11/7/2016 awaiting clarification of requirements
                
                
                
                ################# 
            
            
            except Exception, err:
                #skip this one 
                #self.skippedVisitIds.append(visit_id)                
                #self.logger.error('Error processing visit(%s): %s.  Skipping this.....' %(visit_id, err))
                self.logger.error('Error processing visit(%s): %s.....' %(visit_id, err))
                continue
            
        #we are done with LDAP now
        self.proxy.disconnect()         
        
        #create the OS group/users and copy files
        for visitGroup, users in self.visitId_users.iteritems():
            #we will create the file structure anyway even if something has gone wrong in managing the Scarf account
            #if(visitGroup in self.skippedVisitIds):
            #    self.logger.info("VisitID(%s) is in the skipped file, will skip creating local users..." % visitGroup)
            #    continue                     
            group = visitGroup.replace('-','_') #swap all - to _            
            
            try:
                self.addGroup(group)
            except OSError, err:    #no point in copying files if can't create the OS Group     
                self.skippedVisitIds.append(visitGroup)
                self.logger.error('Error creating group for visitId(%s): %s. Skipping this...' % (group, err))
                #do next visitGroup
                continue
            
            fedids = [user.name for user in users]
            for fedid in fedids:
                try:
                    self.createuser(group, fedid)                 
                except OSError, err:   
                    self.logger.error('Error creating user for %s: %s. Skipping this...' % (fedid, err))
                    #do next fedid
                    continue   
                
            self.logger.info('After creating users, about to go through visit ids and copy files....') 
            #Now copy the files and set file permissions
            #no point in processing it if we failed to get icat.location
            if visitGroup in self.skippedVisitIds:
                self.logger.warn('Skip copying files for %s as we had errors creating the user group....' % visitGroup)
                continue
            else:
                # filter out the skipped files as they have no icat.location
                self.copydata(group,[df for df in self.visitId_dfIds[visitGroup] if df not in self.skippedDFids])  
        
        #create a report in the log
        self.logger.info("*******************IDS SCARF REPORT FOR TRANSFER REQUEST ID: %s" % str(self.request['id']))
        self.logger.info("**********************Number of files transferred :")
        #has to guard against none type for instance variable used in methods
        if self.numFilesCopied is None or self.numFilesCopied == 0:
            self.logger.info("****************************** 0 ")
        else:
            self.logger.info("****************************** %i " % self.numFilesCopied)
        self.logger.info("**********************Skipped visitIds : ")
        self.logger.info("****************************** %s " % self.skippedVisitIds)
        self.logger.info("**********************Skipped datafiles : ")
        self.logger.info("****************************** %s " % self.skippedDFids)
    
    def createuser(self, group, fedid): 
        '''
        Create local file user accounts for requester and all other investigation_users who already have a SCARF account
        
        '''
        try:
            if re.match('^[\w-]+$', fedid) == None:
                raise OSError("%s contains non-alphanumeric characters" % fedid)
            if os.system("id -u %s" % fedid) != 0:                
                #useradd will update if a/c exists. -M do not create home directory
                if os.system("useradd %s -g %s -M" % (fedid, group)) == 0:
                    self.logger.info("Creating new local user account for: %s" % fedid)
                else:
                    raise OSError("Unable to create local user account for: %s" % fedid)
            else:
                self.logger.info("User(%s) already exists!" % fedid)
                
        except OSError, err:
            self.logger.error('Error creating %s with group(%s) : %s...' % (fedid, group, err))
            raise
    
    def copydata(self, visitID, dfIDs):
        '''
        Copy requested data from the source to the target folders
        DLS stores their data in this folder structure and this is stored in Datafile.location attribute for each data file:
            /dls/<beamline>/data/<year>/<visitId>/*/<datafile.name>
        
        e.g. dls/x01/data/2014/x5022-2/processing/tmp/r0008/001/submit.pbs
            with beamline = x01 
                year = 2014
                visitId = x5022-2  The visitId is capitalised in Dataset and Investigation objects, i.e. X5022-2 
                and datafile.name = submit.pbs
                
        All folders set up to the visitId level are owned by user:glassfish and group:glassfish with u=rwx g=rwx o=rx permission
        All folders at and below the visitId level are owned by user:glassfish and group:visitId with u=rwx g=rx permission
        
        visitID already has '-' replaced by '_'
        
        The glassfish group has already been created.  It has 1 user (glassfish, uid = 50548)
        '''
        self.logger.info('Preparing to copy %i files for %s....' %( len(dfIDs), visitID))
        locations = [self.df_locations[fid] for fid in dfIDs if fid in self.df_locations.keys()]
        for location in locations:              
            #we will strip the '/dls' segment, the parent path including the 'dls' segment will be defined in the configuration file
            tempPath = location[location.find('dls',0, len(location))+len('dls'):]          #/beamline/data/year/cm12167-3/location1/location2/file.dat
            beamlinePath = self.destination + tempPath[0:tempPath.find('/',1,len(tempPath))] #dls + /beamline 
            grpPath = self.destination + tempPath[:tempPath.find(visitID.replace('_','-'),0,len(tempPath))+len(visitID)]  #dls + /beamline/data/year/cm12167-3
            #subFolderPath = tempPath[tempPath.find(visitID,0,len(tempPath))+len(visitID):]  #/location1/location2/file.dat 
            self.logger.debug('split file location(%s) into group folder(%s) and beamline folder(%s) paths...' % (location, grpPath, beamlinePath))                
                                       
            #check if visitId folder exists, linux doesn't care if it it ends with '/' or not
            source = "%s/%s" % (self.source, location)
            destination = self.destination + tempPath
            self.destination_dir = os.path.dirname(destination)
            if not os.path.isdir(self.destination_dir):
                self.logger.debug("Creating directory %s" % self.destination_dir)
                os.makedirs(self.destination_dir)
        
            self.logger.debug("Copying file %s -> %s" % (source, destination))
            shutil.copy(source, destination) #will overwrite if exists
            self.numFilesCopied += 1
            
            #set permission, assume that root dls folder is already created and has permission set
            if os.system("chown -R %s:%s %s" %(self.dlsDefaultUser,self.dlsDefaultUser,beamlinePath)) == 0:
                self.logger.info("setting glassfish permission recursively for %s path..." % beamlinePath)
                if os.system("chmod 775 %s" % beamlinePath) != 0:
                    self.logger.warn('Failed to set permission on %s to 775' % beamlinePath)
            else:
                self.logger.warn("Failed to set glassfish permission recursively for %s path!!!" % beamlinePath )   
            #now try and set the visit group permission
            if os.system("chown -R %s:%s %s" %(self.dlsDefaultUser,visitID,grpPath)) == 0:
                self.logger.info("set %s permission recursively for %s path..." % (visitID,grpPath))
                if os.system("chmod 750 %s" % grpPath) != 0:
                    self.logger.warn('Failed to set permission on %s to 750' % grpPath)
            else:
                self.logger.warn("Failed to set %s permission recursively for %s path!!!" % (visitID,grpPath))

    def configLdap(self):
        '''
        Configure ldapWrapper authorisation 
        '''
        self.proxy = ldapWrapper.LdapProxy(self.config, self.logger)
        self.proxy.connect()
                
        
    def getVisitId(self, location): 
        '''
        extract visitId, which is the fifth element in the tokenized path
        '''
        os.sep = '/'
        path_list = location.split(os.sep)
        visitId = path_list[5]         
        self.logger.info('location(%s) has visitId = %s' %(location, visitId))        
        return visitId
    
    def getUid(self, user, vId):
        '''
        Retreve the ldapWrapper uid for a user in the visit group, if none found, return None
        '''
        self.logger.debug('Processing visitId(%s), fedid(%s)...' %(vId, user.name))
        fedid = user.name
        if fedid is None:
            self.logger.debug('VisitId(%s) : failed to extract fedid from user(%s).  Skipping this user... ' %(vId, user.name))
        else:
            self.logger.debug('VisitId(%s) : Extracted fedid(%s) from user... ' %(vId, user.name))
            try:
                if self.proxy.connected == False:
                    self.proxy.connect()
                
                return self.proxy.getUser(fedid) #uid could be none
            except (ValueError,ldapWrapper.ldap.LDAPError), err:
                self.logger.error('Error retrieving user dn for %s: %s' %(fedid, err)) 
            except Exception, e:
                self.logger.error('Other error retrieving user dn for %s: %s' %(fedid, e))
                
    def addGroup(self, visitId):
        '''
        Check if the user group exist on the OS.  If not, create it.
        '''
        try:
            #match from start to finish for occurrences of non-alphanumeric and '-' characters
            if re.match('^[\w-]+$', visitId) == None:                
                raise OSError("Group(%s) contains non-alphanumeric characters" % visitId)
            else:
                #go and force create the group 
                if os.system("groupadd %s -f" % visitId) != 0:
                    raise OSError("Failed to create group(%s) ...." % visitId)    
        except OSError, err:
            self.logger.error('Error creating user group(%s) : %s...' %(visitId,err))
            raise
        
    def chunks(self, l, n):
        '''
        Chunk a list into smaller subset of size n
        '''
        return [l[i:i+n] for i in xrange(0, len(l), n)]