import re
import os
import icat
import shutil

from pollcat import chunks, getICAT
from common import *

"""
Globus Plugin for PollCAT

This plugin will create a local unix user account and copy the
requested files to thier home directory under the download name
specificed in the TopCAT download request.
"""

class Plugin(object):

    def __init__(self, request, datafileIds, config, logger):
        self.request = request
        self.datafileIds = datafileIds
        self.config = config
        self.logger = logger

        # merge globus config with main pollcat config
        self.config.read('plugins/globus/globus.config')


    def run(self):
        self.createuser(self.request['userName'])
        self.copydata(self.request['userName'], self.request['fileName'], self.datafileIds)


    def createuser(self, username):
        self.logger.debug("Attempting to create user: %s" % username)
    
        if re.match('^[\w-]+$', username) == None:
            raise OSError("Username contains non-alphanumeric characters")

        params = (
            username,
            self.config.get('globus', 'DESTINATION'),
            username
        )    

        if os.system("useradd %s -d %s/%s" % params) == 0:
            self.logger.info("Creating new local user account for: %s" % username)
        else:
            self.logger.warn("Unable to create locate user account for: %s" % username)
    
    
    def copydata(self, username, downloadname, datafileIds):
        SOURCE = self.config.get('globus', 'SOURCE')
        DESTINATION = self.config.get('globus', 'DESTINATION')
    
        if os.path.exists(DESTINATION + '/' + username + '/' + downloadname):
            self.logger.warn("Download name already exists. Changing to %s_2" % downloadname)
            downloadname = downloadname + "_2"
    
        for ids in chunks(datafileIds, int(self.config.get('globus', 'LOCATION_CHUNKS'))):
            query = 'SELECT df.location FROM Datafile df WHERE df.id IN (%s)' % ids
            for location in getICAT(self.config).search(query):
                source = "%s/%s" % (SOURCE, location)
                destination = "%s/%s/%s/%s" % (DESTINATION, username, downloadname, location)
    
                destination_dir = os.path.dirname(destination)
                if not os.path.isdir(destination_dir):
                    self.logger.debug("Creating directory %s" % destination_dir)
                    os.makedirs(destination_dir)
            
                self.logger.debug("Copying file %s -> %s" % (source, destination))
                shutil.copy(source, destination)
