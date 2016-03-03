import os
import time
import requests
import json
import re
import shutil
import icat
import logging
import logging.config
import ConfigParser

def chunks(l, n):
    # Split a list into chunks of comma separated strings of size n
    return [",".join(str(j) for j in l[i:i + n]) for i in range(0, len(l), n)]


def getICAT():
    try:
        icatclient.ping()
    except:
        icatclient = icat.client.Client(config.get('main', 'ICAT_URL') + "/ICATService/ICAT?wsdl")
        icatclient.login('db', {
            'username' : config.get('main', 'ICAT_USER'),
            'password' : config.get('main', 'ICAT_PASSWD').decode("utf8")
        })
    return icatclient


def updateDownloadRequest(preparedId, downloadid):
    logger.info("Request %s finished, marking as complete" % preparedId)
    requests.put(
        url=config.get('main', 'TOPCAT_URL') + '/api/v1/admin/download/' + str(downloadid) + '/status',
        params={
            'icatUrl'   : config.get('main', 'ICAT_URL'), 
            'sessionId' : getICAT().sessionId,
            'value'     : 'COMPLETE'
        }
    )


def createuser(username):
    logger.debug("Attempting to create user: %s" % username)
    params = (
        re.sub(r'[^a-zA-Z0-9=]', '', username), # make username safe
        config.get('main', 'DESTINATION'),
        re.sub(r'[^a-zA-Z0-9=]', '', username)
    )
    ret = os.system("useradd %s -d %s/%s" % params)
    if ret == 0:
        logger.info("Creating new local user account for: %s" % username)


def copydata(username, downloadname, dfids):
    SOURCE = config.get('main', 'SOURCE')
    DESTINATION = config.get('main', 'DESTINATION')

    if os.path.exists(DESTINATION + '/' + username + '/' + downloadname):
        logger.warn("Download name already exists. Changing to %s_2" % downloadname)
        downloadname = downloadname + "_2"

    for ids in chunks(dfids, int(config.get('main', 'LOCATION_CHUNKS'))):
        query = 'SELECT df.location FROM Datafile df WHERE df.id IN (%s)' % ids
        for dflocation in getICAT().search(query):
            source = "%s/%s" % (SOURCE, dflocation)
            destination = "%s/%s/%s/%s" % (DESTINATION, username, downloadname, dflocation)

            destination_dir = os.path.dirname(destination)
            if not os.path.isdir(destination_dir):
                logger.debug("Creating directory %s" % destination_dir)
                os.makedirs(destination_dir)
        
            logger.debug("Copying file %s -> %s" % (source, destination))
            shutil.copy(source, destination)


def checkstatus(preparedId, dfids):
    """
    Check each datafile to see if ONLINE
    Break out on first occurance of non restored file
    """
    isready = True
    for ids in chunks(dfids, int(config.get('main', 'STATUS_CHUNKS'))):
        response = requests.get(
            url=config.get('main', 'IDS_URL') + '/ids/getStatus',
            params={'datafileIds' : ids},
            timeout=15
        )
        if response.status_code != 200:
            logger.error("Problem contacting the IDS")
            isready = False
            break
        if response.text != "ONLINE":
            isready = False
            break

    return isready


def getDatafileIds(preparedId):
    logger.debug("Retrieving datafileIds for %s" % preparedId)
    response = requests.get(
        url=config.get('main', 'IDS_URL') + '/ids/getDatafileIds',
        timeout=int(config.get('main', 'DATAFILEIDS_TIMEOUT')),
        params={'preparedId' : preparedId}
    )
    return json.loads(response.text)['ids']


def getDownloadRequests():
    logger.debug("Retrieving Globus download requests from TopCAT")
    response = requests.get(
        url=config.get('main', 'TOPCAT_URL') + '/api/v1/admin/downloads',
        params={
            'icatUrl'     : config.get('main', 'ICAT_URL'), 
            'sessionId'   : getICAT().sessionId,
            'queryOffset' : "where download.transport = 'globus' and " + 
                            "download.isDeleted = false and download.status != " +
                            "org.icatproject.topcat.domain.DownloadStatus.COMPLETE"
        }
    )
    downloadrequests = json.loads(response.text)
    logger.debug("Found %s pending requests" % str(len(downloadrequests)))
    return downloadrequests


def mainloop():
    for request in getDownloadRequests():
        dfids = getDatafileIds(request['preparedId'])
        if checkstatus(request['preparedId'], dfids):
            logger.info("Request %s _IS_ ready" % request['preparedId'])
            try:
                createuser(request['userName'])
                copydata(request['userName'], request['fileName'], dfids)
                updateDownloadRequest(request['preparedId'], request['id'])
            except Exception, e:
                logger.error("Request failed: %s" % request['preparedId'], exc_info=True)
                continue
        else:
            logger.info("Request %s _IS_NOT_ ready" % request['preparedId'])
            continue


if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('pollcat.config')

    logging.config.fileConfig('logging.ini')
    logger = logging.getLogger('root')

    icatclient = None

    while True:
        try:
            mainloop()
        except Exception as e:
            logger.error("Mainloop has unexpectedly stopped", exc_info=True)

        time.sleep(float(config.get('main', 'DELAY')))

