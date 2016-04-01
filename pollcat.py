import time
import requests
import json
import logging
import logging.config
import ConfigParser
import importlib

from common import *

def checkDatafileStatus(preparedId, dfids):
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
    """
    Get a list of all datafile ids associated with the preparedId
    """
    logger.debug("Retrieving datafileIds for %s" % preparedId)
    response = requests.get(
        url=config.get('main', 'IDS_URL') + '/ids/getDatafileIds',
        timeout=int(config.get('main', 'DATAFILEIDS_TIMEOUT')),
        params={'preparedId' : preparedId}
    )
    return json.loads(response.text)['ids']


def updateDownloadRequest(preparedId, downloadid):
    logger.info("Request %s finished, marking as complete" % preparedId)
    r = requests.put(
        url=config.get('main', 'TOPCAT_URL') + 'api/v1/admin/download/' + str(downloadid) + '/status',
        params={
            'icatUrl'   : config.get('main', 'ICAT_URL'), 
            'sessionId' : getICAT(config).sessionId,
            'value'     : 'COMPLETE'
        },
        headers={"Content-type": "application/x-www-form-urlencoded; charset=UTF-8"}
    )


def getDownloadRequests():
    logger.debug("Retrieving Globus download requests from TopCAT")
    response = requests.get(
        url=config.get('main', 'TOPCAT_URL') + '/api/v1/admin/downloads',
        params={
            'icatUrl'     : config.get('main', 'ICAT_URL'), 
            'sessionId'   : getICAT(config).sessionId,
            'queryOffset' : "where download.transport = 'globus' and " + 
                            "download.isDeleted = false and download.status = " +
                            "org.icatproject.topcat.domain.DownloadStatus.RESTORING"
        }
    )
    downloadrequests = json.loads(response.text)
    logger.debug("Found %s pending requests" % str(len(downloadrequests)))
    return downloadrequests


def mainloop():
    for request in getDownloadRequests():
        datafileIds = getDatafileIds(request['preparedId'])
        if checkDatafileStatus(request['preparedId'], datafileIds):
            logger.info("Request %s _IS_ ready" % request['preparedId'])
            try:
                # import plugin class and execute the run method
                module = importlib.import_module(
                    "plugins." + 
                    config.get('main', 'PLUGIN_NAME') + "." +
                    config.get('main', 'PLUGIN_NAME')
                )
                plugin_class = getattr(module, 'Plugin')
                logger.debug("Initilising plugin: %s" % config.get('main', 'PLUGIN_NAME'))
                plugin = plugin_class(request, datafileIds, config, logger)
                logger.debug("Running plugin")
                plugin.run()
            except Exception, e:
                logger.error("%s plugin failed" % config.get('main', 'PLUGIN_NAME'), exc_info=True)
                continue
            updateDownloadRequest(request['preparedId'], request['id'])
        else:
            logger.info("Request %s _IS_NOT_ ready" % request['preparedId'])
            continue


if __name__ == "__main__":
    config = ConfigParser.ConfigParser()
    config.read('pollcat.config')

    logging.config.fileConfig('logging.ini')
    logger = logging.getLogger('root')

    while True:
        try:
            mainloop()
        except Exception as e:
            logger.error("Mainloop has unexpectedly stopped", exc_info=True)

        time.sleep(float(config.get('main', 'DELAY')))

