
"""
SCARF Plugin for PollCAT
"""

class Plugin(object):

    def __init__(self, request, datafileIds, config, logger):
        self.request = request
        self.datafileIds = datafileIds
        self.config = config
        self.logger = logger

        # merge scarf config with main pollcat config
        self.config.read('plugins/scarf/scarf.config')


    def run(self):
        self.debug("run() function for SCARF plugin executed")
