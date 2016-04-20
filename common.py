import icat


class IcatClient(object):
    """
    Simple wrapper around python-icat that checks to see if session
    is valid before returning the client. If it has expired, a new
    session in initiated.
    """

    def __init__(self, config):
        self.config = config

    def getInstance(self):
        try:
            self.icatclient.refresh()
        except:
            url = self.config.get('main', 'ICAT_URL') + "/ICATService/ICAT?wsdl"
            self.icatclient = icat.client.Client(url)
            self.icatclient.login('db', {
                'username' : self.config.get('main', 'ICAT_USER'),
                'password' : self.config.get('main', 'ICAT_PASSWD').decode("utf8")
            })
        return self.icatclient


def chunks(l, n):
    """
    Split a list of integers into a list of comma separated strings which
    are grouped into chunks of size n.

    chunks([1,2,3,4,5,6,7,8,9], 3) -> ["1,2,3", "4,5,6", "7,8,9"] 

    Parameters:
        l - a list of integers
        n - the chunk size
    """
    return [",".join(str(j) for j in l[i:i + n]) for i in range(0, len(l), n)]
