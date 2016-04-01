import icat

def chunks(l, n):
    # Split a list into chunks of comma separated strings of size n
    return [",".join(str(j) for j in l[i:i + n]) for i in range(0, len(l), n)]


def getICAT(config):
    """
    Check the status of 
    """
    try:
        icatclient.refresh()
    except:
        url = config.get('main', 'ICAT_URL') + "/ICATService/ICAT?wsdl"
        icatclient = icat.client.Client(url)
        icatclient.login('db', {
            'username' : config.get('main', 'ICAT_USER'),
            'password' : config.get('main', 'ICAT_PASSWD').decode("utf8")
        })
    return icatclient