import icat
import icat.client

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


def getICAT(config):
    """
    Check if ICAT session still valid and then return an ICAT client object  

    Parameters:
        config - a config parser object containing connection information for
                 ICAT
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
