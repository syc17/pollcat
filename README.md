PollCAT
=======

PollCAT is a small bit of glue logic that moves data requested via TopCATv2
into users home directories, ready for Globus Online Transfers.

It sits along side TopCATv2 and the ICAT Data Service (IDS) where it
periodically queries the TopCAT admin interface looking for Globus download 
requests. For each request, PollCAT waits for the IDS to retrieve files from
tape. When the IDS changes the status of the request from RESTORING to ONLINE,
pollcat then copies the requested files to the users local home directory and
informs TopCAT that the request is now COMPLETE.

Requirements:

* python-icat     - Avaliable from https://github.com/icatproject/python-icat
* python-requests - Can be installed using yum / apt-get

Files:

* pollcat.config - Make sure you set all the values in here before starting.
* pollcat.py     - The script that pollcatd will call.
* pollcatd       - Use this file to start, stop and check the status of the
                   PollCAT script eg. ./pollcatd status

