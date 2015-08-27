#!/usr/bin/python
## basic script to query circ.lu passivedns
## https://www.circl.lu/services/passive-dns/
##
## NEED: pypdns
## in: ip list as stdin or one ip argument
## out: input data; json pdns output

import pypdns
import sys
import traceback
import re
import datetime
import json
import argparse

w_network = 1
w_remotesyslog = 1
CIRCL_USER = ''
CIRCL_PASS =  ''
#from os.path import expanduser
#home = expanduser("~")
GEODB_DIR = '/home/vagrant/cdev/data'

import logging
#import logging.handlers
from logging.handlers import SysLogHandler
import socket
class ContextFilter(logging.Filter):
  hostname = socket.gethostname()

  def filter(self, record):
    record.hostname = ContextFilter.hostname
    return True

## FIXME! no more control on verbosity of both script and modules (or comment those lines)
if w_remotesyslog == 1:
	logger = logging.getLogger()
	logger.setLevel(logging.INFO)
	syslog = SysLogHandler(address='/dev/log')
	#syslog = logging.handlers.SysLogHandler(address = ('IP', PORT))
	#formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
	formatter = logging.Formatter('pdns-query: %(message)s')
	syslog.setFormatter(formatter)
	logger.addHandler(syslog)

#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", filename='debug.log',level=logging.DEBUG)
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", level=logging.DEBUG, stream=sys.stderr)
logging.basicConfig(level=logging.ERROR)

## https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
#logging.captureWarnings(True)
## https://github.com/shazow/urllib3/issues/497
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()


from netaddr import IPAddress
def is_ip(address):
    try:
        ip = IPAddress(address)
        return True
    except:
        return False

import pygeoip
gi1 = pygeoip.GeoIP(GEODB_DIR + '/GeoIPASNum.dat', pygeoip.MEMORY_CACHE)
gi2 = pygeoip.GeoIP(GEODB_DIR + '/GeoLiteCity.dat', pygeoip.MEMORY_CACHE)

def org_by_addr(address):
    if is_ip(address):
    	logging.debug("geolocate " + str(address))
        gias = gi1.org_by_addr(address)
        logging.debug("geo: " + str(gias))
	as_num, sep, as_name = str(gias).partition(' ')
        as_num = as_num.replace("AS", "")
        return as_num, as_name
    else:
	return None, None

def cc_by_addr(address):
    if is_ip(address):
    	logging.debug("geolocate " + str(address))
        geo_data = gi2.country_code_by_addr(address)
        logging.debug("geo: " + str(geo_data))
	return geo_data
    else:
	return None


def passivedns_data(uri):
    global CIRCL_USER
    global CIRCL_PASS
    if w_network == 1:
        uri = re.sub(r'^www\.', '', uri)
        try:
            logging.debug("querying circl.lu for " + str(uri))
            r = pypdns.PyPDNS('https://www.circl.lu/pdns/query', (CIRCL_USER, CIRCL_PASS), enable_cache=True)
            q = r.query(uri)
            logging.debug("q " + str(q))
            return q
        except Exception, e:
            return "Passive DNS: error " + str(e)
    else:
        return "Network call disabled"

# return anomalylevel, summary, time_first, time_last, raw 
def enrich(pdnsret):
    anomalylevel = 0
    count = counta = countns = countcname = countcountry = countas = 0
    time_first = datetime.datetime.utcnow()
    time_last = datetime.datetime(1970, 1, 1, 0, 0)
    listcountry = []
    listas = []
    pdnssum = ''
    logging.debug("pdnsret is " + str(pdnsret))
    if pdnsret == []:
        return
    logging.debug("len pdnsret is " + str(len(pdnsret)))
    if len(pdnsret) == 6:
        pdnsret = [ pdnsret ]
    #logging.debug("pdnsret is " + str(pdnsret))
    try: 
        for p in pdnsret:
            logging.debug("pdnsjson p: " + str(p))
            if p[u'time_first'] < time_first:
                time_first = p[u'time_first']
            if p[u'time_last'] > time_last:
                time_last = p[u'time_last']
            if p[u'rrtype'] == u'A':
                counta += 1
            elif p[u'rrtype'] == u'NS':
                countns += 1
            elif p[u'rrtype'] == u'CNAME':
                countcname += 1
            count += 1
            try:
		as_num, as_name = org_by_addr(p[u'rdata'])
		cc = cc_by_addr(p[u'rdata'])
                if as_num is not None:
			listas.append(as_num)
                if cc is not None:
			listcountry.append(cc)
            except Exception, e:
                logging.error("fail to geoip: " + str(e))
        
	listas = list(set(listas))
	listcountry = list(set(listcountry))
        if counta == 0 or countns == 0:
            anomalylevel = 1
        if counta > 20:
            anomalylevel = 2
        if countns > 10:
            anomalylevel = 2
	if listas > 2 or listcountry > 2:
            anomalylevel = 3

        summary = str(count) + ' (A:' + str(counta) + '; NS:' + str(countns) + '; CNAME:' + str(countcname) + ") (AS: " + str(listas).strip('[]') + "; CC: " + str(listcountry).strip('[]') + ")"
        return anomalylevel, summary, time_first, time_last, count, counta, countns, countcname, listas, listcountry
	
    except Exception, e:
        logging.error("Error for " + str(pdnsret) + ": " + str(e))
        traceback.print_exc()
	return None, None, None, None, None, None, None, None, None

# CEF Format -> CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
# Sample output CEF:0|PassiveDNS-CIRCL|API|1.0|10000|CIRCL PassiveDNS match on xxx|$anomalylevel|PDNS Count|PDNS First seen|PDNS Last seen
def pdns2cef(pdnsret):
    anomalylevel, summary, time_first, time_last, count, counta, countns, countcname, listas, listcountry = enrich(pdnsret)
    if anomalylevel > 0:
        return "CEF:0|PassiveDNS-CIRCL|API|1.0|10000|CIRCL PassiveDNS match on " + str(pdnsret[0]['rrname']) + "|" + str(anomalylevel) + "|" + str(summary) + "|"  + str(time_first) + '|' + str(time_last) + '|' + str(count) + '|' + str(counta) + '|' + str(countns) + '|' + str(countcname) + '|' + str(listas).strip('[]') + '|' + str(listcountry).strip('[]') + '|' + str(pdnsret)
    else:
	return None

        
## either take stdin (one or multiple lines), either one argument
def main():
    parser = argparse.ArgumentParser(
        description='Query CIRCL PassiveDNS service.',
        prog='pdns-query.py',
        usage='%(prog)s [options] [domain]'
        )
    parser.add_argument('-t', '--type', help="Specify output type: CSV (default), CEF")
    parser.add_argument('-s', '--syslog', help="Send output to syslog too", action="store_true")
    parser.add_argument('argstring', metavar='STR', type=str, nargs='?',
                       help='a domain or a file containing domains')
    possible_types = [ 'csv', 'cef' ]
    args = parser.parse_args()

    if not args.type:
        out_type = 'csv'
    elif args.type.lower() not in possible_types:
        sys.exit('Invalid file type specified. Possible types are: %s' % possible_types)
    else:
        out_type = args.type.lower()

    try:
        logging.debug("starting: " + str(len(sys.argv)))
        if args.argstring:
            logging.debug("input as argument: " + args.argstring)
            ret = passivedns_data(args.argstring)
            logging.debug("ret line: " + str(ret).strip())
	    if "Passive DNS: error " in ret:
		print (ret)
            elif out_type == 'cef' and ret != []:
                cefret = pdns2cef(ret)
                if cefret:
                    print cefret
                    if args.syslog:
                        logger.info(cefret)
            else:
                print str(ret).strip('[]')
        else:
            logging.debug("input as stdin")
            for line in sys.stdin:
                logging.debug("input line: " + line.strip())
                ret = passivedns_data(line.strip())
                logging.debug("ret line: " + str(ret).strip('[]'))
		if "Passive DNS: error " in str(ret):
			print "Error: " + str(ret).strip('[]')
			continue
                if out_type == 'cef':
                    cefret = pdns2cef(ret)
                    if cefret:
                        print cefret
                        if args.syslog:
                            logger.info(cefret)
                else:
                    print line.strip() + ';' + str(passivedns_data(line.strip()))

        logging.debug("ending")
    except KeyboardInterrupt:
        print 'Goodbye Cruel World...'
        sys.exit(0)
    except Exception, error:
        traceback.print_exc()
        print '(Exception):, %s' % (str(error))
        sys.exit(1)

if __name__ == '__main__':
    main()

