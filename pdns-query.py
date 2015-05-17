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

import logging
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", filename='debug.log',level=logging.DEBUG)
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", level=logging.DEBUG, stream=sys.stderr)
logging.basicConfig(level=logging.ERROR)

## https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
logging.captureWarnings(True)

w_network = 1
CIRCL_USER = ''
CIRCL_PASS =  ''

def passivedns_data(uri):
    global CIRCL_USER
    global CIRCL_PASS
    if w_network == 1:
        uri = re.sub(r'^www\.', '', uri)
        try:
            logging.debug("querying circl.lu for " + str(uri))
            r = pypdns.PyPDNS('https://www.circl.lu/pdns/query', (CIRCL_USER, CIRCL_PASS), enable_cache=True)
            q = r.query(uri)
            return q
        except Exception, e:
            return "Passive DNS: error " + str(e)
    else:
        return "Network call disabled"

# CEF Format -> CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
# Sample output CEF:0|PassiveDNS-CIRCL|API|1.0|10000|CIRCL PassiveDNS match on xxx|$severity|PDNS Count|PDNS First seen|PDNS Last seen
def pdns2cef(pdnsret):
    severity = 0
    count = counta = countns = countcname = 0
    time_first = datetime.datetime.utcnow()
    time_last = datetime.datetime(1970, 1, 1, 0, 0)
    pdnssum = ''
#    pdnsret = json.loads(jsonin)
    logging.debug("pdnsret is " + str(pdnsret))
    if pdnsret == []:
        return
    logging.debug("len pdnsret is " + str(len(pdnsret)))
    if len(pdnsret) == 6:
        pdnsret = [ pdnsret ]
    logging.debug("pdnsret is " + str(pdnsret))
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
        if counta == 0 or countns == 0:
            severity = 1
        if counta > 20:
            severity = 2
        if countns > 10:
            severity = 2
        if severity > 0:
            return "CEF:0|PassiveDNS-CIRCL|API|1.0|10000|CIRCL PassiveDNS match on " + str(pdnsret[0]['rrname']) + "|" + str(severity) + "|" + str(count) + ' (A:' + str(counta) + '; NS:' + str(countns) + '; CNAME:' + str(countcname) + ")|"  + str(time_first) + '|' + str(time_last) + '|' + str(pdnsret[0])
    except Exception, e:
        logging.error("Erreur pdns2cef for " + str(pdnsret) + ": " + str(e))
        traceback.print_exc()

        
## either take stdin (one or multiple lines), either one argument
def main():
    parser = argparse.ArgumentParser(
        description='Query CIRCL PassiveDNS service.',
        prog='pdns-query.py',
        usage='%(prog)s [options]'
        )
    parser.add_argument('-t', '--type', help="Specify output type: CSV (default), CEF")
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
        try:
            logging.debug("input as argument: " + args.argstring)
            ret = passivedns_data(args.argstring)
            if out_type == 'cef' and ret != []:
                cefret = pdns2cef(ret[0])
                if cefret:
                    print cefret
            else:
                print str(ret[0])
        except:
            logging.debug("input as stdin")
            for line in sys.stdin:
                logging.debug("input line: " + line.strip())
                ret = passivedns_data(line.strip())
                if out_type == 'cef':
                    cefret = pdns2cef(ret)
                    if cefret:
                        print cefret
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

