""" SSL-checker """
import socket
import ssl

import pydig
import requests
import urllib3
from flask import Flask
from flask import request
from waitress import serve

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def dodig(host, recordtype):
    """ DIG """
    return pydig.query(host, recordtype)


def getip4(host):
    """ get IPv4 address from host """
    return dodig(host, 'A')


def getip6(host):
    """ get IPv6 address from host """
    return dodig(host, 'AAAA')


def getip(host, ipversion='ipv4'):
    """ get IP address from host """
    if ipversion == 'ipv4':
        hostlist = getip4(host)
        return hostlist, hostlist
    if ipversion == 'ipv6':
        hostlist = getip6(host)
        ret = []
        for ipaddress in hostlist:
            if '.' not in ipaddress:
                ret.append(ipaddress)
        return ret, ret
    return False, []


def gethttpstatus(host, ipaddress):
    """ get HTTP-status from host """
    ret = ''
    try:
        print(f'Get status for {host} on {ipaddress}')
        headers = {'Host': f'{host}'}
        url = f'https://{ipaddress}'
        req = requests.get(url, headers=headers, verify=False, timeout=6, allow_redirects=False)
        ret = req.status_code
    except requests.ConnectionError:
        return 'failed to connect'
    return ret


def getcertinfo(host, ipversion='ipv4'):
    """ get information from certificate from host """
    ret = {}
    if ipversion == 'ipv6':
        sock_type = socket.AF_INET6
    else:
        sock_type = socket.AF_INET
    ctx = ssl.create_default_context()
    socks = socket.socket(sock_type)
    socks.settimeout(5.0)
    with ctx.wrap_socket(socks, server_hostname=host) as soc:
        print(f'Get cert for {host}')
        try:
            soc.connect((host, 443))
        except IOError:
            ret['error'] = 'Error getting cert'
            return ret
        cert = soc.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject['commonName']
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer['commonName']
        validdate = cert['notAfter']

        ret['CN'] = issued_to
        ret['Issuer'] =issued_by
        ret['ValidUntil'] = validdate
        return ret


def getinfo(host):
    """ get all information from host """
    data = {}
    data['host'] = host
    ipresponses = []
    ipv4found, ipv4lijst = getip(host)
    if ipv4found:
        for ipaddress in ipv4lijst:
            ipdata = {}
            ipdata['ip'] = ipaddress
            response = gethttpstatus(host, ipaddress)
            ipdata['HTTP reponse'] = response
            ipresponses.append(ipdata)
        certinfo = getcertinfo(host)
        data['ipv4cert'] = certinfo

    ipv6found, ipv6lijst = getip(host, 'ipv6')
    if ipv6found:
        for ipaddress in ipv6lijst:
            ipdata = {}
            ipdata['ip'] = ipaddress
            formattedip = f'[{ipaddress}]'
            response = gethttpstatus(host, formattedip)
            ipdata['HTTP reponse'] = response
            ipresponses.append(ipdata)
        certinfo = getcertinfo(host, 'ipv6')
        data['ipv6cert'] = certinfo
    data['ipresponses'] = ipresponses
    return data


@app.route('/sslcheck', methods=['GET'])
def sslcheckget():
    """ get """
    return 'OK'

@app.route('/sslcheck', methods=['POST'])
def sslcheckpost():
    """ post """
    apikey = None
    host = None
    for header in request.headers:
        if header[0] == 'Apikey':
            apikey = header[1]
        if header[0] == 'Hostname':
            host = header[1]
    if apikey is None or apikey != 'MySecret':
        return 'Invalid apikey'
    if host is None:
        return 'No host given'
    return getinfo(host)

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=8082)
