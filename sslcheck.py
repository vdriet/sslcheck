""" SSL-checker """
import socket
import ssl
from datetime import datetime

import pydig
import requests
import urllib3
from flask import Flask, request
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
    return True, hostlist
  if ipversion == 'ipv6':
    hostlist = getip6(host)
    ret = []
    for ipaddress in hostlist:
      if '.' not in ipaddress:
        ret.append(ipaddress)
    return True, ret
  return False, []


def gethttpstatus(host, ipaddress):
  """ get HTTP-status from host """
  try:
    headers = {'Host': f'{host}'}
    url = f'https://{ipaddress}'
    req = requests.get(url, headers=headers, verify=False, timeout=6, allow_redirects=False)
    return req.status_code
  except requests.ConnectionError:
    return 'failed to connect'


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
    validdate = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

    ret['CN'] = issued_to
    ret['issuer'] = issued_by
    ret['validuntil'] = validdate.strftime('%Y-%m-%d %H:%M:%S')
    return ret


def gettlsinfo(host, ipversion='ipv4'):
  """ get TLS information from host """
  ret = {}
  if ipversion == 'ipv6':
    sock_type = socket.AF_INET6
  else:
    sock_type = socket.AF_INET
  for ver in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ver
    ctx.maximum_version = ver
    socks = socket.socket(sock_type)
    socks.settimeout(5.0)
    with ctx.wrap_socket(socks, server_hostname=host) as soc:
      try:
        soc.connect((host, 443))
        ret[ver.name] = True  # pylint: disable=no-member
      except IOError:
        ret[ver.name] = False  # pylint: disable=no-member
  return ret


def getipinfo(host, ipversion='ipv4'):
  """ get info from host """
  data = {}
  ipaddressdata = []
  ipfound, iplijst = getip(host, ipversion)
  if ipfound:
    for ipaddress in iplijst:
      ipdata = {'ip': ipaddress}
      if ipversion == 'ipv6':
        ipaddress = f'[{ipaddress}]'
      response = gethttpstatus(host, ipaddress)
      ipdata['httpreponse'] = response
      ipaddressdata.append(ipdata)
    data['addresses'] = ipaddressdata
    certinfo = getcertinfo(host, ipversion)
    data['cert'] = certinfo
    tlsinfo = gettlsinfo(host, ipversion)
    data['tls'] = tlsinfo
  return data


def getinfo(host):
  """ get all information from host """
  data = {'host': host}
  ipresponses = {'ipv4data': getipinfo(host), 'ipv6data': getipinfo(host, 'ipv6')}
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
