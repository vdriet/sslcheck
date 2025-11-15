""" SSL-checker """
import os
import socket
import ssl
from datetime import datetime
from typing import Any

import pydig
import requests
from flask import Flask, request
from dotenv import load_dotenv

from waitress import serve

app = Flask(__name__)
load_dotenv()

secretapikey = os.getenv('SECRETAPIKEY', default='MySecret')


def dodig(host: str, recordtype: str) -> list[str]:
  """
  Executes a DNS query for a specified host and record type and returns the DNS
  query result.

  This function enables querying DNS records based on a given host and record
  type, facilitating DNS resolution and record retrieval. It leverages the
  pydig library to perform the query.

  Args:
      host (str): The hostname or domain to query.
      recordtype (str): The type of DNS record to query, such as 'A', 'MX', 'TXT', etc.

  Returns:
      list[str]: A list of DNS query results related to the specified host and
      record type.
  """
  return pydig.query(host, recordtype)


def getip4(host: str) -> list[str]:
  """
  Resolves and retrieves the IPv4 address for a given host.

  Determines the IPv4 address associated with the specified host by using
  a dedicated function to perform an 'A' record DNS query.

  Parameters:
      host: str
          The host for which the IPv4 address is to be resolved.

  Returns:
      list[str]
          The IPv4 address for the provided host.

  Raises:
      Any exceptions that may occur during DNS resolution.
  """
  return dodig(host, 'A')


def getip6(host: str) -> list[str]:
  """
  Resolves the IPv6 address for a given host.

  This function retrieves the IPv6 address associated with the specified host by
  performing a DNS query for the 'AAAA' record.

  Args:
      host (str): The hostname for which the IPv6 address is to be resolved.

  Returns:
      list[str]: List with the IPv6 addresses of the given host.
  """
  return dodig(host, 'AAAA')


def getip(host: str, ipversion: str = 'ipv4') -> tuple[bool, list[str]]:
  """
  Resolves the IP addresses of a given host based on the specified IP version.

  This function retrieves IP addresses for a hostname based on whether the user
  requests IPv4 or IPv6 addresses. It handles the filtering of IPv6 addresses to
  exclude any that are represented in dot-decimal notation.

  Parameters:
      host: str
          The hostname for which to resolve IP addresses.
      ipversion: str
          Specifies the IP version, either 'ipv4' or 'ipv6'. Defaults to 'ipv4'.

  Returns:
      tuple[bool, list[str]]
          A tuple where the first element is a boolean indicating success or
          failure. The second element is a list of resolved IP addresses. For
          'ipv4', it contains IPv4 addresses. For 'ipv6', it contains
          non-dot-decimal IPv6 addresses.
  """
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


def gethttpstatus(host: str, ipaddress: str) -> str:
  """
  Get the HTTP status code for a specified host and IP address.

  This function sends an HTTP GET request to the provided IP address and specifies
  the `Host` in the headers for the request. It disables SSL verification and applies
  a timeout of 6 seconds, along with preventing automatic redirects. If the request
  is successful, it returns the HTTP status code. Otherwise, it handles connection
  errors and returns a failure message.

  Parameters:
  host: str
      The host/domain to be set in the request headers.
  ipaddress: str
      The IP address where the HTTP GET request is to be sent.

  Returns:
  int or str
      Returns the HTTP status code as an integer on a successful connection, or the
      string 'failed to connect' if there is a connection error.
  """
  try:
    headers = {'Host': f'{host}'}
    url = f'https://{ipaddress}'
    req = requests.get(url, headers=headers, verify=False, timeout=6, allow_redirects=False)
    return f'{req.status_code}'
  except requests.ConnectionError:
    return 'failed to connect'


def getcertinfo(host: str, ipversion: str = 'ipv4') -> dict:
  """
  Retrieves the SSL certificate details of a given host specifying the IP version.

  The function establishes a secure connection to the given host, fetches the SSL
  certificate, and extracts information such as the common name (CN) of the
  certificate, the issuer's common name, and the validity period of the certificate.
  If an error occurs while attempting to establish a connection or retrieve the
  certificate, an error message is included in the return dictionary.

  Parameters:
  host: str
    The hostname of the server for which the SSL certificate information is retrieved.
  ipversion: str
    The IP version to be used for the connection. Defaults to 'ipv4'. Supported
    options are 'ipv4' and 'ipv6'.

  Returns:
  dict
    A dictionary containing the extracted certificate information or an error message
    in case of failure.

  Raises:
  IOError
    If an error occurs during the connection or SSL handshake process.
  """
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


def gettlsinfo(host: str, ipversion: str = 'ipv4') -> dict[str, bool]:
  """
Get the supported TLS versions for a given host.

This function checks the provided host for its support for specific versions
of TLS protocols by establishing secure sockets using SSL/TLS configurations
with predefined minimum and maximum versions. It supports both IPv4 and IPv6
connections as specified by the user.

Arguments:
    host (str): The hostname of the server to test for supported TLS versions.
    ipversion (str): Specify whether to use 'ipv4' or 'ipv6' for the connection.
        Defaults to 'ipv4'.

Returns:
    dict: A dictionary where the keys are strings representing the names of
    the TLS versions and the values are booleans indicating support for that
    version.
"""
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


def getipinfo(host: str, ipversion: str = 'ipv4') -> dict:
  """
Fetches IP information, HTTP response status, TLS information, and certificate data
for the given host and IP version.

This function retrieves the list of IP addresses for a specified host and IP version
(IPv4 or IPv6), checks their HTTP response status, fetches TLS connection details, and
retrieves certificate information. It returns this aggregated data in a structured format.

Parameters:
host: str
    The hostname for which information is to be retrieved.
ipversion: str
    The IP version to use, either 'ipv4' or 'ipv6'. Defaults to 'ipv4'.

Returns:
dict
    A dictionary containing the addresses list, TLS information, and certificate
    details. The structure of the dictionary is as follows:
    - addresses: A list of dictionaries, where each dictionary has:
        - ip: str, the IP address.
        - httpreponse: varies, the HTTP response status for the given IP.
    - cert: varies, details of the host's certificate.
    - tls: varies, TLS configuration information associated with the host.
"""
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


def getinfo(host: str) -> dict:
  """
Gets detailed information about a given host, including its IPv4 and IPv6
information.

Parameters:
host (str): The hostname or IP address for which information is being
retrieved.

Returns:
dict: A dictionary containing the `host` and `ipresponses`. The `ipresponses`
key contains another dictionary with keys `ipv4data` and `ipv6data` that hold
information for IPv4 and IPv6, respectively.
"""
  data: dict[str, Any] = {'host': host}
  ipresponses = {'ipv4data': getipinfo(host), 'ipv6data': getipinfo(host, 'ipv6')}
  data['ipresponses'] = ipresponses
  return data


@app.route('/sslcheck', methods=['GET'])
def sslcheckget() -> str:
  """
Handles GET requests to the '/sslcheck' endpoint.

This function is a simple handler for SSL check. It responds to a GET request
to verify the SSL status of the server.

Returns:
    str: This function always returns the string 'OK', indicating the service runs.
"""
  return 'OK'


@app.route('/sslcheck/dig/<host>', methods=['GET'])
def sslcheckdigget(host: str) -> str:
  """
  Handles GET requests to the '/sslcheck/dig' endpoint.

  This function is a simple handler for SSL check. It responds to a GET request
  to get dig informatie for a URL.

  Returns:
      str: This function returns dig information.
  """
  types = ["A",
           "AAAA",
           "CAA",
           "CNAME",
           "DNSKEY",
           "DS",
           "MX",
           "NS",
           "PTR",
           "SOA",
           "TXT",]
  records = {}
  ret = f'Host: {host}'
  for rectype in types:
    values = []
    try:
      values = dodig(host, rectype)
    except:
      print(rectype)
    if len(values) > 0:
      records[rectype] = values
      ret = f'{ret}<br/>{rectype}: {values}<br/>'
  return ret


@app.route('/sslcheck', methods=['POST'])
def sslcheckpost() -> str or dict:
  """
Handles SSL certificate check requests via a POST method.

This function validates the presence and correctness of an API key in the
request headers before extracting the specified hostname. If the API key
is missing or invalid, or if the hostname is not provided, an appropriate
response is returned to the client. If all headers are valid,
it delegates hostname processing to another function (e.g., getinfo).

Returns either:
    str: Error message if the API key is missing or invalid, or if the hostname is not provided.
    dict: A dictionary with the properties of the requested host.
"""
  apikey = None
  host = None
  for header in request.headers:
    if header[0] == 'Apikey':
      apikey = header[1]
    if header[0] == 'Hostname':
      host = header[1]
  if apikey is None or apikey != secretapikey:
    return 'Invalid apikey'
  if host is None:
    return 'No host given'
  return getinfo(host)


if __name__ == '__main__':
  serve(app, host="0.0.0.0", port=8082)
