""" testen voor de slackbot datumfuncties """
import unittest
from unittest.mock import patch, MagicMock

import sslcheck


class TestDig(unittest.TestCase):
  certinfo = {'CN': 'vanderiethattem.nl',
              'issuer': 'CA',
              'validuntil': '2024-12-29 10:11:12'}

  @patch('sslcheck.gettlsinfo', side_effect=[{'TLSv1_2': False, 'TLSv1_3': True}, {'TLSv1_2': True, 'TLSv1_3': False}])
  @patch('sslcheck.getcertinfo', side_effect=[certinfo, certinfo])
  @patch('pydig.query', side_effect=[['1.2.3.4'], ['1:2::3:0']])
  @patch('requests.get')
  def test_getinfo(self, mock_requestsget, mock_pydigquery, mock_getcertinfo, mock_gettlsinfo):
    mock_requestsget_response = MagicMock()
    mock_requestsget_response.status_code = 200
    mock_requestsget_response.get.return_value = mock_requestsget_response
    mock_requestsget.return_value = mock_requestsget_response

    verwachting = {'host': 'www.vanderiethattem.nl',
                   'ipresponses': {'ipv4data': {'addresses': [{'httpreponse': 200,
                                                               'ip': '1.2.3.4'}],
                                                'cert': {'CN': 'vanderiethattem.nl',
                                                         'issuer': 'CA',
                                                         'validuntil': '2024-12-29 10:11:12'},
                                                'tls': {'TLSv1_2': False, 'TLSv1_3': True}},
                                   'ipv6data': {'addresses': [{'httpreponse': 200,
                                                               'ip': '1:2::3:0'}],
                                                'cert': {'CN': 'vanderiethattem.nl',
                                                         'issuer': 'CA',
                                                         'validuntil': '2024-12-29 10:11:12'},
                                                'tls': {'TLSv1_2': True, 'TLSv1_3': False}}}}
    resultaat = sslcheck.getinfo("www.vanderiethattem.nl")
    assert mock_requestsget.called
    assert mock_pydigquery.called
    assert mock_getcertinfo.called
    assert mock_gettlsinfo.called
    self.assertEqual(resultaat, verwachting)
