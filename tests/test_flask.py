from unittest.mock import patch

import pytest
from flask import Flask

import sslcheck


@pytest.fixture()
def app():
  app = Flask(__name__, template_folder='../templates')
  app.config.update({
    "TESTING": True,
  })

  @app.route('/sslcheck', methods=['GET'])
  def sslcheckget():
    return sslcheck.sslcheckget()

  @app.route('/sslcheck', methods=['POST'])
  def sslcheckpost():
    return sslcheck.sslcheckpost()

  @app.route('/sslcheck/dig/<host>', methods=['GET'])
  def sslcheckdigget(host: str):
    return sslcheck.sslcheckdigget(host)

  @app.route('/sslcheck/digall/<host>', methods=['GET'])
  def sslcheckdigallget(host: str):
    return sslcheck.sslcheckdigallget(host)

  yield app


@pytest.fixture()
def client(app):
  return app.test_client()


def test_sslcheck_get(client):
  response = client.get('/sslcheck')
  assert b"OK" in response.data


def test_sslcheck_post_empty(client):
  response = client.post('/sslcheck')
  assert b"Invalid apikey" in response.data


def test_sslcheck_post_wrongkey(client):
  response = client.post('/sslcheck',
                         headers={'Apikey': 'somekey'})
  assert b"Invalid apikey" in response.data


def test_sslcheck_post_onlykey(client):
  response = client.post('/sslcheck',
                         headers={'Apikey': 'MySecret'})
  assert b"No host given" in response.data


@patch('sslcheck.getinfo', side_effect=None)
def test_sslcheck_post(mock_info, client):
  client.post('/sslcheck',
              headers={'Apikey': 'MySecret'
                , 'Hostname': 'example.com'})
  assert mock_info.called


@patch('pydig.query', side_effect=[['12.34.56.78'],
                                   [], [], [], [], [], [], [], [], [], [], ])
def test_sslcheckdig_get(mock_query, client):
  response = client.get(f'/sslcheck/dig/test.nl')
  assert b"Host: test.nl" in response.data
  assert b"<td class=\"w3-align-top\">A</td>" in response.data
  assert b"12.34.56.78<br/>" in response.data
  assert mock_query.call_count == 11


@patch('pydig.Resolver.query', side_effect=[
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
  ['12.34.56.78'], [], [], [], [], [], [], [], [], [], [],
])
def test_sslcheckdigall_get(mock_query, client):
  response = client.get(f'/sslcheck/digall/test.nl')
  assert b"Host: test.nl" in response.data
  assert b"<td class=\"w3-align-top\">A</td>" in response.data
  assert b"12.34.56.78<br/>" in response.data
  assert mock_query.call_count == 11 * 12
