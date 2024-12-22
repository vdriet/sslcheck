from unittest.mock import patch

import pytest
from flask import Flask

import sslcheck


@pytest.fixture()
def app():
  app = Flask(__name__)
  app.config.update({
    "TESTING": True,
  })

  @app.route('/sslcheck', methods=['GET'])
  def sslcheckget():
    return sslcheck.sslcheckget()

  @app.route('/sslcheck', methods=['POST'])
  def sslcheckpost():
    return sslcheck.sslcheckpost()

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
