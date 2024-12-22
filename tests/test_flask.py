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


@pytest.fixture()
def runner(app):
  return app.test_cli_runner()


def test_sslcheck_get(client):
  response = client.get("/sslcheck")
  assert b"OK" in response.data

def test_sslcheck_post(client):
  response = client.post("/sslcheck")
  assert b"Invalid apikey" in response.data
