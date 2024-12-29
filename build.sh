#!/bin/bash
set -e
pip install -r requirements.txt
pip list --outdated
pylint *.py
coverage run -m pytest
coverage report -m