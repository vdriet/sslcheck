#!/bin/bash
set -e
pip list --outdated
pylint *.py
