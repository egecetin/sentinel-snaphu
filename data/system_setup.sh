#!/bin/bash

sudo apt-get update && apt-get upgrade -y && apt-get install -y \
    python3-dev \
    python3-pip \
    snaphu \
    wget \
    zip

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
