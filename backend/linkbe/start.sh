#!/bin/bash
ip vrf exec vrf1 /usr/local/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 --enable-stdio-inheritance linkbe.wsgi:application
