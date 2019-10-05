#!/bin/bash


# http-single-domain test
#./run http01 --dir https://pebble:14000/dir --record 172.17.0.12 --domain example.com 
./run http01 --dir https://127.0.0.1:14000/dir --record 172.17.0.12 --domain example.com 
