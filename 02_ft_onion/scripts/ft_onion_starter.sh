#!/bin/bash

service tor start
service nginx restart
service ssh start -D