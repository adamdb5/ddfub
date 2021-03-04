#!/bin/sh
sshpass -p ***REMOVED*** ssh adamb@192.168.2.100 "rmdir /s /q src"
sshpass -p ***REMOVED*** scp -r ../src adamb@192.168.2.100:src/
