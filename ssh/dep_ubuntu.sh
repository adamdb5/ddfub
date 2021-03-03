#!/bin/sh
sshpass -p orangepi ssh root@192.168.2.127 'rm -rf ~/src'
sshpass -p orangepi scp -r ../src root@192.168.2.127:src/
