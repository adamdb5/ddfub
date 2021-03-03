#!/bin/sh
sshpass -p armbian ssh root@192.168.2.2 'rm -rf ~/src'
sshpass -p armbian scp -r ../src root@192.168.2.2:src/
