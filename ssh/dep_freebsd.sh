#!/bin/sh
sshpass -p freebsd ssh freebsd@192.168.2.83 'rm -rf ~/src'
sshpass -p freebsd scp -r ../src freebsd@192.168.2.83:src/
