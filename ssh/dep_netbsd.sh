#!/bin/sh
sshpass -p netbsd ssh netbsd@192.168.2.128 'rm -rf ~/src'
sshpass -p netbsd scp -r ../src netbsd@192.168.2.128:src/
