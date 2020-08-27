#!/bin/bash

SERVER=ubuntu@ec2-13-59-88-125.us-east-2.compute.amazonaws.com

make clean
rsync -avz -e "ssh -i ~/Dropbox/Casa.pem" --progress main.c endpoints.ini src ${SERVER}:~/cwf/
rsync -avz -e "ssh -i ~/Dropbox/Casa.pem" --progress example_site/todo_index.tmpl ${SERVER}:/var/www/cwf/
