sudo netstat -tulpn | grep 8082 | awk '{print $7}' | sed 's/\/python//g' | xargs sudo kill -9 | true
. ./env.sh
python sslcheck.py >> /home/peter/logs/sslcheck.log &
