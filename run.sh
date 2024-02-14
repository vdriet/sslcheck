docker stop sslcheck
docker rm -f sslcheck
docker run --detach --restart always --name sslcheck --publish 8082:8082 sslcheck
