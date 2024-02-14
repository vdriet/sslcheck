docker stop sslcheck
docker rm -f sslcheck
docker run --detach --name sslcheck --publish 8082:8082 --rm sslcheck
