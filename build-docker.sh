#/bin/bash

# This file builds the go binary via docker
# See Dockerfile for steps

machine="$(uname -s)"

if [ "$machine" == "Darwin" ]; then
	# Mac OS X platform        
	echo "** MacOS Warning: This docker build will create a Linux binary"
fi

# Linux OS
echo "Building goscan Linux binary..."
if docker build -t goscan . ; then
	docker create -ti --name goscanfile goscan /bin/bash
	docker cp goscanfile:/app/scan .
	docker rm -f goscanfile
	echo "Build complete..."
	ls -lh scan
else
	echo "Build failed..."
fi

