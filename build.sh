#/bin/bash

# This file builds the go binary

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=MacOS;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${unameOut}"
esac

echo "Building goscan $machine binary..."
cd src/main
go mod download
if go build -a -o ../../scan . ; then
	echo "Build complete..."
	cd ../..
	ls -lh scan
else
	echo "Build failed..."
fi

