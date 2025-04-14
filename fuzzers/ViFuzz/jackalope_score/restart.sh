#/bin/sh
rm -rf ./corpus_discovered
rm -rf ./crashes
mkdir ./crashes
mkdir ./corpus_discovered
#cp ./test/* ./corpus_discovered/
find ./test/ -type f -exec cp {} ./corpus_discovered/ \; 
