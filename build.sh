sudo make clean
sudo make uninstall
CGO_ENABLED=1 go build -buildmode=c-archive functions.go
sudo make
sudo make install
