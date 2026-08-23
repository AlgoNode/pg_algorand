sudo make clean
sudo make uninstall
sudo make -j"$(nproc --ignore=1)"
sudo make install
