#!/bin/bash
# pqc-setup.sh
# Shell script to install liboqs, oqs-provider, and OpenSSL with ML-KEM (Kyber), FrodoKEM, BIKE, and HQC support on AlmaLinux

set -e

# ----- CONFIGURATION -----
INSTALL_DIR=/opt
LIBOQS_DIR=$INSTALL_DIR/liboqs
OPENSSL_DIR=$INSTALL_DIR/openssl-oqs
NPROC=$(nproc)

# ----- UPDATE SYSTEM -----
sudo dnf install -y epel-release
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake git perl-core zlib-devel gcc openssl-devel make wget curl nano

# ----- INSTALL OpenSSL 3.x from source (required for oqs-provider) -----
git clone --branch openssl-3.2.1 https://github.com/openssl/openssl.git openssl-vanilla
cd openssl-vanilla
./Configure --prefix=$OPENSSL_DIR enable-fips
make -j$NPROC
sudo make install_sw
cd ..

# ----- INSTALL liboqs -----
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
mkdir -p liboqs/build && cd liboqs/build
cmake .. -DCMAKE_INSTALL_PREFIX=$LIBOQS_DIR -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
make -j$NPROC
sudo make install
cd ../..

# ----- INSTALL oqs-provider (OpenSSL 3.x based) -----
git clone --recursive https://github.com/open-quantum-safe/oqs-provider.git
mkdir -p oqs-provider/build && cd oqs-provider/build

cmake .. \
  -DCMAKE_INSTALL_PREFIX=$OPENSSL_DIR \
  -DOQS_PROVIDER_SANITIZE=OFF \
  -DOQS_DIR=$LIBOQS_DIR \
  -DOPENSSL_ROOT_DIR=$OPENSSL_DIR \
  -DOPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include \
  -DCMAKE_BUILD_TYPE=Release

make -j$NPROC
sudo make install
cd ../..

# ----- CONFIGURE LD LIBRARY PATH -----
echo "$LIBOQS_DIR/lib64" | sudo tee /etc/ld.so.conf.d/liboqs.conf
sudo ldconfig

# ----- CREATE OPENSSL CONFIG FILE -----
cat << EOF > ~/openssl-oqs.cnf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = $OPENSSL_DIR/lib64/ossl-modules/oqsprovider.so
EOF


