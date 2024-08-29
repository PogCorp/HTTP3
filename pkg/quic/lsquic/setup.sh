echo "Cloning dependencies repositories"
#git submodule update --init --recursive
ROOTDIR=${PWD}
LSQUIC=$ROOTDIR
LSQUIC+="/lsquic/"
BORINGSSL=$ROOTDIR
BORINGSSL+="/boringssl/"
echo "Entering boringssl directory: $BORINGSSL:"
cd $BORINGSSL
echo "Building borringssl:"

# NOTE: version above gcc-9 breaks borringssl
cmake -DCMAKE_CXX_COMPILER=g++-9 -DCMAKE_C_COMPILER=gcc-9 -DCMAKE_CXX_FLAGS="-Wno-ignored-attributes" . && make
echo "Entering lsquic directory: $LSQUIC:"
cd $LSQUIC
echo "Building lsquic:"
cmake -DCMAKE_CXX_COMPILER=g++-9 -DCMAKE_C_COMPILER=gcc-9 -DCMAKE_CXX_FLAGS="-Wno-ignored-attributes" -DBORINGSSL_DIR=${BORINGSSL} . && make
cd $ROOTDIR
