git clone --branch v2.01 https://github.com/herumi/bls.git
mkdir out
pwd=$PWD
echo "----------pwd:${pwd} ------------"
cd bls
git submodule init && git submodule update
cmake -DCMAKE_INSTALL_PREFIX=${pwd}/out -B build
cmake --build build -j4 && cmake --install build