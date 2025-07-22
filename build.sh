pwd=$PWD
echo "-------------- pwd:${pwd}"
if [ -d "out" ]; then
    echo "-------------- out 目录存在"
else
    echo "-------------- out 目录不存在，创建 out"
    mkdir out
fi
compile_bls_lib(){
  git clone --branch v2.01 https://github.com/herumi/bls.git
  cd bls
  git submodule init && git submodule update
  if [ -d "build" ]; then
      echo "-------------- build 目录存在,删除"
      rm -rf build
  fi
  cmake -DCMAKE_INSTALL_PREFIX=${pwd}/out -B build
  cmake --build build -j4 && cmake --install build
}

compile_frost_lib(){
  LD_LIBRARY_PATH=${pwd}/out/lib CGO_CFLAGS="-I${pwd}/out/include"\
   CGO_LDFLAGS="-lbls384_256 -lmcl -L${pwd}/out/lib -lstdc++" go run cmd/main.go
#  LD_LIBRARY_PATH=${pwd}/out/lib time ./main
}
param=$1
run(){
  if [[ "${param}" == "dep" ]]; then
    echo "-------------- compile depend"
    compile_bls_lib
  else
    echo "-------------- test golang project"
    compile_frost_lib
  fi
}
run