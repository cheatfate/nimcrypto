#!/usr/bin/env bash

if [[ -z "${NIM_DIR}" ]]; then
  echo "NIM_DIR variable is not set"
  exit 1
fi

if [[ -z "${NIM_BRANCH}" ]]; then
  echo "NIM_BRANCH variable is not set"
  exit 1
fi

function build_nim {
  echo "Building Nim [${NIM_BRANCH}] in ${NIM_DIR}"
  git clone https://github.com/nim-lang/Nim.git ${NIM_DIR}
  cd "${NIM_DIR}"
  git checkout "${NIM_BRANCH}"
  if [ "${NIM_ARCH}" = "i386" ]; then
    NIM_CPU="i386"
  elif [ "${NIM_ARCH}" = "arm64" ]; then
    NIM_CPU="arm64"
  else
    NIM_CPU="amd64"
  fi
  ./build_all.sh ucpu=${NIM_CPU}
  cd ..
}

function use_nim {
  cd "${NIM_DIR}"
  GITBRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')
  echo "Found Nim [${GITBRANCH}] in ${NIM_DIR}"
  if [ "${GITBRANCH}" = "${NIM_BRANCH}" ]; then
    echo "Using Nim [${GITBRANCH}] in ${NIM_DIR}"
    cd ..
  else
    cd ..
    rm -rf "${NIM_DIR}"
    build_nim
  fi
}

if [ ! -e "${NIM_DIR}/bin/nim" ]; then
  build_nim
else
  use_nim
fi
