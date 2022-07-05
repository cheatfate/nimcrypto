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
  if [ "${NIM_BRANCH}" = "devel" ]; then
    git checkout devel
  else
    git checkout "${NIM_BRANCH}"
  fi
  git clone --depth 1 https://github.com/nim-lang/csources_v1
  cd csources_v1 && sh build.sh
  cd ..
  bin/nim c -d:release koch
  ./koch boot -d:release
  ./koch nimble -d:release
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
