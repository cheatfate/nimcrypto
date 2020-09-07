#!/usr/bin/env bash
if [ ! -e "$NIM_DIR/bin/nim" ]; then
  echo "Building Nim [$NIM_BRANCH] in $NIM_DIR"
  git clone https://github.com/nim-lang/Nim.git "$NIM_DIR"
  cd "$NIM_DIR"
  if [ "$NIM_BRANCH" = "devel" ]; then
    git checkout devel
  else
    git checkout "tags/$NIM_BRANCH" -b "$NIM_BRANCH"
  fi
  git clone --depth 1 https://github.com/nim-lang/csources
  cd csources && sh build.sh
  cd ..
  bin/nim c -d:release koch
  ./koch boot -d:release
  ./koch nimble -d:release
  cd ..
else
  GITBRANCH=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p')
  echo "Using Nim [$GITBRANCH] in $NIM_DIR"
fi
