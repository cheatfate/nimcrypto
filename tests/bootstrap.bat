@echo off
IF NOT EXIST "%CD%\%NIM_DIR%\bin\nim.exe" (
  echo Building Nim [%NIM_BRANCH%] in %NIM_DIR%
  git clone https://github.com/nim-lang/Nim.git "%CD%\%NIM_DIR%"
  cd "%CD%\%NIM_DIR%"
  IF NOT "%NIM_BRANCH%" == "devel" (
    git checkout "tags/%NIM_BRANCH%" -b "%NIM_BRANCH%"
  ) ELSE (
    git checkout devel
  )
  git clone --depth 1 https://github.com/nim-lang/csources
  cd csources
  IF "%PLATFORM%" == "x64" ( build64.bat ) else ( build.bat )
  cd ..
  bin\nim c -d:release koch
  koch boot -d:release
  koch nimble
  cd ..
) ELSE (
  cd "%CD%\%NIM_DIR%"
  set GITBRANCH=
  for /f %%I in ('git.exe rev-parse --abbrev-ref HEAD 2^> NUL') do set GITBRANCH=%%I
  echo Using Nim [%GITBRANCH%] in %NIM_DIR%
  cd ..
)
