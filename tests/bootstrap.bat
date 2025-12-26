@ECHO OFF

SETLOCAL enabledelayedexpansion

IF "%NIM_DIR%" == "" (
  ECHO NIM_DIR variable is not set
  EXIT /B 0
)

IF "%NIM_BRANCH%" == "" (
  ECHO NIM_BRANCH variable is not set
  EXIT /B 0
)

IF "%NIM_ARCH%" == "" (
  ECHO NIM_ARCH variable is not set
  EXIT /B 0
)

IF NOT EXIST "%CD%\%NIM_DIR%\bin\nim.exe" (
  CALL :BUILD_NIM
) ELSE (
  CALL :USE_NIM
)
EXIT /B 0

:BUILD_NIM
ECHO Building Nim [%NIM_BRANCH%] (%NIM_ARCH%) in %NIM_DIR%
git clone https://github.com/nim-lang/Nim.git "%CD%\%NIM_DIR%"
CD "%CD%\%NIM_DIR%"
git checkout "%NIM_BRANCH%"
SET ARCH=%NIM_ARCH%
SET PROCESSOR_ARCHITECTURE=%NIM_ARCH%
CALL build_all.bat
CD ..
EXIT /B 0

:USE_NIM
CD "%CD%\%NIM_DIR%"
FOR /F "tokens=3" %%I IN ('git status ^| head -1') DO SET GITBRANCH=%%I
ECHO Found Nim [%GITBRANCH%] in %NIM_DIR%
IF "%GITBRANCH%" == "%NIM_BRANCH%" (
  ECHO Using Nim [%GITBRANCH%] in %NIM_DIR%
  CD ..
) ELSE (
  CD ..
  RMDIR /S /Q "%NIM_DIR%"
  CALL :BUILD_NIM
)

EXIT /B 0
