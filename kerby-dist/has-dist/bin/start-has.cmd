@echo off

@rem Licensed to the Apache Software Foundation (ASF) under one
@rem or more contributor license agreements.  See the NOTICE file
@rem distributed with this work for additional information
@rem regarding copyright ownership.  The ASF licenses this file
@rem to you under the Apache License, Version 2.0 (the
@rem "License"); you may not use this file except in compliance
@rem with the License.  You may obtain a copy of the License at
@rem
@rem     http://www.apache.org/licenses/LICENSE-2.0
@rem
@rem Unless required by applicable law or agreed to in writing, software
@rem distributed under the License is distributed on an "AS IS" BASIS,
@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@rem See the License for the specific language governing permissions and
@rem limitations under the License.
setlocal
set CONF_DIR=%1%
set WORK_DIR=%2%

@rem Pid file to save pid numbers
set pid=C:\WINDOWS\Temp\has.pid 
set APP_MAIN=org.apache.kerby.has.server.HasServer

@rem Reset HAS_CONF_DIR and HAS_WORK_DIR if CONF_DIR or WORK_DIR not null
if not "%CONF_DIR%" == "" (
  @rem if this is an exist folder
  if not exist "%CONF_DIR%" (
    echo. [ERROR] %CONF_DIR% is not a directory
    call:usage
    GOTO END
  )
) else (
  if not "%HAS_CONF_DIR%" == "" (
    if exist "%HAS_CONF_DIR%" (
      set CONF_DIR=%HAS_CONF_DIR%
    )
  ) else (
    echo. [ERROR] HAS_CONF_DIR is null or not a directory
    GOTO END
  )
)

if not "%WORK_DIR%" == "" (
  if not exist "%WORK_DIR%" (
    echo. "[ERROR] %WORK_DIR% is not a directory"
    call:usage
    GOTO END
  )
) else (
  if not "%HAS_WORK_DIR%" == "" (
    if exist "%HAS_WORK_DIR%" (
      WORK_DIR=%HAS_WORK_DIR%
    )
  ) else (
    echo. [ERROR] HAS_WORK_DIR is null or not a directory
    GOTO END
  )
)

@rem Get HAS_HOME directory
set bin="%~dp0"
set HAS_HOME="%~dp0\.."
@rem cd %HAS_HOME%

for %%a in (%*) do (
  if -D == %%a (
    set DEBUG=-Xdebug -Xrunjdwp:transport=dt_socket,address=8010,server=y,suspend=n
  )
)

set args=%CONF_DIR% %WORK_DIR%

echo [INFO] conf_dir=%CONF_DIR%
echo [INFO] work_dir=%WORK_DIR%

echo Starting HAS server...

@rem Start HAS server
start /b java %DEBUG%  ^
-classpath %HAS_HOME%\target\lib\*;%HAS_HOME%\.  -DHAS_LOGFILE=has ^
org.apache.kerby.has.server.HasServer -start %args% 
jps | findstr "HasServer" > %pid%
endlocal
jps
echo Starting HAS server finish 
GOTO:DONE

:usage
echo "Usage: start-has.cmd <conf_dir> <working_dir>"
echo "    Example:"
echo "        start-has.cmd conf work"
GOTO:EOF

:END
echo &pause&goto:eof
GOTO:EOF

:DONE

