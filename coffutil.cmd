@echo off
setlocal EnableDelayedExpansion

set COFFUTIL_HOME=%~dp0
set COFFUTIL_JAR_NAME=coffutil-fat-1.0-SNAPSHOT.jar
set COFFUTIL_FAT_JAR=%COFFUTIL_HOME%\build\libs\%COFFUTIL_JAR_NAME%

rem *** find JDK runtime
if not defined XXJAVA_HOME (
    set JAVA_HOME=\Users\stooke\dev\tools\openjdk-11.0.5_10
)
if not exist %JAVA_HOME%\bin\java.exe (
    @echo "no JAVA_HOME set; cannot start"
    exit /b 1
)

set COFFUTIL_REPO=C:/Users/stooke/dev/graal11/coffutil
set MAIN_CLASS=com.redhat.coffutil.Main

rem *** first, find most recent class files - if found, run them instead of fat jar
if exist "%COFFUTIL_REPO%/build/classes/java/main/%MAIN_CLASS:.=/%.class" (
    set CLASSPATH=%COFFUTIL_REPO%/build/classes/java/main
    %JAVA_HOME%\bin\java -classpath !CLASSPATH! %MAIN_CLASS% %1 %2 %3 %4 %5 %6 %7 %8 %9
    exit /b
)

rem *** find fat jar
if not exist %COFFUTIL_FAT_JAR% (
    set COFFUTIL_FAT_JAR=%COFFUTIL_HOME%\%COFFUTIL_JAR_NAME%
)
if not exist %COFFUTIL_FAT_JAR% (
    @echo "coffutil jar file %COFFUTIL_JAR_NAME% not found; cannot start"
    exit /b 1
)

rem ** run coffutil
%JAVA_HOME%\bin\java -jar %COFFUTIL_FAT_JAR% %1 %2 %3 %4 %5 %6 %7 %8 %9

exit /b
