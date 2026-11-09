call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

echo:
echo:
echo:

echo **********************************************************************
echo * Configure the application                                          *
echo **********************************************************************
echo:


cmake -B build_win -DPCAP_ROOT=.\\extern\\npcap-sdk-1.13 .

echo:
echo:
echo:

echo **********************************************************************
echo * Build the application                                              *
echo **********************************************************************
echo:

cmake --build build_win --parallel %NUMBER_OF_PROCESSORS%

echo:
echo:
echo:

echo **********************************************************************
echo * The application can be found at                                    *
echo * build_win\src\Debug\network-capture.exe                            *
echo **********************************************************************
pause