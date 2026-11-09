#/bin/sh

echo "**********************************************************************"
echo "* Configure the application                                          *"
echo "**********************************************************************"
echo

cmake -B build_linux .

echo
echo
echo

echo "**********************************************************************"
echo "* Build the application                                              *"
echo "**********************************************************************"
echo

cmake --build build_linux --parallel `nproc`

echo
echo
echo

echo "**********************************************************************"
echo "* The application can be found at                                    *"
echo "* build_linux/src/network-capture                                    *"
echo "**********************************************************************"
