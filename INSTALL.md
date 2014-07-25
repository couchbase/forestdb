## Dependencies

On non-Windows platforms, there is a dependency on Snappy library because ForestDB supports an option to compress a document body using Snappy.
Please visit [Snappy site](https://code.google.com/p/snappy/) for more details.

* **Ubuntu**

    `sudo apt-get install libsnappy-dev`.

* **CentOS**

    `wget https://snappy.googlecode.com/files/snappy-1.1.1.tar.gz`

    `tar -xvfz snappy-1.1.1.tar.gz`

    `cd snappy-1.1.1`

    `./configure && make && sudo make install`

* **OS X**

    `sudo brew install snappy`

## Compilation and Build

We use [CMake](http://www.cmake.org/cmake/) to provide the build support for a wide range of platforms. Please follow the instructions below to install CMake in your target platform.

* **Ubuntu**

    `sudo apt-get install cmake`

* **Centos**

    `wget http://www.cmake.org/files/v2.8/cmake-2.8.12.1.tar.gz`

    `tar xvfz cmake-2.8.12.1.tar.gz`

    `cd cmake-2.8.12.1`

    `./bootstrap && make && sudo make install`

* **OS X**

    `brew install cmake`

* **Windows**

    Please download and install CMake binary for Windows from [CMake download page](http://www.cmake.org/cmake/resources/software.html).

Once CMake is installed, please follow the instructions below to compile and build ForestDB on Ubuntu, Centos, or OS X:

`git clone forestdb_repo_url`

`cd forestdb`

`mkdir build`

`cd build`

`cmake ../`

(The default value of `CMAKE_BUILD_TYPE` is `RelWithDebInfo`. If you want to build with optimizations disabled for debugging, type `cmake -DCMAKE_BUILD_TYPE=Debug ../` instead.)

`make all`

On Windows (using Visual Studio's CL compiler), the instructions are as follows:

`git clone forestdb_repo_url` (or clone repository using [TortoiseGit](http://code.google.com/p/tortoisegit/))

`cd forestdb`

`mkdir build`

`cd build`

Note that the path and environment variables for command-line builds need to be set before moving to the next step. Please refer to the [MSDN Page](http://msdn.microsoft.com/en-us/library/f2ccy3wt.aspx).

`cmake -G "NMake Makefiles" ..\`

(The default value of `CMAKE_BUILD_TYPE` is `Debug`. If you want to build with optimizations enabled for better performance, type `cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ../` instead.)

`nmake all`

## Test

To run all the unit tests:

* **Ubuntu**, **Centos**, and **OS X**

    `make test`

* **Windows**

    `nmake test`

