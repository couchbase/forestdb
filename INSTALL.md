## Dependencies

On non-Windows platforms, there is a dependency on Snappy library because ForestDB supports an option to compress a document body using Snappy.
Please visit [Snappy site](https://code.google.com/p/snappy/) for more details.

* **Ubuntu**

    `sudo apt-get install libsnappy-dev`

* **CentOS**

    `wget https://snappy.googlecode.com/files/snappy-1.1.1.tar.gz`

    `tar -xvfz snappy-1.1.1.tar.gz`

    `cd snappy-1.1.1`

    `./configure && make && sudo make install`

* **OS X**

    `sudo brew install snappy`

We also use the asynchronous I/O library `libaio` on Linux if it is available, to submit multiple I/O requests at once to speed up fetching non-resident blocks from disk. As of this time, we use `libaio` to read data blocks from the old file during the compaction.

* **Ubuntu**

    `sudo apt-get install libaio-devel`

* **CentOS**

    `sudo yum install libaio-devel`

We plan to support asynchronous I/O in other operating systems such as Windows and OS X, soon.

For better memory fragmentation and concurrency management, jemalloc can be linked to ForestDB if available on the host environment. Please visit [jemalloc site](http://www.canonware.com/jemalloc/) for more information and install guideline.

Database encryption is also supported and can be enabled at compilation time. Currently, we support CommonCrypto library on iOS and OS X, [OpenSSL](https://www.openssl.org/), and [LibTomCrypt](https://github.com/libtom/libtomcrypt).

## Compilation and Build

We use [CMake](http://www.cmake.org/cmake/) to provide the build support for a wide range of platforms. Cmake version 3.1 is required at least to have C++11 support. Please follow the instructions below to install CMake in your target platform.

* **Ubuntu**

    `sudo apt-get install cmake`

* **Centos**

    `wget http://www.cmake.org/files/v2.8/cmake-3.4.3.tar.gz`

    `tar xvfz cmake-3.4.3.tar.gz`

    `cd cmake-3.4.3`

    `./bootstrap && make && sudo make install`

* **OS X**

    `brew install cmake`

* **Windows**

    Please download and install CMake binary for Windows from [CMake download page](http://www.cmake.org/cmake/resources/software.html).

Once CMake is installed, please follow the instructions below to compile and build ForestDB on Ubuntu, Centos, or OS X:

`git clone git://github.com/couchbase/forestdb`

`cd forestdb`

`mkdir build`

`cd build`

`cmake ../`

(The default value of `CMAKE_BUILD_TYPE` is `RelWithDebInfo`. If you want to build with optimizations disabled for debugging, type `cmake -DCMAKE_BUILD_TYPE=Debug ../` instead.)

`_JEMALLOC` variable can be optionally set to 1 and passed to link jemalloc to ForestDB (`cmake -D_JEMALLOC=1 ../`)

`_ENCRYPTION` macro can be also optionally passed to specify which crypto library (`commoncrypto`, `openssl`, or `libtomcrypt`) is used to support database encryption (e.g., `cmake -D_ENCRYPTION=commoncrypto ../`)

`make all`

On Windows (using Visual Studio's CL compiler), the instructions are as follows:

`git clone git://github.com/couchbase/forestdb` (or clone repository using [TortoiseGit](http://code.google.com/p/tortoisegit/))

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

* To enable code-coverage reporting for tests, install ```gcov``` and ```lcov``` for your OS. (Windows not supported).  Also make sure build type is **Coverage**

     `cmake -DCMAKE_BUILD_TYPE=Coverage ../`

     `make all`

     `make test_coverage`

    This target will run the tests and output coverage report to ```<repo>/coverage/index.html```

* To enable valgrind tests, install ```valgrind``` for your OS. (Windows not supported).  Also make sure build type is **Valgrind**

     `cmake -DCMAKE_BUILD_TYPE=Valgrind ../`

     `make all`

     `make test_valgrind`

    This target will run the tests and output the memory report to the console

* By default, every run will produce an additional .lat file which indicates the latencies
  of the forestdb api. This is disabled if CMAKE_BUILD_TYPE=Release

* To enable the use of threadsanitizer for tests, install clang 3.5+ (currently only Ubuntu 14.04 is supported).  Also make sure to set flag **CB_THREADSANITIZER**

     `cmake  -DCMAKE_C_COMPILER=clang-3.5 -DCMAKE_CXX_COMPILER=clang++-3.5  -DCB_THREADSANITIZER=1 ..`

     `make all`

     `make test`

     Alternatively you can manually run tests under build/tests/<component>/ for real-time analysis.  When running as standalone it is recommended to include false error suppressions:

     `TSAN_OPTIONS="second_deadlock_stack=1 suppressions=../../../cmake/Modules/tsan.suppressions" ./fdb_functional_test`

* For hardware accelerated CRC32C which can improve ForestDB performance, please fetch the optional couchbase platform repository into the forestdb source directory before building.

     `cd forestdb`

     `git clone https://github.com/couchbase/platform.git`

     `Follow the rest of the platform specific build instructions from above`
