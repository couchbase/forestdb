/*
Copyright 2013 Jung-Sang Ahn, Couchbase Inc., all rights reserved.
*/

#ifndef _JSAHN_TEST_H
#define _JSAHN_TEST_H

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include "common.h"

#define _TEST_GLOBAL
#ifdef _TEST_GLOBAL

#define TEST_INIT() \
	static int __test_pass=1; \
	struct timeval __test_begin, __test_prev, __test_cur, __test_interval_total, __test_interval_ins; \
	gettimeofday(&__test_begin, NULL); \
	__test_cur = __test_begin

#define TEST_CHK(cond) {if (!(cond)) {fprintf(stderr, "Test failed: %s %d\n", __FILE__, __LINE__); __test_pass=0;}}
#define TEST_RESULT(name) {if ((__test_pass)) fprintf(stderr, "%s PASSED\n", (name)); else fprintf(stderr, "%s FAILED\n", (name)); }

#define TEST_TIME() {\
	__test_prev = __test_cur; \
	gettimeofday(&__test_cur, NULL); \
	__test_interval_total = _utime_gap(__test_begin, __test_cur); \
	__test_interval_ins = _utime_gap(__test_prev, __test_cur); \
	DBG("Time elapsed: total %"_FSEC".%06"_FUSEC" , interval %"_FSEC".%06"_FUSEC"\n", \
		__test_interval_total.tv_sec, __test_interval_total.tv_usec, \
		__test_interval_ins.tv_sec, __test_interval_ins.tv_usec); }


#else

#define TEST_CHK(cond, sw) {if (!(cond)) {fprintf(stderr, "Test failed: %s %d\n", __FILE__, __LINE__); sw=0;}}
#define TEST_RESULT(name, sw) {if ((sw)) fprintf(stderr, "%s PASSED\n", (name)); else fprintf(stderr, "%s FAILED\n", (name)); }

#endif

#endif


