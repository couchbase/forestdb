/* timed api wrapper methods */

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif
#if defined(WIN32)
#include <Windows.h>
#else
#include <sys/time.h>
#endif
#if !defined(WIN32) && !defined(_WIN32)
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "libforestdb/forestdb.h"
#include "config.h"
#include "timing.h"

ts_nsec timed_fdb_commit(fdb_file_handle *fhandle, bool walflush){

  ts_nsec start, end;
  fdb_status status;

  start = get_monotonic_ts();
  if(walflush){
    status = fdb_commit(fhandle, FDB_COMMIT_MANUAL_WAL_FLUSH);
  } else {
    status = fdb_commit(fhandle, FDB_COMMIT_NORMAL);
  }

  end = get_monotonic_ts();

  if(status == FDB_RESULT_SUCCESS){
    return ts_diff(start, end);
  } else {
    return ERR_NS;
  }
}

ts_nsec timed_fdb_compact(fdb_file_handle *fhandle){

  ts_nsec start, end;
  fdb_status status;

  start = get_monotonic_ts();
  status = fdb_compact(fhandle, NULL);

  end = get_monotonic_ts();

  if(status == FDB_RESULT_SUCCESS){
    return ts_diff(start, end);
  } else {
    return ERR_NS;
  }
}

ts_nsec timed_fdb_set(fdb_kvs_handle *kv, fdb_doc *doc){

  ts_nsec start, end;
  fdb_status status;

  start = get_monotonic_ts();
  status = fdb_set(kv, doc);
  end = get_monotonic_ts();

  if(status == FDB_RESULT_SUCCESS){
    return ts_diff(start, end);
  } else {
    return ERR_NS;
  }
}

ts_nsec timed_fdb_get(fdb_kvs_handle *kv, fdb_doc *doc){

  ts_nsec start, end;
  fdb_status status;

  start = get_monotonic_ts();
  status = fdb_get(kv, doc);
  end = get_monotonic_ts();

  if(status == FDB_RESULT_SUCCESS){
    return ts_diff(start, end);
  } else {
    return ERR_NS;
  }
}

ts_nsec timed_fdb_delete(fdb_kvs_handle *kv, fdb_doc *doc){

  ts_nsec start, end;
  fdb_status status;

  start = get_monotonic_ts();
  status = fdb_del(kv, doc);
  end = get_monotonic_ts();

  if(status == FDB_RESULT_SUCCESS){
    return ts_diff(start, end);
  } else {
    return ERR_NS;
  }
}

ts_nsec timed_fdb_snapshot(fdb_kvs_handle *kv, fdb_kvs_handle **snap_kv){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_snapshot_open(kv, snap_kv, FDB_SNAPSHOT_INMEM);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_kvs_close(fdb_kvs_handle *kv){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_kvs_close(kv);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_close(fdb_file_handle *fhandle){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_close(fhandle);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_shutdown(){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_shutdown();
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_iterator_init(fdb_kvs_handle *kv, fdb_iterator **it){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_iterator_init(kv, it, NULL, 0, NULL, 0, FDB_ITR_NONE);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }


}

ts_nsec timed_fdb_iterator_get(fdb_iterator *it, fdb_doc **doc){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_iterator_get(it, doc);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_iterator_next(fdb_iterator *it){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_iterator_next(it);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

ts_nsec timed_fdb_iterator_close(fdb_iterator *it){

    ts_nsec start, end;
    fdb_status status;

    start = get_monotonic_ts();
    status = fdb_iterator_close(it);
    end = get_monotonic_ts();

    if(status == FDB_RESULT_SUCCESS){
      return ts_diff(start, end);
    } else {
      return ERR_NS;
    }

}

/*
    return a monotonically increasing value with a seconds frequency.
*/
ts_nsec get_monotonic_ts() {
    ts_nsec ts = 0;
#if defined(WIN32)
    /* GetTickCound64 gives us near 60years of ticks...*/
    ts =  GetTickCount64() * 1000;  // TODO: this is not true high-res microseconds on windows
#elif defined(__APPLE__)
    long time = mach_absolute_time();

    static mach_timebase_info_data_t timebase;
    if (timebase.denom == 0) {
      mach_timebase_info(&timebase);
    }

    ts = (double)time * timebase.numer / timebase.denom;
#elif defined(__linux__) || defined(__sun) || defined(__FreeBSD__)
    /* Linux and Solaris can use clock_gettime */
    struct timespec tm;
    if (clock_gettime(CLOCK_MONOTONIC, &tm) == -1) {
        abort();
    }
    ts = tm.tv_nsec;
#else
#error "Don't know how to build get_monotonic_ts"
#endif

    return ts;
}

ts_nsec ts_diff(ts_nsec start, ts_nsec end)
{
    ts_nsec diff = 0;
    if ((end-start)<0) {
        diff  = 1000000000+end-start;
    } else {
        diff = end-start;
    }
    return diff/1000;
}
