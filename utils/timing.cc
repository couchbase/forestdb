/* timed api wrapper methods */

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
