DEFAULT_HEAD="bench_head"
THRESHOLD_STATS="threshold.stats"
NEW_BENCH_STATS="cmp_bench_new.stats"
OLD_BENCH_STATS="cmp_bench_old.stats"
BENCH_REPORT='cmp_bench_report.txt'
BUILD_DIR="../build"

if [ -n "$WORKSPACE" ]; then # jenkins override
  BUILD_DIR="$WORKSPACE/build"
fi
if [ -n "$_BUILD_DIR" ]; then # explicit override
  BUILD_DIR="$_BUILD_DIR"
fi
FDB_BENCH="$BUILD_DIR/tests/bench/fdb_bench"

# builds and runs bench mark
function run_bench {

  # build
  pushd $BUILD_DIR
  make -j4
  popd

  STAT_FILE=$1
  rm $STAT_FILE
  $FDB_BENCH  | tee $STAT_FILE.0

  # append thresholds to output file
  # (see threshold.stats)
  while read line; do
    stat="$( echo $line | awk '{print $1}')"

    if [ -n "$stat" ]; then
      threshold="$(grep "^$stat" $THRESHOLD_STATS | awk '{print $2}')"

      # append threshold to file
      line="$line $threshold"
    fi

    echo $line >> $STAT_FILE
  done < $STAT_FILE.0
}

# set new revision name
NEW_REV=`git rev-parse --abbrev-ref HEAD`
if [ "$NEW_REV" == "HEAD" ]; then
  # give branch a name
  git checkout -b $DEFAULT_HEAD
  if [ $? != 0 ]; then
    echo "ERROR: [git checkout -b $DEFAULT_HEAD] - resolve any uncommitted changes before proceeding"
    exit 1
  fi
  NEW_REV=$DEFAULT_HEAD
fi


# set old revision name - or read from stdin
OLD_REV=`git log  --skip=1 -1 --format="%H"`

if [ -n "$1" ]; then
  OLD_REV=$1
else
  echo "Comparing to most recent commit: ".$OLD_REV
  sleep 1
fi


# run benchmark at current rev
run_bench $NEW_BENCH_STATS

# checkout previous patch
git checkout $OLD_REV
if [ $? != 0 ]; then
  echo "ERROR: [git checkout $OLD_REV] - resolve any uncommitted changes before proceeding"
  exit 1
fi

# run benchmark at old rev
run_bench $OLD_BENCH_STATS


# run diff compares 2 files and prints diff in 3rd column
# the third indicates added latency and regression is based
# on values in threshold.stats.
#
#... example output ...
#
# BENCH-SEQUENTIAL_SET-WALFLUSH-1
# stat            old             new             diff (ms)       thresh     regress
# set             11.381200ns     10.151800ns     -1.2294         100
# commit_wal      22366.000000ns  21965.000000ns  -401            100000
awk 'NR==FNR {a[NR]=$2; next} $1~/BENCH/{printf "%s\n%-15s %-15s %-15s %-15s %-10s %-10s\n", $1, "stat", "old", "new", "diff (ms)", "thresh", "regress"; next} {if(a[FNR]-$2>$3){ b[NR]="yes" }} {printf "%-15s %-15s %-15s %-15s %-10s %-10s\n", $1, $2, a[FNR], a[FNR]-$2, $3, b[NR]}' $NEW_BENCH_STATS $OLD_BENCH_STATS  |   sed -E 's/^ .*yes//' | tee $BENCH_REPORT

REGRESSION_CNT=`cat $BENCH_REPORT | grep "yes \+$" | wc -l`
echo -e "\nDone: $REGRESSION_CNT possible regressions\n\n"


# return to new revision
git checkout $NEW_REV

# cleanup
rm $OLD_BENCH_STATS*
rm $NEW_BENCH_STATS*

# validator exit code
if [ $REGRESSION_CNT -gt 0 ]; then
  exit 1
fi
