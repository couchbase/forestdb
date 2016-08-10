/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2016 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


#include <algorithm>
#include <cmath>
#include <iterator>
#include <numeric>
#include <string>

#include "stat_aggregator.h"

StatAggregator::StatAggregator(int _num_stats, int _num_samples) {

    num_stats = _num_stats;
    num_samples = _num_samples;
    t_stats = new stat_history_t*[num_stats];
    for (int i = 0; i < num_stats; ++i) {
        t_stats[i] = new stat_history_t[num_samples];
    }
}

StatAggregator::~StatAggregator() {

    for (int i = 0; i < num_stats; ++i) {
        delete[] t_stats[i];
    }
    delete[] t_stats;
}

void StatAggregator::aggregateAndPrintStats(const char* title, int count,
                                            const char* unit) {

    samples_t all_timings;
    for (int i = 0; i < num_stats; ++i) {
        for (int j = 1; j < num_samples; ++j) {
            t_stats[i][0].latencies.insert(t_stats[i][0].latencies.end(),
                                           t_stats[i][j].latencies.begin(),
                                           t_stats[i][j].latencies.end());
            t_stats[i][j].latencies.clear();
        }

        all_timings.push_back(std::make_pair(t_stats[i][0].name,
                                             &t_stats[i][0].latencies));
    }

    int printed = 0;
    printf("\n===== Avg Latencies (%s) - %d samples (%s) %n",
            title, count, unit, &printed);
    fillLineWith('=', 88-printed);

    printValues(all_timings, unit);

    fillLineWith('=', 87);
}


// Given a vector of values (each a vector<T>) calcuate metrics on them
// and print to stdout.
void StatAggregator::printValues(samples_t values, std::string unit) {

    // First, calculate mean, median, standard deviation and percentiles
    // of each set of values, both for printing and to derive what the
    // range of the graphs should be.
    std::vector<Stats> value_stats;
    for (const auto& t : values) {
        Stats stats;
        if (t.second->size() == 0) {
            continue;
        }
        stats.name = t.first;
        stats.values = t.second;
        std::vector<uint64_t>& vec = *t.second;

        // Calculate latency percentiles
        std::sort(vec.begin(), vec.end());
        stats.median = vec[(vec.size() * 50) / 100];
        stats.pct5 = vec[(vec.size() * 5) / 100];
        stats.pct95 = vec[(vec.size() * 95) / 100];
        stats.pct99 = vec[(vec.size() * 99) / 100];

        const double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
        stats.mean = sum / vec.size();
        double accum = 0.0;
        for (auto &d : vec) {
            accum += (d - stats.mean) * (d - stats.mean);
        }
        stats.stddev = sqrt(accum / (vec.size() - 1));

        value_stats.push_back(stats);
    }

    // From these find the start and end for the spark graphs which covers the
    // a "reasonable sample" of each value set. We define that as from the 5th
    // to the 95th percentile, so we ensure *all* sets have that range covered.
    uint64_t spark_start = std::numeric_limits<uint64_t>::max();
    uint64_t spark_end = 0;
    for (const auto& stats : value_stats) {
        spark_start = (stats.pct5 < spark_start) ? stats.pct5 : spark_start;
        spark_end = (stats.pct95 > spark_end) ? stats.pct95 : spark_end;
    }

    printf("\n                                Percentile\n");
    printf("  %-16s Median     95th     99th  Std Dev  "
            "Histogram of samples\n\n", "");
    // Finally, print out each set.
    for (const auto& stats : value_stats) {
        if (unit == "ns") {
            printf("%-16s %8.03f %8.03f %8.03f %8.03f  ",
                    stats.name.c_str(), stats.median, stats.pct95,
                    stats.pct99, stats.stddev);
        } else if (unit == "µs") {
            printf("%-16s %8.03f %8.03f %8.03f %8.03f  ",
                    stats.name.c_str(), stats.median/1e3, stats.pct95/1e3,
                    stats.pct99/1e3, stats.stddev/1e3);
        } else if (unit == "ms") {
            printf("%-16s %8.03f %8.03f %8.03f %8.03f  ",
                    stats.name.c_str(), stats.median/1e6, stats.pct95/1e6,
                    stats.pct99/1e6, stats.stddev/1e6);
        } else {    // unit == "s"
            printf("%-16s %8.03f %8.03f %8.03f %8.03f  ",
                    stats.name.c_str(), stats.median/1e9, stats.pct95/1e9,
                    stats.pct99/1e9, stats.stddev/1e9);
        }

        // Calculate and render Sparkline (requires UTF-8 terminal).
        const int nbins = 32;
        int prev_distance = 0;
        std::vector<size_t> histogram;
        for (unsigned int bin = 0; bin < nbins; bin++) {
            const uint64_t max_for_bin = (spark_end / nbins) * bin;
            auto it = std::lower_bound(stats.values->begin(),
                                       stats.values->end(),
                                       max_for_bin);
            const int distance = std::distance(stats.values->begin(), it);
            histogram.push_back(distance - prev_distance);
            prev_distance = distance;
        }

        const auto minmax = std::minmax_element(histogram.begin(),
                                                histogram.end());
        const size_t range = *minmax.second - *minmax.first + 1;
        const int levels = 8;
        for (const auto& h : histogram) {
            int bar_size = ((h - *minmax.first + 1) * (levels - 1)) / range;
            putchar('\xe2');
            putchar('\x96');
            putchar('\x81' + bar_size);
        }
        putchar('\n');
    }
    if (unit == "ns") {
        printf("%52s  %-14d %s %14d\n", "",
               int(spark_start), unit.c_str(), int(spark_end));
    } else if (unit == "µs") {
        printf("%52s  %-14d %s %14d\n", "",
               int(spark_start/1e3), unit.c_str(), int(spark_end/1e3));
    } else if (unit == "ms") {
        printf("%52s  %-14d %s %14d\n", "",
               int(spark_start/1e6), unit.c_str(), int(spark_end/1e6));
    } else {    // unit == "s"
        printf("%52s  %-14d %s %14d\n", "",
               int(spark_start/1e9), unit.c_str(), int(spark_end/1e9));
    }
}

void StatAggregator::fillLineWith(const char c, int spaces) {

    for (int i = 0; i < spaces; ++i) {
        putchar(c);
    }
    putchar('\n');
}
