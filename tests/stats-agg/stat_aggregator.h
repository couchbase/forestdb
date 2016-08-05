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

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <string>
#include <vector>

typedef struct {
    std::string name;
    std::vector<uint64_t> latencies;
} stat_history_t;

struct Stats {
    // Stat name
    std::string name;
    // Calculated mean
    double mean;
    // Calculated median
    double median;
    // Estimated standard deviation
    double stddev;
    // Calculated 5th percentile
    double pct5;
    // Calculated 95th percentile
    double pct95;
    // Calculated 99th percentile
    double pct99;
    // Vector of samples
    std::vector<uint64_t>* values;
};

typedef stat_history_t** StatMatrix_t;
typedef std::vector<std::pair<std::string, std::vector<uint64_t>*> > samples_t;

class StatAggregator {
public:
    StatAggregator(int _num_stats, int _num_samples);

    ~StatAggregator();

    void aggregateAndPrintStats(const char* title, int count, const char* unit);

    StatMatrix_t t_stats;

private:

    void printValues(samples_t values, std::string unit);

    void fillLineWith(const char c, int spaces);

    int num_stats;
    int num_samples;
};
