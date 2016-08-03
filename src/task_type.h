/*
 *     Copyright 2014 Couchbase, Inc.
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

#ifndef SRC_TASK_TYPE_H_
#define SRC_TASK_TYPE_H_ 1

enum task_type_t {
    NO_TASK_TYPE=-1,
    WRITER_TASK_IDX=0,
    READER_TASK_IDX=1,
    AUXIO_TASK_IDX=2,
    NONIO_TASK_IDX=3,
    NUM_TASK_GROUPS=4 // keep this as last element of the enum
};

#endif  // SRC_TASK_TYPE_H_
