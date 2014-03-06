ForestDB
=======
ForestDB is a fast key-value storage engine that is based on hierarchical B+-tree trie data structure. We propose and implement trie (also known as prefix tree)-like structure, called HB+-trie (Hierarchical B+-tree based trie), which can support efficient indexing and retrieval on a large number of variable-length keys over tree-like structures, in terms of block device I/O. In addition, documents and internal nodes of trie are stored as block-aligned form so that we can minimize the number of block-I/O accesses while indexing the documents.

Contributors
======
Jung-Sang Ahn <jungsang.ahn@gmail.com>
Sundar Sridharan <sundar.sridharan@gmail.com>
Gihwan Oh <wurikiji@gmail.com>
Chiyoung Seo <chiyoung.seo@gmail.com>

build
=====
make

test
====
make test

benchmark
=========
make bench

how to use
==========
refer to tests/forestdb_test.c
