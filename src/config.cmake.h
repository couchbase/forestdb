#pragma once

/* Header files */
#cmakedefine HAVE_ATOMIC_H ${HAVE_ATOMIC_H}

/* various */
#define FORESTDB_VERSION "${FORESTDB_VERSION}"

#ifdef __GNUC__
#define HAVE_GCC_ATOMICS 1
#endif