#pragma once

/* Header files */
#cmakedefine HAVE_ATOMIC_H ${HAVE_ATOMIC_H}

#ifdef __GNUC__
#define HAVE_GCC_ATOMICS 1
#endif