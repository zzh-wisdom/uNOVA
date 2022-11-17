#ifndef UNOVA_UTIL_UTIL_H_
#define UNOVA_UTIL_UTIL_H_

#include <stddef.h>
#include <stdio.h>
#include <assert.h>

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

#define WRITE_ONCE(var, val) \
    (*((volatile typeof(val) *)(&(var))) = (val))

#ifndef HAVE_ARCH_BUG_ON
#define BUG() do {printf("%s %d bug\n", __func__, __LINE__); assert(0);} while (1)
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely(x)	__builtin_expect(!!(x), 1)

#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})

#define WARN_ON_ONCE(condition) WARN_ON(condition)
#endif

#endif
