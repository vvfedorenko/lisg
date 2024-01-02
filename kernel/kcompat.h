#ifndef _KCOMPAT_H
#define _KCOMPAT_H

#ifndef __LINUX_BITMAP_H
#define bitmap_zalloc(nbits, flags) vmalloc(BITS_TO_LONGS(nbits) * sizeof(unsigned long))
#define bitmap_free(b) vfree(b)
#endif

#ifndef kfree_rcu_mightsleep
#define kfree_rcu_mightsleep kfree_rcu
#endif

#endif
