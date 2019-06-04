#include <ntddk.h>

#if DBG
#include "debug.h"

#define MAGIC	'TMEM'
#define INT_3	__asm int 3

struct prefix {
	ULONG		magic;
	struct		prefix *next;
	struct		prefix *prev;
	ULONG		size;
	const char	*file;
	ULONG		line;
	char		data[];
};

struct postfix {
	ULONG	size;
	ULONG	magic;
};

static KSPIN_LOCK guard;
static struct prefix *first, *last;
static ULONG count;

static struct postfix	*check(struct prefix *p);

void
mempool_init()
{
	first = last = NULL;
	KeInitializeSpinLock(&guard);
}

void
mempool_fini()
{
	KIRQL irql;
	ULONG total = 0;

	KeAcquireSpinLock(&guard, &irql);

	if (first != NULL) {
		struct prefix *p;
		for (p = first; p; p = p->next) {
			check(p);

			DBGOUT(("memtrack: memory leak detected! %s:%u (%u bytes)\n",
				p->file, p->line, p->size));

			total += p->size;
		}
	}

	KeReleaseSpinLock(&guard, irql);
	DBGOUT(("memtrack: Total memory leakage: %u bytes (%u blocks)\n", total, count));

	if (total) INT_3;
}

void *
mt_malloc(ULONG size, const char *file, ULONG line)
{
	KIRQL irql;
	struct prefix *data;
	struct postfix *pd;

#if 1
	// check pool integrity
	KeAcquireSpinLock(&guard, &irql);
	
	for (data = first; data; data = data->next)
		check(data);
	
	for (data = last; data; data = data->prev)
		check(data);
	
	KeReleaseSpinLock(&guard, irql);
#endif

	if (size == 0) {
		DBGOUT(("memtrack: mt_malloc: size == 0!\n"));
		INT_3;
		return NULL;
	}

	data = (struct prefix *)ExAllocatePool(NonPagedPool,
		sizeof(struct prefix) + size + sizeof(struct postfix));
	if (data == NULL)
		return NULL;

	data->magic = MAGIC;
	data->next = NULL;
	data->prev = NULL;
	data->size = size;
	data->file = file;
	data->line = line;

	memset(data->data, 0xcc, size);		// fill by 0xcc: new

	pd = (struct postfix *)(data->data + data->size);

	pd->size = size;
	pd->magic = MAGIC;

	KeAcquireSpinLock(&guard, &irql);
	
	if (last) {
		last->next = data;
		data->prev = last;
		last = data;
	}
	else {
		data->prev = NULL;
		first = last = data;
	}
	count++;

	KeReleaseSpinLock(&guard, irql);
	return data->data;
}

void
mt_free(void *ptr)
{
	KIRQL irql;
	struct prefix *data = (struct prefix *)((char *)ptr - sizeof(struct prefix));
	struct postfix *pd = check(data);

	if (pd == NULL)
		return;

	KeAcquireSpinLock(&guard, &irql);

	if (data->next != NULL)
		data->next->prev = data->prev;
	else
		last = data->prev;
	if (data->prev != NULL)
		data->prev->next = data->next;
	else
		first = data->next;

	memset(data->data, 0xc9, data->size);	// fill by 0xc9: free

	data->size = (ULONG)-1;
	pd->size = (ULONG)-1;

	count--;
	KeReleaseSpinLock(&guard, irql);

	ExFreePool(data);
}

struct postfix *
check(struct prefix *p)
{
	struct postfix *pd;

	if (p->magic != MAGIC) {
		DBGOUT(("memtrack: check: invalid pre-magic! 0x%x\n", p));
		INT_3;
		return NULL;
	}

	pd = (struct postfix *)(p->data + p->size);

	if (pd->magic != MAGIC) {
		DBGOUT(("memtrack: memtrack_free: invalid post-magic! 0x%x\n", pd));
		INT_3;
		return NULL;
	}

	if (p->size != pd->size) {
		DBGOUT(("memtrack: memtracl_free: invalid post-size! 0x%x 0x%x\n", p, pd));
		INT_3;
		return NULL;
	}

	return pd;
}

#else

#include "malloc.h"
#include <ntddk.h>

void *	mp_mspace__ = NULL;
KSPIN_LOCK	mp_spinlock__;

void
mempool_init()
{
	if (!mp_mspace__)
	{
		mp_mspace__ = create_mspace(0, 0);
		KeInitializeSpinLock(&mp_spinlock__);
	}
}

void * 
mempool_malloc(size_t size)
{
	void *	ptr = NULL;
	if (mp_mspace__)
	{
		KIRQL	irql;
		KeAcquireSpinLock(&mp_spinlock__, &irql);
		ptr = mspace_malloc(mp_mspace__, size);
		KeReleaseSpinLock(&mp_spinlock__, irql);
	}
	return ptr;
}

void mempool_free(void * ptr)
{
	if (mp_mspace__ && ptr)
	{
		KIRQL	irql;
		KeAcquireSpinLock(&mp_spinlock__, &irql);
		mspace_free(mp_mspace__, ptr);
		KeReleaseSpinLock(&mp_spinlock__, irql);
	}
}
void mempool_fini()
{
	if (mp_mspace__)
		destroy_mspace(mp_mspace__);
}

#endif /* DBG */