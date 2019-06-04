#ifndef mempool_h__
#define mempool_h__

#ifdef __cplusplus
extern "C" {
#endif

/** tag for memory blocks */
//lint -e742
#define MEM_TAG		'1VRD'


void	mempool_init(void);
void	mempool_fini(void);

#if DBG

/**
 * Allocate memory from nonpaged pool and store name of file and line of code with this block
 * @param	size	size of block
 * @param	file	name of file to associate with memory block
 * @param	line	line number to associate with memory block
 * @return			address of allocated block in nonpaged pool
 * @retval	NULL	error
 */
void	*mt_malloc(ULONG size, const char *file, ULONG line);
void	mt_free(void *ptr);

#define __malloc(size)	mt_malloc((size), __FILE__, __LINE__)	
#define __free(ptr)	mt_free(ptr)

#define _TEST_ME_	__asm int 3

#else /* DBG */

void * mempool_malloc(size_t size);
void mempool_free(void * ptr);

#define __malloc(size)	mempool_malloc(size)	
#define __free(ptr)	mempool_free(ptr)

//#endif /* _NDIS_ */

/** macro for debug break in checked build */
#define _TEST_ME_


#endif /* DBG */

#ifdef __cplusplus
} // extern "C"
#endif
#endif // mempool_h__