#include <types.h>
#include <kern/errno.h>
#include <kern/fcntl.h>
#include <limits.h>
#include <kern/stat.h>
#include <kern/seek.h>
#include <kern/unistd.h>
#include <lib.h>
#include <uio.h>
#include <proc.h>
#include <current.h>
#include <synch.h>
#include <vfs.h>
#include <vnode.h>
#include <file.h>
#include <syscall.h>
#include <copyinout.h>

/*
 * Add your file-related functions here ...
 */
int sys_open(const char *filename, int flags, mode_t mode){
    size_t got;
    int fd, ret;
    struct vnode *vn_ptr;

    /* 
     * Find out the new fd that is available. 
     * Fd starts from 3 as 0, 1, 2 have been used as stdin stdout stderr. 
     * Use spinlock to access file descriptor table safely.
     */
    spinlock_acquire(&curproc->p_lock);
    fd = 3;
    while(curproc->fd_table[fd] != NULL && fd < OPEN_MAX)
        fd++;
    spinlock_release(&curproc->p_lock);
    if(fd == OPEN_MAX)
		return ENFILE;

    //copy the string from user space to kernel space.
    char *kfilename = (char*)kmalloc(sizeof(char)*PATH_MAX);
    if(kfilename == NULL)
		return ENOMEM;

	copyinstr((const_userptr_t)filename, kfilename, PATH_MAX, &got);

    //call vfs_open to get vnode address of the file 
    ret = vfs_open(kfilename, flags, mode, &vn_ptr);

	if(ret != 0)
        //TODOO
    	return ret;

    curproc->fd_table[fd] = (struct openfile *)kmalloc(sizeof(struct openfile));
    curproc->fd_table[fd]->flags = flags;
	curproc->fd_table[fd]->offset = 0;
    curproc->fd_table[fd]->vn_ptr = vn_ptr;

	kfree(kfilename);

	return fd;
}

ssize_t sys_write(int fd, const void *buf, size_t nbytes){
    // struct fd_table fd_table;
    // struct vnode vn;
    struct iovec iov;
    struct uio uio;    
    kprintf("+++%d+++\n",fd);
    //还缺vn和offset，要通过fd拿到对应的vn和offset
    // fd_table = curproc->fd_table;   //怎么获取fd为1的
    
    long long offset = 100;

    uio_uinit(&iov, &uio, (userptr_t)buf, nbytes, offset, UIO_WRITE);
    // VOP_WRITE(vn, uio); 


    return 0;
}