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


int fd_table_init(struct proc *newProc)
{
    int ret1, ret2, ret3;
    struct vnode *vn_in, *vn_out, *vn_err;
    char *stdin = kstrdup("con:");
    char *stdout = kstrdup("con:");
    char *stderr = kstrdup("con:");

    //intialize stdin file descriptor
    if(newProc->fd_table[0] == NULL){
        ret1 = vfs_open(stdin, O_RDONLY, 0, &vn_in);
        if(ret1 != 0){
            return ret1;
        }
        newProc->fd_table[0] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[0]->flags = O_RDONLY;
        newProc->fd_table[0]->offset = 0;
        newProc->fd_table[0]->vn_ptr = vn_in;
        newProc->fd_table[0]->lock = lock_create(stdin);
    }
    
    //intialize stdout file descriptor
    if(newProc->fd_table[1] == NULL){
        ret2 = vfs_open(stdout, O_WRONLY, 0, &vn_out);
        if(ret2 != 0){
            return ret2;
        }
        newProc->fd_table[1] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[1]->flags = O_WRONLY;
        newProc->fd_table[1]->offset = 0;
        newProc->fd_table[1]->vn_ptr = vn_out;
        newProc->fd_table[1]->lock = lock_create(stdout);
    }

    //intialize stderr file descriptor
    if(newProc->fd_table[2] == NULL){
        ret3 = vfs_open(stderr, O_WRONLY, 0, &vn_err);
        if(ret3 != 0){
            return ret3;
        }
        newProc->fd_table[2] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[2]->flags = O_WRONLY;
        newProc->fd_table[2]->offset = 0;
        newProc->fd_table[2]->vn_ptr = vn_err;
        newProc->fd_table[2]->lock = lock_create(stderr);
    }

    return 0;
}

int sys_open(const char *filename, int flags, mode_t mode, int *retval)
{
    size_t got;
    int fd, ret;
    struct vnode *vn_ptr;

    /*
     * Find out the new fd that is available. 
     * Fd starts from 3 as 0, 1, 2 have been used as stdin stdout stderr. 
     * Use spinlock to access file descriptor table safely concurently.
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
    	return ret;

    curproc->fd_table[fd] = (struct openfile *)kmalloc(sizeof(struct openfile));
    curproc->fd_table[fd]->flags = flags;
	curproc->fd_table[fd]->offset = 0;
    curproc->fd_table[fd]->vn_ptr = vn_ptr;
    curproc->fd_table[fd]->lock = lock_create(kfilename);

	kfree(kfilename);
    *retval = fd;

	return 0;
}

ssize_t sys_write(int fd, const void *buf, size_t nbytes, int *retval)
{
    struct iovec iov;
    struct uio uio;
    struct vnode *vn_ptr;
    off_t offset;
    int ret;
    
    if(curproc->fd_table[fd] == NULL || fd > OPEN_MAX || fd < 0){
        kprintf("--------Call VOP_WRITE Error------------\n");
		return EBADF;
	}
	if(curproc->fd_table[fd]->flags == O_RDONLY){
        kprintf("--------Call VOP_WRITE Error------------\n");
		return EINVAL;
	}

    lock_acquire(curproc->fd_table[fd]->lock);
    offset = curproc->fd_table[fd]->offset;
    uio_uinit(&iov, &uio, (userptr_t)buf, nbytes, offset, UIO_WRITE);
    vn_ptr = curproc->fd_table[fd]->vn_ptr;
    ret = VOP_WRITE(vn_ptr, &uio);
    if(ret){
        kprintf("--------Call VOP_WRITE Error------------\n");
		*retval = -1;
        lock_release(curproc->fd_table[fd]->lock); 
        return ret;
    }
    curproc->fd_table[fd]->offset = uio.uio_offset;
    *retval = nbytes - uio.uio_resid;
    lock_release(curproc->fd_table[fd]->lock);

    return 0;
}