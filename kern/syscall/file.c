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

int sys_open(const char *filename, int flags, mode_t mode, int *retval){
    size_t got;
    int fd, ret;
    struct vnode *vn_ptr;

    kprintf("-----curproc->fd_table[0]->flags: %d---------",curproc->fd_table[0]->flags);
    kprintf("-----curproc->fd_table[1]->flags: %d---------",curproc->fd_table[1]->flags);
    kprintf("-----curproc->fd_table[2]->flags: %d---------",curproc->fd_table[2]->flags);

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
    	return ret;

    curproc->fd_table[fd] = (struct openfile *)kmalloc(sizeof(struct openfile));
    curproc->fd_table[fd]->flags = flags;
	curproc->fd_table[fd]->offset = 0;
    curproc->fd_table[fd]->vn_ptr = vn_ptr;

	kfree(kfilename);
    *retval = fd;

	return 0;
}

int fd_table_init(struct proc *newProc)
{
    int ret;
    struct vnode *vn_in, *vn_out, *vn_err;
    char *console = kstrdup("con:");

    //intialize stdin file descriptor
    if(newProc->fd_table[0] == NULL){
        ret = vfs_open(console, O_RDONLY, 0664, &vn_in);
        // ret = vfs_open(console, O_RDONLY, 0664, &vn_ptr1);
        if(ret != 0){
            kprintf("file descriptor initialize failed\n");
            return ret;
        }
        newProc->fd_table[0] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[0]->flags = O_RDONLY;
        newProc->fd_table[0]->offset = 0;
        newProc->fd_table[0]->vn_ptr = vn_in;
    }
    
    //intialize stdout file descriptor
    if(newProc->fd_table[1] == NULL){
        ret = vfs_open(console, O_WRONLY, 0, &vn_out);
        if(ret != 0){
            kprintf("file descriptor initialize failed\n");
            return ret;
        }
        newProc->fd_table[1] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[1]->flags = O_WRONLY;
        newProc->fd_table[1]->offset = 0;
        newProc->fd_table[1]->vn_ptr = vn_out;
    }

    //intialize stderr file descriptor
    if(newProc->fd_table[1] == NULL){
        ret = vfs_open(console, O_WRONLY, 0, &vn_err);
        if(ret != 0){
            kprintf("file descriptor initialize failed\n");
            return ret;
        }
        newProc->fd_table[2] = (struct openfile *)kmalloc(sizeof(struct openfile));
        newProc->fd_table[2]->flags = O_WRONLY;
        newProc->fd_table[2]->offset = 0;
        newProc->fd_table[2]->vn_ptr = vn_err;
    }

    kfree(console);
    return 0;
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