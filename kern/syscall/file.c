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
#include <kern/stattypes.h>
#include <endian.h>


int fd_table_init(struct proc *newProc)
{
    int ret1, ret2, ret3;
    struct vnode *vn_in, *vn_out, *vn_err;
    char *stdin, *stdout, *stderr;

    bzero(newProc->fd_table, sizeof(newProc->fd_table));
    //intialize stdin file descriptor
    stdin = kstrdup("con:");
    ret1 = vfs_open(stdin, O_RDONLY, 0, &vn_in);
    if(ret1 != 0){
        kfree(stdin);
        return ret1;
    }
    newProc->fd_table[STDIN_FILENO] = (struct openfile *)kmalloc(sizeof(struct openfile));
    newProc->fd_table[STDIN_FILENO]->flags = O_RDONLY;
    newProc->fd_table[STDIN_FILENO]->offset = 0;
    newProc->fd_table[STDIN_FILENO]->vn_ptr = vn_in;
    newProc->fd_table[STDIN_FILENO]->lock = lock_create(stdin);
    kfree(stdin);
    
    //intialize stdout file descriptor
    stdout = kstrdup("con:");
    ret2 = vfs_open(stdout, O_WRONLY, 0, &vn_out);
    if(ret2 != 0){
        kfree(stdout);
        return ret2;
    }
    newProc->fd_table[STDOUT_FILENO] = (struct openfile *)kmalloc(sizeof(struct openfile));
    newProc->fd_table[STDOUT_FILENO]->flags = O_WRONLY;
    newProc->fd_table[STDOUT_FILENO]->offset = 0;
    newProc->fd_table[STDOUT_FILENO]->vn_ptr = vn_out;
    newProc->fd_table[STDOUT_FILENO]->lock = lock_create(stdout);
    kfree(stdout);

    //intialize stderr file descriptor
    stderr = kstrdup("con:");
    ret3 = vfs_open(stderr, O_WRONLY, 0, &vn_err);
    if(ret3 != 0){
        kfree(stderr);
        return ret3;
    }
    newProc->fd_table[STDERR_FILENO] = (struct openfile *)kmalloc(sizeof(struct openfile));
    newProc->fd_table[STDERR_FILENO]->flags = O_WRONLY;
    newProc->fd_table[STDERR_FILENO]->offset = 0;
    newProc->fd_table[STDERR_FILENO]->vn_ptr = vn_err;
    newProc->fd_table[STDERR_FILENO]->lock = lock_create(stderr);
    kfree(stderr);

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
    while(curproc->fd_table[fd] != NULL && fd < OPEN_MAX){
        fd++;
    }
    spinlock_release(&curproc->p_lock);
    if(fd >= OPEN_MAX){
		return ENFILE;
    }

    //copy the string from user space to kernel space.
    char *kfilename = (char*)kmalloc(sizeof(char)*PATH_MAX);
    if(kfilename == NULL){
		return ENOMEM; 
    }
	copyinstr((const_userptr_t)filename, kfilename, PATH_MAX, &got);
    //call vfs_open to get vnode address of the file 
    ret = vfs_open(kfilename, flags, mode, &vn_ptr);
	if(ret != 0){
    	return ret;
    }

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

    lock_acquire(curproc->fd_table[fd]->lock);
    if(curproc->fd_table[fd] == NULL || fd >= OPEN_MAX || fd < 0){
        lock_release(curproc->fd_table[fd]->lock);
		return EBADF;
	}
	if(curproc->fd_table[fd]->flags == O_RDONLY){
        lock_release(curproc->fd_table[fd]->lock);
		return EBADF;
	}

    offset = curproc->fd_table[fd]->offset;
    vn_ptr = curproc->fd_table[fd]->vn_ptr;
    uio_uinit(&iov, &uio, (userptr_t)buf, nbytes, offset, UIO_WRITE);
    ret = VOP_WRITE(vn_ptr, &uio);
    if(ret){
        lock_release(curproc->fd_table[fd]->lock); 
        return ret;
    }
    *retval = nbytes - uio.uio_resid;
    curproc->fd_table[fd]->offset = uio.uio_offset;
    lock_release(curproc->fd_table[fd]->lock);

    return 0;
}

ssize_t sys_read(int fd, void *buf, size_t buflen, int *retval)
{
    off_t offset;
    struct vnode *vn_ptr;
    struct uio uio;
    struct iovec iov;
    int ret;

    lock_acquire(curproc->fd_table[fd]->lock);
    if(curproc->fd_table[fd] == NULL || fd >= OPEN_MAX || fd < 0){
        lock_release(curproc->fd_table[fd]->lock);
        return EBADF;
    }
    if(curproc->fd_table[fd]->flags == O_WRONLY){
        lock_release(curproc->fd_table[fd]->lock);
        return EBADF;
    }

    offset = curproc->fd_table[fd]->offset;
    vn_ptr = curproc->fd_table[fd]->vn_ptr;
    uio_uinit(&iov, &uio, (userptr_t)buf, buflen, offset, UIO_READ);
    ret = VOP_READ(vn_ptr, &uio);
    if(ret){
        lock_release(curproc->fd_table[fd]->lock); 
        return ret;
    }
    *retval = buflen - uio.uio_resid;
    curproc->fd_table[fd]->offset = uio.uio_offset;
    lock_release(curproc->fd_table[fd]->lock);

    return 0;
}

int sys_close(int fd, int *retval) {

    lock_acquire(curproc->fd_table[fd]->lock);
    if (fd < 0 || fd >= OPEN_MAX || curproc->fd_table[fd] == NULL) {
        return EBADF;
    }
    vfs_close(curproc->fd_table[fd]->vn_ptr);   
    lock_release(curproc->fd_table[fd]->lock);
    
    //destroy the fd lock after it has been used for the last time.
    lock_destroy(curproc->fd_table[fd]->lock);
    kfree(curproc->fd_table[fd]);
    curproc->fd_table[fd] = NULL;

    *retval = 0;
    return 0;
}

ssize_t sys_lseek(int fd, uint32_t tf_a2, uint32_t tf_a3, int32_t tf_sp, int64_t *retval64){
    uint64_t pos;
    int whence;
    int ret;
    struct openfile *file;
    struct stat stat_buf;

    if (fd >= OPEN_MAX || fd < 0 || curproc->fd_table[fd] == NULL) {
        return EBADF;
    }
    if(!VOP_ISSEEKABLE(curproc->fd_table[fd]->vn_ptr)) {
		return ESPIPE;
	}
    join32to64(tf_a2, tf_a3, &pos);

    copyin((const_userptr_t)(tf_sp + 16), &whence, sizeof(int));
    if(whence < 0 || whence > 2){
		return EINVAL;
	}

    file = curproc->fd_table[fd];

    lock_acquire(file->lock);
    switch (whence) {
        case SEEK_SET:
            file->offset = pos;
            *retval64 = file->offset;
            break;
        case SEEK_CUR:
            file->offset += pos;
            *retval64 = file->offset;
            break;
        case SEEK_END:
            ret = VOP_STAT(file->vn_ptr, &stat_buf);
            if(ret){
                lock_release(file->lock);
                return ret;
            }else{
                file->offset = pos + stat_buf.st_size;
                *retval64 = file->offset;
            }
            break;
        default:
            lock_release(file->lock);
            break;
    }
    lock_release(file->lock);

    return 0;
}

int sys_dup2(int oldfd, int newfd, int *retval) {
    int ret;

    if (oldfd < 0 || oldfd >= OPEN_MAX || curproc->fd_table[oldfd] == NULL) {
        return EBADF;
    }
    if (newfd < 0 || newfd >= OPEN_MAX) {
        return EBADF;
    }
    if (oldfd == newfd) {
        return EBADF;
    }
    
    lock_acquire(curproc->fd_table[oldfd]->lock);
    if(curproc->fd_table[newfd] != NULL){
		ret = sys_close(newfd, retval);
        if(ret){
            return ret;
        }
	}
    curproc->fd_table[newfd] = curproc->fd_table[oldfd];
    lock_release(curproc->fd_table[oldfd]->lock);

    *retval = newfd;
    return 0;
}