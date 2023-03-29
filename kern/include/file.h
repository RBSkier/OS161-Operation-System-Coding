/*
 * Declarations for file handle and file table management.
 */

#ifndef _FILE_H_
#define _FILE_H_

/*
 * Contains some file-related maximum length constants
 */


/*
 * Put your function declarations and data types here ...
 */
struct proc;

struct openfile{
    int flags;
    off_t offset;
    struct vnode *vn_ptr;
    struct lock *lock;
};

int fd_table_init(struct proc *newProc);
int sys_open(const char *filename, int flags, mode_t mode, int *retval);
ssize_t sys_write(int fd, const void *buf, size_t nbytes, int *retval);
ssize_t sys_read(int fd, void *buf, size_t buflen, int *retval);
int sys_close(int fd, int *retval);
ssize_t sys_lseek(int fd, uint32_t tf_a2, uint32_t tf_a3, int32_t tf_sp, int64_t *retval64);
int sys_dup2(int oldfd, int newfd, int *retval);


#endif /* _FILE_H_ */
