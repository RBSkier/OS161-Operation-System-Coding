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
};

int fd_table_init(struct proc *newProc);
int sys_open(const char *filename, int flags, mode_t mode, int *retval);
ssize_t sys_write(int fd, const void *buf, size_t nbytes);


#endif /* _FILE_H_ */
