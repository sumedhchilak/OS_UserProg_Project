#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <threads/vaddr.h>
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "lib/syscall-nr.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/inode.h"
#include <user/syscall.h>
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
/* check validity of memory address*/
static void verify_user(void *p);

/* Sys Calls */
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char* file, unsigned initial_size);
static bool sys_remove (const char* file);
static int sys_open (const char* file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
verify_user(void *p){
  if(p == NULL){
    sys_exit(-1);
  }
  else if (!(is_user_vaddr(p)) || !(is_user_vaddr(p + 1)) || 
    !(is_user_vaddr(p + 2)) || !(is_user_vaddr(p + 3)) || !(is_user_vaddr(p + 4))) {
    sys_exit(-1);
  }
  else if((pagedir_get_page(thread_current()->pagedir, p) == NULL)) {
    sys_exit(-1);
  }   
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int32_t *p = (int32_t*)f->esp;
  int status = *p;
  verify_user((void *)p);

    switch(status){

      case SYS_HALT:
      {
        sys_halt();
        break;
      }

      case SYS_EXIT:
      {
        int exit_status = p[1];
        sys_exit (exit_status);
        break;
      }

      case SYS_EXEC:
      {
        const char* cmd_line = p[1];
        f->eax = sys_exec(cmd_line);
        break;
      }

      case SYS_WAIT:
      {
        pid_t child = p[1];
        f->eax = sys_wait(child);
        break;
      }

      case SYS_CREATE:
      {
        const char* file = p[1];
        unsigned initial_size = p[2];
        f->eax = sys_create(file, initial_size);
        break;
      }

      case SYS_REMOVE:
      {
        const char* file = p[1];
        f->eax = sys_remove(file);
        break;
      }

      case SYS_OPEN:
      {
        const char* file = p[1];
        f->eax = sys_open(file);
        break;
      }

      case SYS_FILESIZE:
      {
        int fd = p[1];
        f->eax = sys_filesize(fd);
        break;
      }

      case SYS_READ:
      {
        int fd = p[1];
        void *buffer = p[2];
        unsigned size = p[3];
        f->eax = sys_read(fd, buffer, size);
        break;
      }

      case SYS_WRITE:
      {
        int fd = p[1];
        const void *buffer = p[2];
        unsigned size = p[3];
        f->eax = sys_write(fd, buffer, size);
        break;
      }

      case SYS_SEEK:
      {
        int fd = p[1];
        unsigned position = p[2];
        sys_seek(fd, position);
        break;
      }

      case SYS_TELL:
      {
        int fd = p[1];
        f->eax = sys_tell(fd);
        break;
      }

      case SYS_CLOSE:
      {
        int fd = p[1];
        sys_close(fd);
        break;
      }
      
      default:
      {
        printf ("system call!\n");
        thread_exit ();
        break;
      }
    }
  }

static void
sys_halt (void) {
  shutdown_power_off();
}

static void
sys_exit (int status) {
  // struct status_child *child;
  thread_current()->exit_status = status;
  thread_exit();
}

static pid_t
sys_exec (const char *cmd_line) {
  return process_execute(cmd_line);
}  

static int
sys_wait (pid_t pid) {
  return process_wait(pid);
}

static bool
sys_create (const char* file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

static bool
sys_remove (const char* file) {
  return filesys_remove(file);
}

static int
sys_open (const char* file) {
  // struct file* new_file = filesys_open(file);
  // struct thread* curr_thread = thread_current();
  // if(new_file == NULL){
  //   return -1;
  // }
  // else{

  // }
  return -1;
}

static int
sys_filesize (int fd) {
  return 0;
}

static int
sys_read (int fd, void *buffer, unsigned size) {
  return 0;
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
  return 0;
}

static void 
sys_seek (int fd, unsigned position) {
  
}

static unsigned
sys_tell (int fd) {
  return 0;
}

static void
sys_close (int fd) {
  
}
