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
static bool valid(void *p);

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
static struct file* find_file(int fd);
static void remove_file (struct list_elem * target);

#define MAX_OPEN 128

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock_file);
}

bool
valid(void *p){
  // if(p == NULL){
  //   return 0;
  // }
  // else if (!(is_user_vaddr(p)) || !(is_user_vaddr(p + 1)) || 
  //   !(is_user_vaddr(p + 2)) || !(is_user_vaddr(p + 3)) || 
  //   !(is_user_vaddr(p + 4))) {
  //   sys_exit(-1);
  // }
  // else if((pagedir_get_page(thread_current()->pagedir, p) == NULL)) {
  //   sys_exit(-1);
  // } 
  return (p != NULL && is_user_vaddr(p) && pagedir_get_page(thread_current()->pagedir, p) != NULL);
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();
  printf("HELLO");
  uint32_t *p = (uint32_t) f->esp;
  if(!valid(p) || !valid(p + 1) || !valid(p + 2) || !valid(p + 3)){
    sys_exit(-1);
  }
  int status = *p;
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
        sys_exit(-1);
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
  struct process_info *p = thread_current()->process;
  p->exit_status = status;
  thread_exit();
}

static pid_t
sys_exec (const char *cmd_line) {
  return (pid_t) process_execute(cmd_line);
}  

static int
sys_wait (pid_t pid) {
  return process_wait(pid);
}

static bool
sys_create (const char* file, unsigned initial_size) {
  lock_acquire(&lock_file);
  bool val = filesys_create(file, initial_size);
  lock_release(&lock_file);
  return val;
}

static bool
sys_remove (const char* file) {
  lock_acquire(&lock_file);
  bool val = filesys_remove(file);
  lock_release(&lock_file);
  return val;
}

static int
sys_open (const char* file) {
  lock_acquire(&lock_file);
  struct file* new_file = filesys_open(file);
  lock_release(&lock_file);
  if(new_file == NULL){
    return -1;
  }
  else{
    struct thread* curr_thread = thread_current();
    if(curr_thread == NULL){
      return -1;
    }
    list_push_back(&curr_thread->open_file_list, &new_file->open_elem);
    return new_file->fd;
  }
}

static int
sys_filesize (int fd) {
  struct file* file = find_file(fd);
  if(file == NULL){
    return -1;
  }
  lock_acquire(&lock_file);
  int val = file_length(file);
  lock_release(&lock_file);
  return val;
}

static int
sys_read (int fd, void *buffer, unsigned size) {
  if(fd == STDIN_FILENO){
    char* buffer_copy = (char *) buffer;
    unsigned i;
    for(i = 0; i < size; i++){
      buffer_copy[i] = input_getc();
    }
    return size;
  }
  else if(fd == STDOUT_FILENO){
    return -1;
  }
  else{
    struct file* file = find_file(fd);
    if(file == NULL){
      return -1;
    }
    lock_acquire(&lock_file);
    int val = file_read(file, (char*) buffer, size);
    lock_release(&lock_file);
    return val;
  }
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
  if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
    return size;
  }
  else if(fd == STDIN_FILENO){
    return -1;
  }
  else{
    struct file *file = find_file(fd);
    if(file == NULL){
      return -1;
    }
    lock_acquire(&lock_file);
    int val = file_write(file->fd, buffer, size);
    lock_release(&lock_file);
    return val;
  }
}

static void 
sys_seek (int fd, unsigned position) {
  struct file *file = find_file(fd);
  if(file != NULL){
    lock_acquire(&lock_file);
    file_seek(file, position);
    lock_release(&lock_file);
  }
  return;
}

static unsigned
sys_tell (int fd) {
  struct file *file = find_file(fd);
  if(file == NULL){
    return -1;
  }
  lock_acquire(&lock_file);
  unsigned val = file_tell(file);
  lock_release(&lock_file);
  return val;
}

static void
sys_close (int fd) {
  struct file *file = find_file(fd);
  if(file != NULL){
    file_close(file);
    struct list_elem* target;
    target = &file->open_elem;
    // remove_file(target);
    list_remove(target);
  }
}

static struct file*
find_file(int fd) {
  struct thread *curr_thread = thread_current();
  struct list_elem *element;
  for(element = list_begin(&curr_thread->open_file_list);
    element != list_end(&curr_thread->open_file_list); element = list_next(element)){
      struct file * file_elem = list_entry(element, struct file, open_elem);
      if(file_elem->fd == fd){
        return file_elem;
      }
    }
    return NULL;
}

// static void
// remove_file(struct list_elem * target){
//   struct file * target_file = list_entry(target, struct file, open_file_elem);
//   struct thread *curr_thread = thread_current();
//   struct list_elem *element;
//   for(element = list_begin(&curr_thread->open_file_list);
//     element != list_end(&curr_thread->open_file_list); element = list_next(element)){
//       struct file * file_elem = list_entry(element, struct file, open_file_elem);
//       if(file_elem->fd == target_file->fd){
//         list_remove(target)
//       }
//     }
//     return;
// }