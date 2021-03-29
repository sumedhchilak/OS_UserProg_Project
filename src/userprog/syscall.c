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
#include "threads/init.h"


static void syscall_handler (struct intr_frame *);
/* check validity of memory address*/
static bool valid(void *p);

#define MAX_OPEN 128


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  uint32_t *p = (uint32_t*)f->esp;
  // if(!valid(p) || !valid(p + 1) || !valid(p + 2) || !valid(p + 3)){
  //   sys_exit(-1);
  // }
  int status = *p;
  printf("%d", status);
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

void
sys_halt (void) {
  shutdown_power_off();
}

void
sys_exit (int status) {
  struct thread *curr = thread_current();
  curr->exit_status = status;
  printf("%s: exit(%d)\n", curr->name, status);
  sema_up(&curr->sema_wait);
  sema_up(&curr->sema_free);

  struct list_elem *element;
  for(element = list_begin(&curr->list_child);
    element != list_end(&curr->list_child); element = list_next(element)){
      struct thread *child = list_entry(element, struct thread, child_elem);
      sema_up(&child->sema_free);
    }
  thread_exit();
}

struct thread*
get_child(tid_t c_tid){
  struct thread *curr = thread_current();
  if(!list_empty (&curr->list_child)){
    struct thread* recent_child = list_entry((*list_end(&curr->list_child)).prev,
                                      struct thread, child_elem);
    return recent_child;
  }
  return NULL;
}

pid_t
sys_exec (const char *cmd_line) {
  tid_t c_tid = process_execute(cmd_line);
  if(c_tid == TID_ERROR){
    return -1;
  }
  struct thread* child = get_child(c_tid);
  if(child == NULL){
    return -1;
  }
  sema_down(&child->sema_load);
  int loaded = child->loaded;
  if(loaded == 0){
    return -1;
  }
  return c_tid;
}  

struct thread*
find_tid (pid_t pid, struct thread *curr){
  struct list_elem *element;
  for(element = list_begin(&curr->list_child);
    element != list_end(&curr->list_child); element = list_next(element)){
      struct thread *child = list_entry(element, struct thread, child_elem);
      if(child->tid == pid){
        return child;
      }
    }
  return NULL;
}


int
sys_wait (int pid) {
  struct thread *curr = thread_current();
  if(list_empty(&curr->list_child)){
    return -1;
  }
  struct thread *child = find_tid(pid, curr);
  if(child == NULL){
    return -1;
  }
  sema_down(&child->sema_wait);
  int exit_status = child->exit_status;
  list_remove(&child->child_elem);
  sema_up (&child->sema_free);
  return exit_status;
}

 bool
sys_create (const char* file, unsigned initial_size) {
  sema_down(&sema_file);
  bool val = filesys_create(file, initial_size);
  sema_up(&sema_file);
  return val;
}

bool
sys_remove (const char* file) {
  sema_down(&sema_file);
  bool val = filesys_remove(file);
  sema_up(&sema_file);
  return val;
}

int
sys_open (const char* file) {
  // sema_down(&sema_file);
  // struct file* new_file = filesys_open(file);
  // if(new_file == NULL){
  //   sema_up(&sema_file);
  //   return -1;
  // }
  // else{
  //   struct thread* curr_thread = thread_current();
  //   if(curr_thread == NULL){
  //     sema_up(&sema_file);
  //     return -1;
  //   }
  //   list_push_back(&curr_thread->open_file_list, &new_file->open_elem);
  //   sema_up(&sema_file);
  //   return new_file->fd;
  // }
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  int value = -1;
  int i = 2;
  for(; i < 128; i++){
    if(curr->file_d[i] == NULL){
      struct file *new_f = filesys_open(file);
      if(new_f != NULL){
        curr->file_d[i] = new_f;
        value = i;
      }
      break;
    }
  }
  sema_up(&sema_file);
  return value;
}

int
sys_filesize (int fd) {
  // struct file* file = find_file(fd);
  // if(file == NULL){
  //   return -1;
  // }
  // sema_down(&sema_file);
  // int val = file_length(file);
  // sema_up(&sema_file);
  // return val;
  if(fd < 1 || fd >= 128){
    return -1;
  }
  struct thread *curr = thread_current();
  int size = -1;
  struct file *file = curr->file_d[fd];
  sema_down(&sema_file);
  if(file == NULL){
    size = -1;
  }
  else{
    size = file_length(file);
  }
  sema_up(&sema_file);
  return size;
}

int
sys_read (int fd, void *buffer, unsigned size) {
  // sema_down(&sema_file);
  // int val = -1;
  // if(fd == STDIN_FILENO){
  //   char* buffer_copy = (char *) buffer;
  //   unsigned i;
  //   for(i = 0; i < size; i++){
  //     buffer_copy[i] = input_getc();
  //   }
  //   val = size;
  // }
  // else if(fd == STDOUT_FILENO){
  //   val = -1;
  // }
  // else{
  //   struct file* file = find_file(fd);
  //   if(file == NULL){
  //     val = -1;
  //   }
  //   else{
  //     int res = file_read(file, (char*) buffer, size);
  //     val = res;
  //   }
  // }
  // sema_up(&sema_file);
  // return val;
  if(fd < 1 || fd >= 128){
    return -1;
  }
  sema_down(&sema_file);
  int val = -1;
  if(fd == STDIN_FILENO){
    char* buffer_copy = (char *) buffer;
    unsigned i;
    for(i = 0; i < size; i++){
      buffer_copy[i] = input_getc();
    }
    val = size;
  }
  else if(fd == STDOUT_FILENO){
    val = -1;
  }
  else {
    struct thread *curr = thread_current();
    struct file* file = curr->file_d[fd];
    if(file == NULL){
      val = -1;
    }
    else{
      int res = file_read(file, (char*) buffer, size);
      val = res;
    }
  }
  sema_up(&sema_file);
  return val;
}

int
sys_write (int fd, const void *buffer, unsigned size) {
  // if(fd == STDOUT_FILENO){
  //   sema_down(&sema_file);
  //   putbuf(buffer, size);
  //   sema_up(&sema_file);
  //   return size;
  // }
  // else if(fd == STDIN_FILENO){
  //   return -1;
  // }
  // else{
  //   struct file *file = find_file(fd);
  //   if(file == NULL){
  //     return -1;
  //   }
  //   sema_down(&sema_file);
  //   int val = file_write(file, buffer, size);
  //   sema_up(&sema_file);
  //   return val;
  // }
  // int retValue = -1;
  // sema_down(&sema_file);
  // if(fd == STDOUT_FILENO){
  //   putbuf(buffer, size);
  //   retValue = size;
  // }
  // else if(fd == STDIN_FILENO){
  //   retValue = -1;
  // }
  // else{
  //   struct file *file = find_file(fd);
  //   if(file == NULL){
  //     retValue = -1;
  //   }
  //   int val = file_write(file, buffer, size);
  //   retValue = val;
  // }
  // sema_up(&sema_file);
  // return retValue;
  if(fd < 1 || fd >= 128){
    return -1;
  }
  sema_down(&sema_file);
  int written = 0;
  if(fd == STDOUT_FILENO){
    written = size;
    putbuf((const char *) buffer, size);
  }
  else{
    struct thread *curr = thread_current();
    struct file *file = curr->file_d[fd];
    if(file == NULL){
      written = 0;
    }
    else{
      written = file_write(file, buffer, size);
    }
  }
  sema_up(&sema_file);
  return written;
}

void 
sys_seek (int fd, unsigned position) {
  // struct file *file = find_file(fd);
  // if(file != NULL){
  //   sema_down(&sema_file);
  //   file_seek(file, position);
  //   sema_up(&sema_file);
  // }
  // return;
  if(fd > 1 && fd < 128){
    sema_down(&sema_file);
    struct thread * curr = thread_current();
    struct file *file = curr->file_d[fd];
    if(file != NULL){
      file_seek(file, position);
    }
    sema_up(&sema_file);
  }
  return;
}

unsigned
sys_tell (int fd) {
  // struct file *file = find_file(fd);
  // if(file == NULL){
  //   return -1;
  // }
  // sema_down(&sema_file);
  // unsigned val = file_tell(file);
  // sema_up(&sema_file);
  // return val;
  if(fd < 1 || fd >= 128){
    return -1;
  }
  unsigned value = -1;
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  struct file *file = curr->file_d[fd];
  if(file != NULL){
    value = file_tell(file);
    sema_up(&sema_file);
    return value;
  }
  sema_up(&sema_file);
  sys_exit (-1);
  return value;
}

void
sys_close (int fd) {
  // struct file *file = find_file(fd);
  // if(file != NULL){
  //   file_close(file);
  //   struct list_elem* target;
  //   target = &file->open_elem;
  //   // remove_file(target);
  //   list_remove(target);
  // }
  if(fd < 1 || fd >= 128){
    return;
  }
  sema_down(&sema_file);
  struct thread *curr = thread_current();
  struct file * file = curr->file_d[fd];
  if(file != NULL){
    file_close(file);
    curr->file_d[fd] = 0;
  }
  sema_up(&sema_file);
}

struct file*
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

// void
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