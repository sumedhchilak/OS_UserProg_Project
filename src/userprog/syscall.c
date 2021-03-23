#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <threads/vaddr.h>
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "lib/syscall-nr.h"



static void syscall_handler (struct intr_frame *);
/* check validity of memory address*/
static void verify_user(void *p);

/* Sys Calls */
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char* file, unsigned initial_size);
static bool remove (const char* file);
static int open (const char* file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
verify_user(void *p){
  if(p == NULL){
    exit(-1);
  }
  else if (!(is_user_vaddr(p)) || !(is_user_vaddr(p + 4))) {
    exit(-1);
  }
  else if((pagedir_get_page(thread_current()->pagedir, p) == NULL)) {
    exit(-1);
  }   
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();
  int *p = f->esp;
  verify_user((void *)p);
  int syscall = *p;
  switch(syscall){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit (-1);
      break;
    default;
      break;
  }

  static void
  halt(void){
    shutdown_power_off();
  }

}
