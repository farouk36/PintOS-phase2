#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "process.h"
#include "pagedir.h"



static void syscall_handler (struct intr_frame *);
void validate(const void *ptr);
static struct lock filesys_lock;

void 
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int syscall_number = *(int *)f->esp;
  switch (syscall_number)
  {
  case SYS_HALT:
    
    break;
  case SYS_EXIT:
    
    break;
  case SYS_EXEC:
    
    break;
  case SYS_WAIT:
   
    break;
  case SYS_CREATE:
    
    break;
  case SYS_REMOVE:
    
     break;
  case SYS_OPEN:
    break;
  case SYS_FILESIZE:
 
    break;
  case SYS_READ:

    break;
  case SYS_WRITE:
    int file_d = *get_paramater(f->esp,4);
    const void *bfr = (void *) *get_paramater(f->esp,8);
    if (!isValid_ptr(bfr)) exiter(-1);
    unsigned size = *get_paramater(f->esp,12);
    if(file_d<0||file_d>=128) return;
    if (file_d == 1) {
      lock_acquire(&filesys_lock);
      putbuf(bfr, size);
      lock_release(&filesys_lock);
      f->eax = size;
    }
    break;
  case SYS_SEEK:

    break;
  case SYS_TELL:

    break;
  case SYS_CLOSE:

    break;
  }
}


void terminate(int status){
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}
void validate(const void *ptr){
  if (ptr == NULL || !is_user_vaddr(ptr) ||pagedir_get_page(thread_current()->pagedir, ptr) == NULL){
    terminate(-1);
  }
}
int* get_paramater(void *esp,int offset){
  validate((int *)(esp + offset));
  return (int *)(esp + offset);
}