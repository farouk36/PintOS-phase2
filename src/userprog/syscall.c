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
char* get_parameter_string(void *esp, int offset);
int* get_parameters(void *esp, int offset);
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
  shutdown_power_off();

    break;
  case SYS_EXIT: {
    int* status = get_parameters(f->esp, 4);
    terminate(*status);
    break;
}
  case SYS_EXEC: {
    char* file_name = get_parameter_string(f->esp, 4);
    validate(file_name);
    process_execute(file_name);
    break;
}
  case SYS_WAIT:{
    // get pid 
    int * parameter = get_parameters(f->esp , 4);
    process_wait(*parameter);
    break;}
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
  process_exit();
}
void validate(const void *ptr){
  if (ptr == NULL || !is_user_vaddr(ptr) ||pagedir_get_page(thread_current()->pagedir, ptr) == NULL){
    terminate(-1);
  }
}
char* get_parameter_string(void *esp, int offset) {
  validate((char *)(esp + offset));
  return *(char **)(esp + offset);
}
int* get_parameters(void *esp, int offset){
   validate((int *)(esp + offset));
   return (int *)(esp + offset);
}