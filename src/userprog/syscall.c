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
#include "shutdown.h"



static void syscall_handler (struct intr_frame *);
void validate(const void *ptr);
static struct lock filesys_lock;
char* get_parameter_string(void *esp, int offset);
int convert_to_physical(const void *ptr);
void get_arguments (struct intr_frame *f, int *args, int num_args);
void terminate(int status);

void 
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{ 
  int esp = convert_to_physical((void *) f->esp);
  int syscall_number = *(int *) esp;
  int args[3];

  switch (syscall_number)
  {
  case SYS_HALT:
    shutdown_power_off();
    break;
  case SYS_EXIT:
  get_arguments(f, args, 1);
    terminate( (int *) args[0]);
    break;
  case SYS_EXEC: 
    get_arguments(f, args, 1);
    char* file_name = (char *) args[0];
    process_execute(file_name);
    break;
  case SYS_WAIT:{
    // get pid 
    int * parameter = (int *) args[0];
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
  if (ptr == NULL || !is_user_vaddr(ptr)){
    terminate(-1);
  }
}

int convert_to_physical(const void *ptr){
  void *page = pagedir_get_page(thread_current()->pagedir, ptr);
  if (page == NULL){
    terminate(-1);
  }else {
    return (int) page;
  }
}

void get_arguments (struct intr_frame *f, int *args, int num_args) {
  int i = 0;
  while(i<num_args){
    int *ptr = (int *) f->esp + 1 + i;
    validate(ptr);
    args[i++] = convert_to_physical((const void *) ptr);
  }
}