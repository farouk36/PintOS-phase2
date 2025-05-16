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
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);
void validate_ptr(const void *ptr);
void validate_string(const char *str);
static struct lock filesys_lock;
void get_arguments (struct intr_frame *f, int *args, int num_args);
void terminate(int status);

void
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  /* Validate that the stack pointer is valid */
  validate_ptr(f->esp);
  
  /* Get the system call number */
  int syscall_number = *(int *)(f->esp);
  
  /* Arguments array for system calls */
  int args[3];
  
  switch (syscall_number)
  {
      case SYS_HALT:
          shutdown_power_off();
          break;
      case SYS_EXIT:
          get_arguments(f, args, 1);
          terminate(*(int *)args[0]);
          break;
      case SYS_EXEC:
          get_arguments(f, args, 1);
          validate_ptr((const void *)*(int *)args[0]);
          validate_string((const char *)*(int *)args[0]);
          f->eax = process_execute((const char *)*(int *)args[0]);
          break;
      case SYS_WAIT:
          get_arguments(f, args, 1);
          f->eax = process_wait(*(int *)args[0]);
          break;
      case SYS_CREATE:
          // Implementation would go here
          break;
      case SYS_REMOVE:
          // Implementation would go here
          break;
      case SYS_OPEN:
          // Implementation would go here
          break;
      case SYS_FILESIZE:
          // Implementation would go here
          break;
      case SYS_READ:
          // Implementation would go here
          break;
      case SYS_WRITE:
          // Implementation would go here
          break;
      case SYS_SEEK:
          // Implementation would go here
          break;
      case SYS_TELL:
          // Implementation would go here
          break;
      case SYS_CLOSE:
          // Implementation would go here
          break;
      default:
          // Unknown system call
          terminate(-1);
  }
}

void terminate(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

void validate_ptr(const void *ptr) {
  if (ptr == NULL || !is_user_vaddr(ptr) || 
      pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    terminate(-1);
  }
}

void validate_string(const char *str) {
  // Validate the pointer itself
  validate_ptr(str);
  
  // Validate each character until we reach the null terminator
  for (; *str != '\0'; str++) {
    validate_ptr(str);
  }
}

/* Retrieves arguments as addresses from the stack */
void get_arguments(struct intr_frame *f, int *args, int num_args) {
  int i;
  
  for (i = 0; i < num_args; i++) {
    void *ptr = (int *)f->esp + i + 1; // Skip past the system call number
    validate_ptr(ptr);
    args[i] = (void *) ptr; // Store the address, not the value
  }
}