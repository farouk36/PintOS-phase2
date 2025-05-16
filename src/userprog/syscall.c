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
#include "devices/shutdown.h"
#include <syscall.h>
#include <fcntl.h>

// Function declarations for system calls
static void sys_halt(void);
static void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);



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
      sys_halt();
      break;
    case SYS_EXIT:
      get_arguments(f, args, 1);
      sys_exit(*(int *)args[0]);
      break;
    case SYS_EXEC:
      get_arguments(f, args, 1);
      f->eax = sys_exec((char *)args[0]);
      break;
    case SYS_WAIT:
      get_arguments(f, args, 1);
      f->eax = sys_wait(*(pid_t *)args[0]);
      break;
    case SYS_CREATE:
      get_arguments(f, args, 2);
      f->eax = sys_create((char *)args[0], args[1]);
      break;
    case SYS_REMOVE:
      get_arguments(f, args, 1);
      f->eax = sys_remove((char *)args[0]);
      break;
    case SYS_OPEN:
      get_arguments(f, args, 1);
      f->eax = sys_open((char *)args[0]);
      break;
    case SYS_FILESIZE:
      get_arguments(f, args, 1);
      f->eax = sys_filesize(args[0]);
      break;
    case SYS_READ:
      get_arguments(f, args, 3);
      f->eax = sys_read(args[0], (void *)args[1], args[2]);
      break;
    case SYS_WRITE:
      get_arguments(f, args, 3);
      f->eax = sys_write(args[0], (void *)args[1], args[2]);
      break;
    case SYS_SEEK:
      get_arguments(f, args, 2);
      sys_seek(args[0], args[1]);
      //! add put 1 on eax or not
      break;
    case SYS_TELL:
      get_arguments(f, args, 1);
      f->eax = sys_tell(args[0]);
      break;
    case SYS_CLOSE:
      get_arguments(f, args, 1);
      sys_close(args[0]);
      //! add put 1 on eax or not
      break;
  }
}

static void 
sys_halt(void) {
  shutdown_power_off();
}

static void 
sys_exit(int status) {
  terminate(status);
}

static pid_t 
sys_exec(const char *cmd_line) {
  return process_execute(cmd_line);
}

static int 
sys_wait(pid_t pid) {
  return process_wait(pid);
}

static bool 
sys_create(const char *file, unsigned initial_size) {
  if (!filesys_create(file, initial_size)) {
    return false;
  }
  return true;
}

static bool 
sys_remove(const char *file) {
  if (!filesys_remove(file)) {
    return false;
  }
  return true;
}

static int 
sys_open(const char *file) {
  struct file *opened_file = filesys_open(file);
  if (opened_file == NULL) {
    return -1;
  }
  int fd = thread_current()->fd_last++;
  thread_current()->fd_table[fd] = opened_file;
  return fd;
}

static int 
sys_filesize(int fd) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    terminate(-1);
  }
  lock_acquire(&filesys_lock);
  int size = file_length(file);
  lock_release(&filesys_lock);
  return size;
}

static int 
sys_read(int fd, void *buffer, unsigned size) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  int bytes_read = file_read(file, buffer, size);
  lock_release(&filesys_lock);
  return bytes_read;
}

static int 
sys_write(int fd, const void *buffer, unsigned size) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    terminate(-1);
  }
  lock_acquire(&filesys_lock);
  int bytes_written = file_write(file, buffer, size);
  lock_release(&filesys_lock);
  return bytes_written;
}

static void 
sys_seek(int fd, unsigned position) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    terminate(-1);
  }
  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
}

static unsigned 
sys_tell(int fd) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    terminate(-1);
  }
  lock_acquire(&filesys_lock);
  unsigned pos = file_tell(file);
  lock_release(&filesys_lock);
  return pos;
}

static void 
sys_close(int fd) {
  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    terminate(-1);
  }
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
  thread_current()->fd_table[fd] = NULL;
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