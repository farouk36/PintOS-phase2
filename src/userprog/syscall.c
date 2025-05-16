#include "syscall.h"
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

// Define tid_t if not already defined
#include "pagedir.h"
#include "devices/shutdown.h"
// #include <syscall.h>


// Function declarations for system calls
static void sys_halt(void);
static void sys_exit(int status);
static tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t pid);
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
      sys_halt();
      break;
    case SYS_EXIT:
      get_arguments(f, args, 1);
      sys_exit(*(int*)args[0]);
      break;
    case SYS_EXEC:
      get_arguments(f, args, 1);
      validate_string(*(const char**)args[0]);
      f->eax = sys_exec(*(const char**)args[0]);
      break;
    case SYS_WAIT:
      get_arguments(f, args, 1);
      f->eax = sys_wait(*(tid_t*)args[0]);
      break;
    case SYS_CREATE:
      get_arguments(f, args, 2);
      validate_string(*(char**)args[0]);
      f->eax = sys_create(*(char**)args[0], *(unsigned*)args[1]);
      break;
    case SYS_REMOVE:
      get_arguments(f, args, 1);
      validate_string(*(char**)args[0]);
      f->eax = sys_remove(*(char**)args[0]);
      break;
    case SYS_OPEN:
      get_arguments(f, args, 1);
      validate_string(*(char**)args[0]);
      f->eax = sys_open(*(char**)args[0]);
      break;
    case SYS_FILESIZE:
      get_arguments(f, args, 1);
      f->eax = sys_filesize(*(int*)args[0]);
      break;
    case SYS_READ:
      get_arguments(f, args, 3);
      f->eax = sys_read(*(int*)args[0], *(void**)args[1], *(unsigned*)args[2]);
      break;
    case SYS_WRITE:
      get_arguments(f, args, 3);
      f->eax = sys_write(*(int*)args[0], *(void**)args[1], *(unsigned*)args[2]);
      break;
    case SYS_SEEK:
      get_arguments(f, args, 2);
      sys_seek(*(int*)args[0], *(unsigned*)args[1]);
      break;
    case SYS_TELL:
      get_arguments(f, args, 1);
      f->eax = sys_tell(*(int*)args[0]);
      break;
    case SYS_CLOSE:
      get_arguments(f, args, 1);
      sys_close(*(int*)args[0]);
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

static tid_t 
sys_exec(const char *cmd_line) {
  return process_execute(cmd_line);
}

static int 
sys_wait(tid_t pid) {
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
  struct open_file * new_file = malloc(sizeof(struct open_file));
  if (opened_file == NULL) {
    return -1;
  }
  int fd = thread_current()->fd_last++;
  thread_current()->fd_table[fd] = opened_file;
  new_file->fd = fd ;
  new_file->file = opened_file;
  lock_acquire(&filesys_lock);
  list_push_back(&thread_current()->open_files, &new_file->elem);
  lock_release(&filesys_lock);
  if (new_file == NULL) {
    file_close(opened_file);
    return -1;
  }
  
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

void 
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
  struct list_elem * e ;
	struct open_file * curFile ;
    for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e)){
        curFile = list_entry(e,struct open_file , elem);
		sys_close(curFile->fd);
	}
  process_exit();
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
  int *sp = (int *)f->esp;
  
  for (i = 0; i < num_args; i++) {
    void *ptr = sp + i + 1; // Skip past syscall number
    validate_ptr(ptr);
    args[i] = (int)ptr;  // Store the address
  }
}