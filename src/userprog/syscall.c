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
int get_arg_int(void *esp, int offset);


static void syscall_handler (struct intr_frame *);
void validate_ptr(const void *ptr);
void validate_string(const char *str);
static struct lock filesys_lock;
void get_arguments (struct intr_frame *f, int *args, int num_args);
void terminate(int status);
static bool validate_fd(int fd);

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
    case SYS_EXIT:{
     int status = get_arg_int(f->esp, 4);
     sys_exit(status);
      break;
    }
    case SYS_EXEC:
      get_arguments(f, args, 1);
      validate_string((const char *)args[0]);
      f->eax = sys_exec((const char *)args[0]);
      break;
    case SYS_WAIT:
      get_arguments(f, args, 1);
      f->eax = sys_wait(args[0]);
      break;
    case SYS_CREATE:
      get_arguments(f, args, 2);
      validate_string((const char *)args[0]);
      f->eax = sys_create((const char *)args[0], args[1]);
      break;
    case SYS_REMOVE:
      get_arguments(f, args, 1);
      validate_string((const char *)args[0]);
      f->eax = sys_remove((const char *)args[0]);
      break;
    case SYS_OPEN:
      get_arguments(f, args, 1);
      validate_string((const char *)args[0]);
      f->eax = sys_open((const char *)args[0]);
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
      break;
    case SYS_TELL:
      get_arguments(f, args, 1);
      f->eax = sys_tell(args[0]);
      break;
    case SYS_CLOSE:
      get_arguments(f, args, 1);
      sys_close(args[0]);
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
sys_exec(const char *cmd_line) 
{
  validate_string(cmd_line);

  tid_t tid;
  lock_acquire(&filesys_lock);
  tid = process_execute(cmd_line);
  lock_release(&filesys_lock);

  // Return -1 if exec failed, as required by Pintos spec
  return tid == TID_ERROR ? -1 : tid;
}
static int 
sys_wait(tid_t pid) {
  return process_wait(pid);
}

static bool 
sys_create(const char *file, unsigned initial_size) {
  lock_acquire (&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

static bool 
sys_remove(const char *file) {
  lock_acquire (&filesys_lock);
  bool success = filesys_remove(file);
  lock_release (&filesys_lock);
  return success;
}

static int 
sys_open(const char *file) {
  struct file *opened_file = filesys_open(file);
  struct open_file * new_file = malloc(sizeof(struct open_file));
  if (opened_file == NULL || new_file == NULL) {
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
  // Validate buffer
  validate_ptr(buffer);
  validate_ptr(buffer + size - 1);
  
  // Handle stdin (fd = 0)
  if (fd == 0) {
    unsigned i;
    uint8_t *buf = buffer;
    for (i = 0; i < size; i++) {
      buf[i] = input_getc();
    }
    return size;
  }
  
  // Handle regular files
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
  // Validate buffer
  validate_ptr(buffer);
  validate_ptr(buffer + size - 1);
  
  // Handle stdout (fd = 1)
  if (fd == 1) {
    lock_acquire(&filesys_lock);
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }else if(fd==0){
    return -1;
  }
  
  // Validate fd
  if (!validate_fd(fd)) {
    return -1;
  }
  
  struct file *file = thread_current()->fd_table[fd];
  lock_acquire(&filesys_lock);
  int bytes_written = file_write(file, buffer, size);
  lock_release(&filesys_lock);
  return bytes_written;
}

static void 
sys_seek(int fd, unsigned position) {
  if (!validate_fd(fd)) {
    terminate(-1);
  }
  
  struct file *file = thread_current()->fd_table[fd];
  lock_acquire(&filesys_lock);
  file_seek(file, position);
  lock_release(&filesys_lock);
}

static unsigned 
sys_tell(int fd) {
  if (!validate_fd(fd)) {
    terminate(-1);
  }
  
  struct file *file = thread_current()->fd_table[fd];
  lock_acquire(&filesys_lock);
  unsigned pos = file_tell(file);
  lock_release(&filesys_lock);
  return pos;
}

void 
sys_close(int fd) {
  if (!validate_fd(fd)) {
    // Just return if fd is invalid, do not terminate to avoid recursion
    return;
  }
  struct thread *cur = thread_current();
  struct file *file = cur->fd_table[fd];
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
  cur->fd_table[fd] = NULL;

  // Remove from open_files list and free the struct
  struct list_elem *e;
  for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files); e = list_next(e)) {
    struct open_file *of = list_entry(e, struct open_file, elem);
    if (of->fd == fd) {
      list_remove(e);
      free(of);
      break;
    }
  }
}

void terminate(int status) {
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  
  /* Don't call sys_close, which could lead to infinite recursion */
  struct list_elem *e;
  while (!list_empty(&cur->open_files)) {
    e = list_pop_front(&cur->open_files);
    struct open_file *of = list_entry(e, struct open_file, elem);
    
    /* Close file directly and update fd table */
    if (cur->fd_table[of->fd] != NULL) {
      file_close(cur->fd_table[of->fd]);
      cur->fd_table[of->fd] = NULL;
    }
    free(of);
  }
  
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
  int *sp = (int *)f->esp;
  
  for (i = 0; i < num_args; i++) {
    void *ptr = sp + i + 1; // Skip past syscall number
    validate_ptr(ptr);
    args[i] = *(int *)ptr;  // Dereference to get the actual value
  }
}

static bool
validate_fd(int fd) {
  if (fd < 0 || fd >= 128 || thread_current()->fd_table[fd] == NULL) {
    return false;
  }
  return true;
}
int get_arg_int(void *esp, int offset) {
    uint8_t *addr = (uint8_t *) esp + offset;
    for (int i = 0; i < 4; i++) {
        validate_ptr(addr + i);
    }
    return *(int *) addr;
}