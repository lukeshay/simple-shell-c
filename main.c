#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PROMPT "\033[0;34mshell352>\033[0;32m "
#define MAX_LINE 80
#define MAX_ARGS 128

enum builtin_t { NONE, QUIT, CD, KILL };
enum redirect_t { NO, IN, OUT };

struct command {
  int argc;
  char *argv[MAX_ARGS];
  enum builtin_t builtin;
  enum redirect_t redirect;
  char *file;
  char cmd[MAX_LINE];
  int bg;
};

struct background {
  pid_t pid;
  pid_t code;
  int num;
  char cmd[MAX_LINE];
};

static int bg_cmd_count = 0;
static int bg_cmd_count_total = 1;
static struct background *bg_cmds[40];

void clean_bg_cmds() {
  int i;
  int cur_count = 0;

  for (i = 0; i < 40 && bg_cmds[i] != NULL; i++) {
    if (bg_cmds[i]->code == 0 && cur_count == i) {
      cur_count++;
    } else if (bg_cmds[i]->code == 0) {
      bg_cmds[cur_count] = malloc(sizeof(struct background));
      *bg_cmds[cur_count++] = *bg_cmds[i];
      free(bg_cmds[i]);
      bg_cmds[i] = NULL;
    } else {
      free(bg_cmds[i]);
      bg_cmds[i] = NULL;
    }
  }

  bg_cmd_count = cur_count;
}

void check_bg_cmds() {
  int i;
  int status;

  for (i = 0; i < 40 && bg_cmds[i] != NULL; i++) {
    bg_cmds[i]->code = waitpid(bg_cmds[i]->pid, &status, WNOHANG);

    if (bg_cmds[i]->code == -1) {
      printf("[%d] Exit %d %s\n", bg_cmds[i]->num, status, bg_cmds[i]->cmd);
    } else if (bg_cmds[i]->code != 0) {
      if (!status) {
        printf("[%d] Done %s\n", bg_cmds[i]->num, bg_cmds[i]->cmd);
        bg_cmds[i]->code = 1;
      } else {
        printf("[%d] Exit %d %s\n", bg_cmds[i]->num, status, bg_cmds[i]->cmd);
        bg_cmds[i]->code = -1;
      }
    }
  }

  clean_bg_cmds();
}

void insert_bg_cmd(pid_t pid, struct command cmd) {
  struct background *bg_cmd;
  int i;

  bg_cmd = malloc(sizeof(struct background));

  for (i = 0; i < 40 && bg_cmds[i] != NULL; i++)
    ;

  bg_cmd->pid = pid;
  bg_cmd->code = 0;
  bg_cmd->num = bg_cmd_count_total++;
  strcpy(bg_cmd->cmd, cmd.cmd);

  bg_cmds[i] = bg_cmd;

  printf("[%d] %d\n", bg_cmd->num, bg_cmd->pid);
}

int get_length(char *str) {
  int len;

  for (len = 0; str[len] != '\0'; len++)
    ;

  return len;
}

void wait_pid(pid_t pid) {
  while (waitpid(pid, NULL, 0) == 0)
    ;
}

/**
 *Runs the 'cd' command.
 */
int builtin_cd(char **args) {
  if (args[1] == NULL) {
    fprintf(stderr, "Expected argument to \"cd\"\n");
    return -1;
  } else {
    if (chdir(args[1]) != 0) {
      return -1;
    }
  }

  return 1;
}

/**
 *Runs the 'kill' command.
 */
int builtin_kill(char **args) {
  int i;
  int found = 0;
  pid_t pid;

  if (args[1] == NULL) {
    fprintf(stderr, "No PID provided");
    return -1;
  } else {
    pid = atoi(args[1]);
    kill(pid, SIGKILL);

    for (i = 0; i < 40 && bg_cmds[i] != NULL; i++) {
      if (bg_cmds[i]->pid == pid) {
        printf("[%d] Terminated %s\n", bg_cmds[i]->num, bg_cmds[i]->cmd);
        bg_cmds[i]->code = -1;
        found = 1;
        break;
      }
    }

    if (!found) {
      fprintf(stderr, "Process with PID %d not found\n", pid);
    } else {
      clean_bg_cmds();
    }
  }

  return 1;
}

/**
 *Checks cmd->argv[0] to see if it is a builtin command.
 */
enum builtin_t parse_builtin(struct command *cmd) {
  if (strcmp(cmd->argv[0], "cd") == 0) {
    return (enum builtin_t)CD;
  } else if (strcmp(cmd->argv[0], "exit") == 0) {
    return (enum builtin_t)QUIT;
  } else if (strcmp(cmd->argv[0], "kill") == 0 ||
             strcmp(cmd->argv[0], "KILL") == 0) {
    return (enum builtin_t)KILL;
  } else {
    return (enum builtin_t)NONE;
  }
}

/**
 *Parses the string by breaking it up into words and determines whether the
 *command is builtin or not. This function loops through and when a delimiter
 *is hit, the word gets added to cmd->argv. A function is then called that
 *determines if the command is builtin. This function returns whether the
 *parsed command should run in the background. If it should, then 1 is
 *returned.
 */
void parse(struct command *cmd) {
  const char delims[10] = " \t\r\n";
  char *ptr;
  int length;
  int redirected = 0;
  char cmds[MAX_LINE];

  strcpy(cmds, cmd->cmd);

  cmd->argc = 0;
  cmd->redirect = (enum redirect_t)NO;
  cmd->file = "";
  cmd->bg = 0;

  ptr = strtok(cmds, delims);

  while (ptr != NULL) {
    length = get_length(ptr);

    if (!redirected && cmd->redirect != (enum redirect_t)NO) {
      cmd->file = ptr;
      redirected = 1;
      ptr = strtok(NULL, delims);
      continue;
    } else {
      cmd->argv[cmd->argc++] = ptr;
    }

    if (length == 1 && ptr[0] == '>') {
      cmd->argc--;
      cmd->redirect = (enum redirect_t)OUT;
    } else if (length == 1 && ptr[0] == '<') {
      cmd->argc--;
      cmd->redirect = (enum redirect_t)IN;
    }

    if (cmd->argc >= MAX_ARGS - 1) {
      break;
    }

    if (redirected) {
      break;
    }

    ptr = strtok(NULL, delims);
  }

  cmd->argv[cmd->argc] = NULL;

  if (cmd->argc == 0) {
    return;
  }

  // Checks if the command is a builtin
  cmd->builtin = parse_builtin(cmd);

  // Checks if the command should run the background
  if ((cmd->bg = (*cmd->argv[cmd->argc - 1] == '&')) != 0) {
    cmd->argv[--cmd->argc] = NULL;
    length = get_length(cmd->cmd);

    cmd->cmd[length - 2] = '\0';
  }
  printf("1: %s\n", cmd->argv[0]);
}

/**
 *This function redirects the input or output of a command. This function first
 *checks if the file exits for a redirect out. If it does not, it will create
 *the file. The redirection is done using dup2.
 */
int redirect(struct command *cmd) {
  int fd = -2;
  FILE *file;

  // Check if there is a redirect in or out
  if (cmd->redirect == (enum redirect_t)OUT) {
    // Creates the file if it does not exist
    if (access(cmd->file, F_OK) == -1) {
      file = fopen(cmd->file, "w");
      if (file == NULL) {
        return -1;
      }

      fclose(file);
    }

    // Attempts to open the file and returns the fd
    if ((fd = open(cmd->file, O_WRONLY)) != -1) {
      dup2(fd, STDOUT_FILENO);
    }
  } else if (cmd->redirect == (enum redirect_t)IN) {
    // Attempts to open the file and returns the fd
    if ((fd = open(cmd->file, O_RDONLY)) != -1) {
      dup2(fd, STDIN_FILENO);
    }
  }

  return fd;
}

/**
 *Runs the given system command by first forking and then waiting for the child
 *process to finish if the command is supposed to run in the foreground.
 */
void run_system_command(struct command cmd) {
  pid_t child_pid;
  int fd;

  printf("4: %s\n", cmd.argv[0]);
  // Forks the current process and sees if it is successful
  if ((child_pid = fork()) < 0) {
    fprintf(stderr, "fork() error");
  } else if (child_pid == 0) { // Runs the command because the PID indicates it

    printf("5: %s\n", cmd.argv[0]);
    // is the child process
    fd = redirect(
        &cmd); // Calls redirect helper which redirects input/output if necessary

    if (fd == -1) {
      fprintf(stderr, "Error opening file '%s'", cmd.file);
      exit(0);
    }

    if (execvp(cmd.argv[0], cmd.argv) < 0) {
      fprintf(stderr, "Command not found: %s\n", cmd.argv[0]);
      if (fd >= 0) {
        close(fd);
      }

      exit(0);
    }

    // Close file if one was opened.
    if (fd >= 0) {
      close(fd);
    }

  } else {
    if (cmd.bg) {
      insert_bg_cmd(child_pid, cmd);
    } else {
      wait_pid(child_pid);
    }
    check_bg_cmds();
  }
}

/**
 *Runs the given built in command. The return value of this function is whether
 *the shell should continue. If the shell should exit, 0 is returned from this
 *function.
 */
int run_builtin_command(struct command *cmd) {
  int status = 0;
  pid_t child_pid;
  int fd;

  // Returns 0 if the shell should quit.
  if (cmd->builtin == (enum builtin_t)QUIT) {
    return 0;
  }

  // Forks the current process and sees if it is successful
  if ((child_pid = fork()) < 0) {
    fprintf(stderr, "fork() error");
  } else if (child_pid == 0) { // Runs the command because the PID indicates it
    // is the child process
    fd = redirect(
        cmd); // Calls redirect helper which redirects input/output if necessary

    if (fd == -1) {
      fprintf(stderr, "Error opening file '%s'", cmd->file);
      exit(0);
    }

    switch (cmd->builtin) {
    case CD:
      status = builtin_cd(cmd->argv);
      break;
    case KILL:
      status = builtin_kill(cmd->argv);
      break;
    default:
      fprintf(stderr, "%s does not exist\n", cmd->argv[0]);
      break;
    }

    // Close file if one was opened.
    if (fd >= 0) {
      close(fd);
    }

    if (status < 0) {
      fprintf(stderr, "Error running builtin: %s\n", cmd->argv[0]);
      exit(0);
    }
  } else {
    if (cmd->bg) {
      insert_bg_cmd(child_pid, *cmd);
    } else {
      wait_pid(child_pid);
    }
    check_bg_cmds();
  }

  return status;
}

/**
 *Evaluates the given string. It first parses the command. If the parse command
 *returns -1, there was an error so nothing happens. If cmd.argv[0] == NULL,
 *the user did not pass in a command so nothing happens. If the command is not
 *a builtin, it is passed off to the run_system_command. Otherwise it is passed
 *off to run_builtin_command.
 */
int eval(char *cmdline) {
  struct command cmd;
  int ret;

  strcpy(cmd.cmd, cmdline);

  // Parses the command
  parse(&cmd);

  printf("2: %s\n", cmd.argv[0]);

  // If bg is -1 or the command is NULL, we return to get the next command
  if (cmd.bg == -1 || cmd.argv[0] == NULL) {
    ret = 1;
    check_bg_cmds();
  } else if (cmd.builtin ==
             (enum builtin_t)NONE) { // Runs the system command and returns

    printf("3: %s\n", cmd.argv[0]);
    run_system_command(cmd);
    ret = 1;
  } else { // Runs builtin command and returns it's return value
    ret = run_builtin_command(&cmd);
  }

  return ret;
}

int main(void) {
  char cmdline[MAX_LINE];
  int should_run = 1;
  char *fgets_r;
  int ferror_r;

  while (should_run) {
    printf("%s", PROMPT);
    fflush(stdout);

    // Gets input from stdin
    fgets_r = fgets(cmdline, MAX_LINE, stdin);
    ferror_r = ferror(stdin);

    printf("\033[0m");
    fflush(stdout);

    if (fgets_r == NULL && ferror_r) {
      fprintf(stderr, "fgets error");
    }

    if (feof(stdin)) {
      printf("\n");
      exit(0);
    }

    cmdline[strlen(cmdline) - 1] = '\0';

    should_run = eval(cmdline);
  }

  return 0;
}
