#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h> 
#include <signal.h>
const char *sysname = "shellish";

enum return_codes {
  SUCCESS = 0,
  EXIT = 1,
  UNKNOWN = 2,
};

struct command_t {
  char *name;
  bool background;
  bool auto_complete;
  int arg_count;
  char **args;
  char *redirects[3];     // in/out redirection
  struct command_t *next; // for piping
};

/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
  int i = 0;
  printf("Command: <%s>\n", command->name);
  printf("\tIs Background: %s\n", command->background ? "yes" : "no");
  printf("\tNeeds Auto-complete: %s\n", command->auto_complete ? "yes" : "no");
  printf("\tRedirects:\n");
  for (i = 0; i < 3; i++)
    printf("\t\t%d: %s\n", i,
           command->redirects[i] ? command->redirects[i] : "N/A");
  printf("\tArguments (%d):\n", command->arg_count);
  for (i = 0; i < command->arg_count; ++i)
    printf("\t\tArg %d: %s\n", i, command->args[i]);
  if (command->next) {
    printf("\tPiped to:\n");
    print_command(command->next);
  }
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
  if (command->arg_count) {
    for (int i = 0; i < command->arg_count; ++i)
      free(command->args[i]);
    free(command->args);
  }
  for (int i = 0; i < 3; ++i)
    if (command->redirects[i])
      free(command->redirects[i]);
  if (command->next) {
    free_command(command->next);
    command->next = NULL;
  }
  free(command->name);
  free(command);
  return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
  char cwd[1024], hostname[1024];
  gethostname(hostname, sizeof(hostname));
  getcwd(cwd, sizeof(cwd));
  printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
  return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
  const char *splitters = " \t"; // split at whitespace
  int index, len;
  len = strlen(buf);
  while (len > 0 && strchr(splitters, buf[0]) != NULL) // trim left whitespace
  {
    buf++;
    len--;
  }
  while (len > 0 && strchr(splitters, buf[len - 1]) != NULL)
    buf[--len] = 0; // trim right whitespace

  if (len > 0 && buf[len - 1] == '?') // auto-complete
    command->auto_complete = true;
  if (len > 0 && buf[len - 1] == '&') // background
    command->background = true;

  char *pch = strtok(buf, splitters);
  if (pch == NULL) {
    command->name = (char *)malloc(1);
    command->name[0] = 0;
  } else {
    command->name = (char *)malloc(strlen(pch) + 1);
    strcpy(command->name, pch);
  }

  command->args = (char **)malloc(sizeof(char *));

  int redirect_index;
  int arg_index = 0;
  char temp_buf[1024], *arg;
  while (1) {
    // tokenize input on splitters
    pch = strtok(NULL, splitters);
    if (!pch)
      break;
    arg = temp_buf;
    strcpy(arg, pch);
    len = strlen(arg);

    if (len == 0)
      continue; // empty arg, go for next
    while (len > 0 && strchr(splitters, arg[0]) != NULL) // trim left whitespace
    {
      arg++;
      len--;
    }
    while (len > 0 && strchr(splitters, arg[len - 1]) != NULL)
      arg[--len] = 0; // trim right whitespace
    if (len == 0)
      continue; // empty arg, go for next

    // piping to another command
    if (strcmp(arg, "|") == 0) {
      struct command_t *c =
          (struct command_t *)malloc(sizeof(struct command_t));
      int l = strlen(pch);
      pch[l] = splitters[0]; // restore strtok termination
      index = 1;
      while (pch[index] == ' ' || pch[index] == '\t')
        index++; // skip whitespaces

      parse_command(pch + index, c);
      pch[l] = 0; // put back strtok termination
      command->next = c;
      continue;
    }

    // background process
    if (strcmp(arg, "&") == 0)
      continue; // handled before

    // handle input redirection
    redirect_index = -1;
    if (arg[0] == '<')
      redirect_index = 0;
    if (arg[0] == '>') {
      if (len > 1 && arg[1] == '>') {
        redirect_index = 2;
        arg++;
        len--;
      } else
        redirect_index = 1;
    }
    if (redirect_index != -1) {
      command->redirects[redirect_index] = (char *)malloc(len);
      strcpy(command->redirects[redirect_index], arg + 1);
      continue;
    }

    // normal arguments
    if (len > 2 &&
        ((arg[0] == '"' && arg[len - 1] == '"') ||
         (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
    {
      arg[--len] = 0;
      arg++;
    }
    command->args =
        (char **)realloc(command->args, sizeof(char *) * (arg_index + 1));
    command->args[arg_index] = (char *)malloc(len + 1);
    strcpy(command->args[arg_index++], arg);
  }
  command->arg_count = arg_index;

  // increase args size by 2
  command->args = (char **)realloc(command->args,
                                   sizeof(char *) * (command->arg_count += 2));

  // shift everything forward by 1
  for (int i = command->arg_count - 2; i > 0; --i)
    command->args[i] = command->args[i - 1];

  // set args[0] as a copy of name
  command->args[0] = strdup(command->name);
  // set args[arg_count-1] (last) to NULL
  command->args[command->arg_count - 1] = NULL;

  return 0;
}

void prompt_backspace() {
  putchar(8);   // go back 1
  putchar(' '); // write empty over
  putchar(8);   // go back 1 again
}

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
  int index = 0;
  char c;
  char buf[4096];
  static char oldbuf[4096];

  // tcgetattr gets the parameters of the current terminal
  // STDIN_FILENO will tell tcgetattr that it should write the settings
  // of stdin to oldt
  static struct termios backup_termios, new_termios;
  tcgetattr(STDIN_FILENO, &backup_termios);
  new_termios = backup_termios;
  // ICANON normally takes care that one line at a time will be processed
  // that means it will return if it sees a "\n" or an EOF or an EOL
  new_termios.c_lflag &=
      ~(ICANON |
        ECHO); // Also disable automatic echo. We manually echo each char.
  // Those new settings will be set to STDIN
  // TCSANOW tells tcsetattr to change attributes immediately.
  tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

  show_prompt();
  buf[0] = 0;
  while (1) {
    c = getchar();
    // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

    if (c == 9) // handle tab
    {
      buf[index++] = '?'; // autocomplete
      break;
    }

    if (c == 127) // handle backspace
    {
      if (index > 0) {
        prompt_backspace();
        index--;
      }
      continue;
    }

    if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
      continue;
    }

    if (c == 65) // up arrow
    {
      while (index > 0) {
        prompt_backspace();
        index--;
      }

      char tmpbuf[4096];
      printf("%s", oldbuf);
      strcpy(tmpbuf, buf);
      strcpy(buf, oldbuf);
      strcpy(oldbuf, tmpbuf);
      index += strlen(buf);
      continue;
    }

    putchar(c); // echo the character
    buf[index++] = c;
    if (index >= sizeof(buf) - 1)
      break;
    if (c == '\n') // enter key
      break;
    if (c == 4) // Ctrl+D
      return EXIT;
  }
  if (index > 0 && buf[index - 1] == '\n') // trim newline from the end
    index--;
  buf[index++] = '\0'; // null terminate string

  strcpy(oldbuf, buf);

  parse_command(buf, command);

  // print_command(command); // DEBUG: uncomment for debugging

  // restore the old settings
  tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
  return SUCCESS;
}
char *path_resolver(char *command) {
  //command has a slash we return its copy
 
       	if (strchr(command, '/')) {
   
	  return strdup(command);
  }

  // getting path
  char *enviroment_path = getenv("PATH");
  if (!enviroment_path){
	  return strdup(command);
	  }

  // copy path
  char *copyp = strdup(enviroment_path);

  char *directory = strtok(copyp, ":");

  char buffybuffer[1024];

  // looping for path
  while (directory != NULL) {
    snprintf(buffybuffer, sizeof(buffybuffer), "%s/%s", directory, command);

    // checking for execution
    if (access(buffybuffer, X_OK) == 0) {
     
	    free(copyp);
    
	    return strdup(buffybuffer);
    }
    directory = strtok(NULL, ":"); //next directory
  }

  free(copyp);
 
  return strdup(command); //back to original command
}



void func_cut(char **currinput) {
   
       	char curr_delimiter = '\t'; //def tab
   
       	char *stringfield = NULL;

    //parsing the input for d and f
    for (int x = 1; currinput[x] != NULL; x++) {
       
	    if (strncmp(currinput[x], "-d", 2) == 0) {// delimiter 
           
		    if (strlen(currinput[x]) > 2) {
               
			    curr_delimiter  = currinput[x][2]; //handling input for -d:
            }
	
		    else if (currinput[x+1] != NULL) {
               
		 	     curr_delimiter  = currinput[x+1][0]; //handling input for -d ":"
                
			    x++;
            }
        }
       
    	    else if (strncmp(currinput[x], "-f", 2) == 0) { //fields 
           
	       	if (strlen(currinput[x]) > 2) {
               
		       	stringfield = currinput[x] + 2; //handling input for -f1,6
            }
	       	else if (currinput[x+1] != NULL) {
               
		       
		       	stringfield = currinput[x+1];   //handling input for -f 1,6
              
		      	 x++;
            }
        }
    }

    if (!stringfield) {
       
	    fprintf(stderr, "f field dont specified\n");
       
	    return;
    }

    //parsing comma separated field indexes
    int currfield[100];
   
    int cnt = 0;
   
    char *stringf = strdup(stringfield);
   
    char *currtoken = strtok(stringf, ",");
    
    while (currtoken != NULL && cnt < 100) {
       
	     currfield[cnt++] = atoi(currtoken);
       
	    currtoken = strtok(NULL, ",");
    }
   
    free(stringf);

    //processing stdin row by row 
    char thisrow[4096];
   
    while (fgets(thisrow, sizeof(thisrow), stdin)) {
       
	 thisrow[strcspn(thisrow, "\n")] = 0; //cutting trailing newline

        
         char *fieldparsed[1000]; //splitting string by delimiter
       
       	int countparsed = 1;
        
       	fieldparsed[countparsed] = thisrow;
        
         int length = strlen(thisrow);
       
       	for (int x = 0; x < length; x++) {
           
	      	if (thisrow[x] == curr_delimiter ) {
              
		       	thisrow[x] = '\0'; //nullterminating at delimiter
                
		         countparsed++;
               
	 	       	fieldparsed[countparsed] = &thisrow[x + 1];
            }
        }

        //printing in fields in order
        int beginning = 1;
       
       	for (int i = 0; i < cnt; i++) {
           
	       	int indexf = currfield[i];
            
            //if field exist in curr line
            if (indexf > 0 && indexf <= countparsed) {
               
		    if (!beginning){
			   
			    printf("%c", curr_delimiter);
               }
		    printf("%s", fieldparsed[indexf]);
               
		    beginning = 0;
            }
        }
        printf("\n");
    }
}



void chat_func(char **inputs) {
   
      	if (inputs[1] == NULL || inputs[2] == NULL) {
       
	       	printf("chatroom <roomname> <username>\n");
       		 return;
    }

    char *room = inputs[1];
   
    char *user = inputs[2];
   
    char directory_room[256];
   
    char pipe_user[512];

    //room folder creation
   
    snprintf(directory_room, sizeof(directory_room), "/tmp/chatroom-%s", room);
   
    mkdir(directory_room, 0777); 

    //creating user pipe
   
    snprintf(pipe_user, sizeof(pipe_user), "%s/%s", directory_room, user);
   
    mkfifo(pipe_user, 0666); 

    printf("entered room  %s\n", room);

    pid_t pid_rc = fork();
  
    if (pid_rc == 0) {
       
	 //continously read receiver process
        
        int descriptor = open(pipe_user, O_RDWR); 
       
       	char bufferybuff[1024];
       
       	while (1) {
            
		int x = read(descriptor, bufferybuff, sizeof(bufferybuff) - 1);
           
	       	if (x > 0) {
               
		       	bufferybuff[x] = '\0';
               
		       	//clearing current line
               		 printf("\r");
		       
		       	printf("                                                                                                                           ");
               	 
		         printf("\r[%s] %s\n", room, bufferybuff);
		       
			//prompt printing
		       	printf("[%s] %s > ", room, user);
		       	fflush(stdout);
            }
        }
        exit(0);
    }
   
    else {
        //process for sender
       
 	 char curr_message[1024];
       
	 char message_new[2048];
        
        while (1) {
           
	       	printf("[%s] %s > ", room, user);
           
	       	fflush(stdout);
            
            if (fgets(curr_message, sizeof(curr_message), stdin) == NULL){
		    break;
	    }
	    //trimming newline
            curr_message[strcspn(curr_message, "\n")] = '\0';
            
            if (strcmp(curr_message, "\\quit") == 0){
		    break; //for exiting
			   }
            if (strlen(curr_message) == 0){
		    continue; }

            snprintf(message_new, sizeof(message_new), "%s: %s", user, curr_message);

            // Iterate over all named pipes within the room's folder 
           
	    DIR *thisdir = opendir(directory_room);
           
	    if (thisdir) {
               
		    struct dirent *curr_dir;
               
		    while ((curr_dir = readdir(thisdir)) != NULL) {
                   
			    //dont write to . and .. and own pipe
                            if (strcmp((*curr_dir).d_name, ".") != 0 && strcmp((*curr_dir).d_name, "..") != 0 &&  strcmp((*curr_dir).d_name, user) != 0) {
                        
                       		 //writing to all other pipes
                       		 pid_t pid_sd = fork();
                       
			     if (pid_sd == 0) {
                                 
				     char pipe_trg[512];
                                  
				     snprintf(pipe_trg, sizeof(pipe_trg), "%s/%s", directory_room, curr_dir->d_name);
                            
                           	 //non blocking for operating under crash
                            	
				     int descout = open(pipe_trg, O_WRONLY | O_NONBLOCK);
                           
				     if (descout >= 0) {
                               
					   write(descout, message_new, strlen(message_new));
                               		    close(descout);
                            }
                            exit(0);
                        }
			     else {
                            
				     waitpid(pid_sd, NULL, 0);
                        }
                    }
                }
                closedir(thisdir);
            }
        }
        
        //quitting
        kill(pid_rc, SIGTERM);
       
       	waitpid(pid_rc, NULL, 0);
       
       	unlink(pipe_user);
    }
}



void reminder(char **inputs) {
   
       	if (inputs[1] == NULL || inputs[2] == NULL) {
       
	       	printf("remind <seconds> <message...>\n");
       
	       	return;
    }

    int time = atoi(inputs[1]);
   
    if (time <= 0) {
        printf("seconds should be positive\n");
        return;
    }

    //reconstructing the message
    char this_message[1024] = "";
   
    for (int x = 2; inputs[x] != NULL; x++) {
        
	    strncat(this_message, inputs[x], sizeof(this_message) - strlen(this_message) - 1);
       
	    if (inputs[x+1] != NULL) {
           
		    strncat(this_message, " ", sizeof(this_message) - strlen(this_message) - 1);
        }
    }

    // Fork a background process for the timer
   
    pid_t reminder_pid = fork();
   
    if (reminder_pid < 0) {
        perror("fork failed");
        return;
    }

    if (reminder_pid == 0) {
      
        sleep(time);
        
        // \a activates bell \n \r moves to new line without interfering the users current prompt 
        printf("\n\r\a[REMINDER] %s\n", this_message);
        
        exit(0);

    }
    else {
        //parent: print reminder and return
        printf("[Reminder set for %d seconds from now (PID: %d)]\n", time, reminder_pid);
    }
}



int process_command(struct command_t *command) {
  int r;
  if (strcmp(command->name, "") == 0)
    return SUCCESS;

  if (strcmp(command->name, "exit") == 0)
    return EXIT;

  if (strcmp(command->name, "cd") == 0) {
    if (command->arg_count > 0) {
      r = chdir(command->args[1]);
      if (r == -1)
        printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
      return SUCCESS;
    }
  }

  
  if (command->next) {
   
	  int fdpiping[2];
  
	  if (pipe(fdpiping) < 0) {
     
		  perror("fail to pipe");
    
		  return SUCCESS;
    }

    pid_t newpid = fork();
    if (newpid == 0) {
      // pipe's left side
      dup2(fdpiping[1], STDOUT_FILENO);
     
      close(fdpiping[0]);
     
      close(fdpiping[1]);
      
      
      command->next = NULL; //severing the chain
      process_command(command); //executing left side recursive
      exit(SUCCESS);
    }

  
    pid_t pidnew2 = fork();
  
    if (pidnew2 == 0) {
      //reading right side of pipe
     
	    dup2(fdpiping[0], STDIN_FILENO);
     
	    close(fdpiping[0]);
     
	    close(fdpiping[1]);
      
     
	    process_command(command->next); //executing rest of chain
     
	    exit(SUCCESS);
    }

    //parent close pipe
    close(fdpiping[0]);
   
    close(fdpiping[1]);

    if (command->background) {
     
	    printf("[%d] work in background", newpid);
     
	    printf("[%d] work in background", pidnew2);
    }
    else {
     	
	    waitpid(newpid, NULL, 0);
     	
	    waitpid(pidnew2, NULL, 0);
    }
    return SUCCESS;
  }


  pid_t pid = fork();
  if (pid == 0) // child
  {
    /// This shows how to do exec with environ (but is not available on MacOs)
    // extern char** environ; // environment variables
    // execvpe(command->name, command->args, environ); // exec+args+path+environ

    /// This shows how to do exec with auto-path resolve
    // add a NULL argument to the end of args, and the name to the beginning
    // as required by exec

    // TODO: do your own exec with path resolving using execv()
    // do so by replacing the execvp call below
    if (command->redirects[0]) {
     //for input red'rect'on
	 int inputfd = open(command->redirects[0], O_RDONLY);
     
      if (inputfd < 0) {
       
	      perror("Input file cannot open");
       
	      exit(EXIT_FAILURE);
      }
     
      dup2(inputfd, STDIN_FILENO); 
      close(inputfd);
    }
    if (command->redirects[1]) {
     // for output direction
	 int outputfd = open(command->redirects[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
     
      if (outputfd < 0) {
       
 	 perror("output file cannot opened");
         exit(EXIT_FAILURE);
      }
     
      dup2(outputfd, STDOUT_FILENO); 
     
      close(outputfd);
    }
   if (command->redirects[2]) {
	//for appending
	   int appendingfd = open(command->redirects[2], O_WRONLY | O_CREAT | O_APPEND, 0666);
     	
	   if (appendingfd < 0) {
       		
		 perror("append file cant open");
       		 exit(EXIT_FAILURE);
      }
      dup2(appendingfd, STDOUT_FILENO);
      close(appendingfd);
    }


    if (strcmp(command->name, "cut") == 0) {
     
	    func_cut(command->args);
    
	    exit(SUCCESS);
    }

    if (strcmp(command->name, "chatroom") == 0) {
     
	    chat_func(command->args);
     
	    exit(SUCCESS);
    }

    if (strcmp(command->name, "remind") == 0) {
   
	    reminder(command->args);
   
	    return SUCCESS;
  }

    char *currpath = path_resolver(command->name);
    execv(currpath, command->args);

    
    printf("-%s: %s: command not found\n", sysname, command->name);
    exit(127);
  } else {
    // TODO: implement background processes here
    if (command->background) {
      
      printf("[%d] started in background\n", pid);
    }
    else {
      // waiting for child
      waitpid(pid, NULL, 0); 
    }
    return SUCCESS;
  }
}

int main() {
  while (1) {
    struct command_t *command =
        (struct command_t *)malloc(sizeof(struct command_t));
    memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

    int code;
    code = prompt(command);
    if (code == EXIT)
      break;

    code = process_command(command);
    if (code == EXIT)
      break;

    free_command(command);
  }

  printf("\n");
  return 0;
}
