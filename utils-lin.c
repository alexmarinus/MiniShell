/**
 * Operating Systems 2013 - Assignment 2
 * Marinus Alexandru
 * Grupa 334CC
*/

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO execute cd */
	/*Schimbare director HOME*/
	if (!dir)
		return (chdir(getenv("HOME")) == 0);
	if (strcmp(dir->string, "~") == 0)
		return (chdir(getenv("HOME")) == 0);
	/*Schimbare alt director*/
	return (chdir(dir->string) == 0);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO execute exit/quit */
	free_parse_memory();
	return SHELL_EXIT;
}

/**
 * Setare variabila de mediu.
 */
static int assignEnvVar(const char *name, const char *value)
{
	return setenv(name, value, 1);
}

/**
 * Redirectare input.
 */
static int redirect_input(int filedes, const char *fileName)
{
	int fd = open(fileName, O_RDWR);

	if (fd < 0)
		return -1;
	return dup2(fd, filedes) == -1 ? -1:0;
}

/**
 * Redirectare iesire pentru stdout si stderr, in mod normal
sau append, in functie de boolean-ul append.
 */
static int redirect_output(int filedes, const char *fileName, bool append)
{
	int fd;

	if (!append)
		fd = open(fileName, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	else
		fd = open(fileName, O_WRONLY | O_APPEND | O_CREAT, 0644);
	/*In caz de eroare, intorc -1, altfel intorc 0.*/
	if (fd < 0)
		return -1;
	return dup2(fd, filedes) == -1 ? -1 : 0;
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL)
			return NULL;

		if (s->expand == true) {
			char *aux = substring;

			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL)
				substring = "";

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (s->expand == false)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false)
			free(substring);

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;

	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

/**
 * Determinarea daca trebuie iesirea standard trebuie
 * redirectata in mod append
 */
bool appendModeOut(simple_command_t *s)
{
	return ((s->io_flags & IO_OUT_APPEND) == IO_OUT_APPEND);
}

/**
 * Determinarea daca trebuie iesirea de eroare trebuie
 * redirectata in mod append
 */
bool appendModeErr(simple_command_t *s)
{
	return ((s->io_flags & IO_ERR_APPEND) == IO_ERR_APPEND);
}

/**
 * Determinarea daca o comanda s (diferita de NULL) este
de asignare a unei variabile de mediu
 */
bool isEnvVariableCommand(simple_command_t *s)
{
	return (s->verb->next_part != NULL
		&& strcmp(s->verb->next_part->string, "=") == 0);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int argCount, outputfd, rc, status;
	pid_t pid;
	bool appendOut, appendErr;

	/* TODO sanity checks */
	if (!s || !s->verb)
		return EXIT_FAILURE;

	/* TODO if builtin command, execute the command */
	if (strcmp(get_word(s->verb), "quit") == 0
		|| strcmp(get_word(s->verb), "exit") == 0) {
		rc = shell_exit();
		return rc;
	}

	if (strcmp(get_word(s->verb), "cd") == 0) {
		if (s->out) {
			outputfd = open(get_word(s->out),
				O_WRONLY | O_TRUNC | O_CREAT, 0600);
			if (outputfd < 0)
				return EXIT_FAILURE;
		}
		rc = shell_cd(s->params);
		return rc;
	}

	/* TODO if variable assignment, execute the assignment and return
	 * the exit status
	 */
	/*Primul parametru al functiei assignEnvVar este numele variabilei
	de mediu, iar al doilea valoarea ce se doreste a fi atribuita*/
	if (isEnvVariableCommand(s)) {
		if (s->verb->next_part->next_part->string) {
			rc = assignEnvVar(s->verb->string,
				s->verb->next_part->next_part->string);
			return rc;
		}
		return EXIT_FAILURE;
	}

	/* TODO if external command:
	 *   1. fork new process
	 *     2c. perform redirections in child
	 *     3c. load executable in child
	 *   2. wait for child
	 *   3. return exit status
	 */
	pid = fork();
	switch (pid) {
	case -1:
		return EXIT_FAILURE;
	case 0:
		/*Proces copil*/
		/*Redirectare doar input (operatorul <)*/
		if (s->in) {
			rc = redirect_input(STDIN_FILENO,
				get_word(s->in));
			DIE(rc == -1, "parse_simple redirect_input STDIN");
		}
		/*Redirectare doar output*/
		if (s->out && !s->err) {
			/*appendOut = true => operatorul >>
			appendOut = false => operatorul > */
			appendOut = appendModeOut(s);
			rc = redirect_output(STDOUT_FILENO,
				get_word(s->out), appendOut);
			DIE(rc == -1, "parse_simple redirect_output STDOUT");
		}
		/*Redirectare doar error*/
		if (s->err && !s->out) {
			/*appendErr = true => operatorul 2>>
			appendErr = false => operatorul 2> */
			appendErr = appendModeErr(s);
			rc = redirect_output(STDERR_FILENO,
				get_word(s->err), appendErr);
			DIE(rc == -1, "parse_simple redirect_output STDERR");
		}
		/*Redirectare doar output si error (&>)*/
		if (s->out && s->err) {
			rc = redirect_output(STDERR_FILENO,
				get_word(s->err), false);
			DIE(rc == -1, "parse_simple redirect_output STDERR");
			rc = redirect_output(STDOUT_FILENO,
				get_word(s->out), true);
			DIE(rc == -1, "parse_simple redirect_output STDOUT");
		}
		/*Executie comanda*/
		rc = execvp(get_word(s->verb),
				get_argv(s, &argCount));
		if (rc == -1) {
			printf("Execution failed for \'%s\'\n",
				get_word(s->verb));
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
		break;
	default:
		/*Procesul parinte isi asteapta copilul*/
		rc = waitpid(pid, &status, 0);
		/* TODO replace with actual exit status */
		return (rc == -1) ? rc:status;
	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO execute cmd1 and cmd2 simultaneously */
	pid_t pid1, pid2;
	int rc, status;

	/*Creez un proces copil care executa prima comanda*/
	pid1 = fork();
	switch (pid1) {
	case -1:
		exit(EXIT_FAILURE);
	case 0:
		rc = parse_command(cmd1, level + 1, father);
		(rc < 0) ? exit(EXIT_FAILURE) : exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}

	/*Creez un proces copil care executa a doua comanda*/
	pid2 = fork();
	switch (pid2) {
	case -1:
		exit(EXIT_FAILURE);
	case 0:
		rc = parse_command(cmd2, level + 1, father);
		(rc < 0) ? exit(EXIT_FAILURE) : exit(EXIT_SUCCESS);
		break;
	default:
		break;
	}

	/*Procesul parinte isi asteapta ambii copii*/
	rc = waitpid(pid1, &status, 0);
	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);
	rc = waitpid(pid2, &status, 0);
	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);

	return true; /* TODO replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid;
	int rc, status;
	bool wait_ret;
	int filedes[2];

	rc = pipe(filedes);
	if (rc == -1)
		return false;

	pid = fork();
	switch (pid) {
	case -1:
		return EXIT_FAILURE;
	case 0:
		/*Procesul copil inchide capul de citire*/
		rc = close(filedes[0]);
		DIE(rc < 0, "do_on_pipe close");
		/*Redirecteaza rezultatul cmd1*/
		rc = dup2(filedes[1], STDOUT_FILENO);
		DIE(rc < 0, "do_on_pipe dup2");
		/*Inchide capul de citire*/
		rc = close(filedes[1]);
		DIE(rc < 0, "do_on_pipe close");
		/*Excuta comanda cmd1*/
		rc = parse_command(cmd1, level + 1, father);
		exit(rc);
	default:
		break;
	}
	/*Procesul parinte inchide capul de citire*/
	rc = close(filedes[1]);
	DIE(rc < 0, "do_on_pipe close");
	/*Citeste comanda cmd2 din pipe*/
	rc = dup2(filedes[0], STDIN_FILENO);
	DIE(rc < 0, "do_on_pipe dup2");
	/*Inchide capul de citire*/
	rc = close(filedes[0]);
	DIE(rc < 0, "do_on_pipe close");
	/*Executa comanda cmd2*/
	rc = parse_command(cmd2, level + 1, father);
	/*Asteapta terminarea procesului copil*/
	wait_ret = waitpid(pid, &status, 0);
	DIE(wait_ret < 0, "do_on_pipe waitpid");
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return (rc < 0);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int rc;

	/* TODO sanity checks */
	if (!c)
		return -1;

	if (c->op == OP_NONE) {
		/* TODO execute a simple command */
		rc = parse_simple(c->scmd, level, father);
		if (rc == SHELL_EXIT)
			free_parse_memory();
		return rc;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO execute the commands one after the other */
		rc = parse_command(c->cmd1, level + 1, c);
		rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO execute the commands simultaneously */
		rc = do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO execute the second command only if the first one
		 * returns non zero
		 */
		rc = parse_command(c->cmd1, level + 1, c);
		if (rc != 0)
			rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO execute the second command only if the first one
		 * returns zero
		 */
		rc = parse_command(c->cmd1, level + 1, c);
		if (rc == 0)
			rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* TODO redirect the output of the first command to the
		 * input of the second
		 */
		rc = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		assert(false);
		break;
	}
	return rc; /* TODO replace with actual exit code of command */
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL)
			break;

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL)
			break;

		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}
