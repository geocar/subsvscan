#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

extern int trylock(int fd);


static char DOTS400[401];

static void alrm_handler(int n)
{
	signal(SIGALRM, alrm_handler);
}

static char *str2(const char *a, const char *b)
{
	char *q, *p;
	p = q = malloc(strlen(a) + strlen(b)+2);
	if (!q) return q;
	while (*a) *p++ = *a++;
	while (*b) *p++ = *b++;
	*p = '\0';
	return q;
}

static int cwrite(int fd, void *buf, size_t len)
{
	int r, x;
	for (x = 0; x < len; x++) {
		do {
			r = write(fd, (void *)(buf+x), len-x);
		} while (r == -1 && errno == EINTR);
		if (r < 1) return 0;
		x += r;
	}
	return 1;
}


int main(int argc, char *argv[])
{
	char *svexec[] = { "svscan", ".", 0 };
	char *rpexec[] = { "readproctitle", "service", "errors:",
		DOTS400, 0 };
	struct dirent *d;
	DIR *dir;
	pid_t svpid, rppid, fxpid, p;
	char buf[PATH_MAX];
	int svrppipe[2];
	int fxpipe[2];
	int i, r, fd;
	int dieflag;
	time_t lastrp_fork;
	char *qp;

	signal(SIGCHLD, SIG_DFL);
	signal(SIGALRM, alrm_handler);
	signal(SIGPIPE, exit);
	for (i = 0; i < 400; i++) DOTS400[i] = '.';
	DOTS400[400] = 0;

	if (argc != 2) {
#define M "Usage: subsvscan dir\n"
		cwrite(2,M,sizeof(M)-1);
#undef M
		exit(0);
	}
	if (chdir(argv[1]) == -1) exit(255);

	dir = opendir(".");
	if (!dir) exit(251);

	close(open(".lock", O_RDWR|O_CREAT, 0600));
	if ((fd = open(".lock", O_RDWR)) == -1) exit(255);
	if (trylock(fd) != 1) exit(0);
	for (i = 0; i < 32; i++) {
		if (i == fd) continue;
		(void)close(i);
	}
	if (pipe(svrppipe) == -1) exit(254);

	switch ((svpid = fork())) {
	case -1: exit(253);
	case 0:
		closedir(dir);
		(void)close(fd);
		(void)close(svrppipe[0]);
		fd = svrppipe[1];
		if (fd != 0) dup(fd);
		if (fd != 1) dup(fd);
		if (fd != 2) dup(fd);
		(void)close(0);
		open("/dev/null",O_RDONLY);
		fcntl(0, F_SETFD, 0);
		fcntl(1, F_SETFD, 0);
		fcntl(2, F_SETFD, 0);
		(void)setsid();
		execvp(*svexec, svexec);
		exit(0);
	};
	(void)close(svrppipe[1]);
	fxpid = rppid = -1;
	fxpipe[0] = fxpipe[1] = -1;

	dieflag = 0;
	lastrp_fork = 0;
	for (;;) {
		if (fxpid == -1) {
			(void)close(fxpipe[1]);
			if (pipe(fxpipe) == -1) exit(253);
			switch ((fxpid = fork())) {
			case -1: exit(253);
			case 0:
				(void)close(fd);
				(void)close(svrppipe[0]);
				(void)close(fxpipe[1]);
				for (;;) {
					do {
						r = read(fxpipe[0], buf, 1);
					} while (r == -1 && errno == EINTR);
					if (r == 1) {
						dieflag = 1;
					} else {
						break;
					}
				}
				if (dieflag) {
					kill(svpid, SIGKILL);
				}
				while ((d = readdir(dir))) {
					if (d->d_name[0] == '.') continue;
					qp = str2(d->d_name, "/supervise/control");
					if (!qp) continue;
					fd = open(qp, O_WRONLY);
					(void)free(qp);
					if (fd == -1) continue;
					cwrite(fd, "dx", 2);
					(void)close(fd);
				}
				closedir(dir);
				if (dieflag) {
					kill(svpid, SIGKILL);
				}

				exit(0);
			default:
				close(fxpipe[0]);
				fxpipe[0] = -1;
				break;
			};
		}
		if (rppid == -1 && time(0) - lastrp_fork >= 5) {
			time(&lastrp_fork);
			if ((rppid = fork()) == 0) {
				close(fd);
				closedir(dir);
				close(fxpipe[1]);
				if (svrppipe[0] != 0) {
					(void)close(0);
					if (dup(svrppipe[0]) != 0) exit(1);
					close(svrppipe[0]);
				}
				close(1);
				close(2);
				fd = open("/dev/null",O_WRONLY);
				if (fd != 1) dup(fd);
				if (fd != 2) dup(fd);
				open("/dev/null",O_WRONLY);
				fcntl(0, F_SETFD, 0);
				fcntl(1, F_SETFD, 0);
				fcntl(2, F_SETFD, 0);
				execvp(*rpexec, rpexec);
				exit(0);
			}
		}
		if (rppid == -1) alarm(5);
		p = wait(&i);
		alarm(0);
		if (p == -1 && errno != EINTR) {
			cwrite(fxpipe[1], "x", 1);
			(void)close(fxpipe[1]);
			fxpipe[1] = -1;
			break;
		}
		if (p == svpid) {
			cwrite(fxpipe[1], "x", 1);
			(void)close(fxpipe[1]);
			fxpipe[1] = -1;
		}
		if (rppid != -1 && p == rppid) rppid = -1;
		if (p == fxpid) {
			fxpid = -1;
			if (WIFEXITED(i) && WEXITSTATUS(i) == 0) {
				break;
			}
		}
	}
	exit(0);
}
