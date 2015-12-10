#ifdef __FreeBSD__
#include <sys/param.h>
#endif

#include <stdio.h>
#include <time.h>
#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#undef st_atime
#undef st_mtime
#undef st_ctime
#include <dirent.h>
#include <lkl.h>
#include <lkl_host.h>

static const char doc_cptofs[] = "Copy files to a filesystem image";
static const char doc_cpfromfs[] = "Copy files from a filesystem image";
static const char args_doc_cptofs[] = "-t fstype -i fsimage path fs_path";
static const char args_doc_cpfromfs[] = "-t fstype -i fsimage fs_path path";

static struct argp_option options[] = {
	{"enable-printk", 'p', 0, 0, "show Linux printks"},
	{"filesystem-type", 't', "string", 0,
	 "select filesystem type - mandatory"},
	{"filesystem-image", 'i', "string", 0,
	 "path to the filesystem image - mandatory"},
	{"selinux", 's', "string", 0, "selinux attributes for destination"},
	{0},
};

static struct cl_args {
	int printk;
	const char *fsimg_type;
	const char *fsimg_path;
	const char *src_path;
	const char *dst_path;
	const char *selinux;
} cla;

static int cptofs;

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cl_args *cla = state->input;

	switch (key) {
	case 'p':
		cla->printk = 1;
		break;
	case 't':
		cla->fsimg_type = arg;
		break;
	case 'i':
		cla->fsimg_path = arg;
		break;
	case 's':
		cla->selinux = arg;
		break;
	case ARGP_KEY_ARG:
		if (!cla->src_path) {
			cla->src_path = arg;
		} else if (!cla->dst_path) {
			cla->dst_path = arg;
		} else {
			argp_usage(state);
			return -1;
		}
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 2 || !cla->fsimg_type || !cla->fsimg_path)
			argp_usage(state);
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp_cptofs = {
	.options = options,
	.parser = parse_opt,
	.args_doc = args_doc_cptofs,
	.doc = doc_cptofs,
};

static struct argp argp_cpfromfs = {
	.options = options,
	.parser = parse_opt,
	.args_doc = args_doc_cpfromfs,
	.doc = doc_cpfromfs,
};

static int searchdir(const char *fs_path, const char *path, const char *match);

static int open_src(const char *path)
{
	int fd;

	if (cptofs)
		fd = open(path, O_RDONLY, 0);
	else
		fd = lkl_sys_open(path, LKL_O_RDONLY, 0);

	if (fd < 0)
		fprintf(stderr, "unable to open file %s for reading: %s\n",
			path, cptofs ? strerror(errno) : lkl_strerror(fd));

	return fd;
}

static int open_dst(const char *path, int mode)
{
	int fd;

	if (cptofs)
		fd = lkl_sys_open(path, LKL_O_RDWR | LKL_O_TRUNC | LKL_O_CREAT,
				  mode);
	else
		fd = open(path, O_RDWR | O_TRUNC | O_CREAT, mode);

	if (fd < 0)
		fprintf(stderr, "unable to open file %s for writing: %s\n",
			path, cptofs ? lkl_strerror(fd) : strerror(errno));

	if (cla.selinux && cptofs) {
		int ret = lkl_sys_fsetxattr(fd, "security.selinux", cla.selinux,
					    strlen(cla.selinux), 0);
		if (ret)
			fprintf(stderr, "unable to set selinux attribute on %s: %s\n",
				path, lkl_strerror(ret));
	}

	return fd;
}

static int read_src(int fd, char *buf, int len)
{
	int ret;

	if (cptofs)
		ret = read(fd, buf, len);
	else
		ret = lkl_sys_read(fd, buf, len);

	if (ret < 0)
		fprintf(stderr, "error reading file: %s\n",
			cptofs ? strerror(errno) : lkl_strerror(ret));

	return ret;
}

static int write_dst(int fd, char *buf, int len)
{
	int ret;

	if (cptofs)
		ret = lkl_sys_write(fd, buf, len);
	else
		ret = write(fd, buf, len);

	if (ret < 0)
		fprintf(stderr, "error writing file: %s\n",
			cptofs ? lkl_strerror(ret) : strerror(errno));

	return ret;
}

static void close_src(int fd)
{
	if (cptofs)
		close(fd);
	else
		lkl_sys_close(fd);
}

static void close_dst(int fd)
{
	if (cptofs)
		lkl_sys_close(fd);
	else
		close(fd);
}

static int copy_file(const char *src, const char *dst, int mode)
{
	long len, to_write, wrote;
	char buf[4096], *ptr;
	int ret = 0;
	int fd_src, fd_dst;

	fd_src = open_src(src);
	if (fd_src < 0)
		return fd_src;

	fd_dst = open_dst(dst, mode);
	if (fd_dst < 0)
		return fd_dst;

	do {
		len = read_src(fd_src, buf, sizeof(buf));

		if (len > 0) {
			ptr = buf;
			to_write = len;
			do {
				wrote = write_dst(fd_dst, ptr, to_write);

				if (wrote < 0) {
					ret = wrote;
					goto out;
				}

				to_write -= wrote;
				ptr += len;

			} while (to_write > 0);
		}

		if (len < 0)
			ret = len;

	} while (len > 0);

out:
	close_src(fd_src);
	close_dst(fd_dst);

	return ret;
}

static int stat_src(const char *path, int *type, int *mode)
{
	struct stat stat;
	struct lkl_stat lkl_stat;
	int ret;

	if (cptofs) {
		ret = lstat(path, &stat);
		*type = stat.st_mode & S_IFMT;
		*mode = stat.st_mode & ~S_IFMT;
	} else {
		ret = lkl_sys_lstat(path, &lkl_stat);
		*type = lkl_stat.st_mode & S_IFMT;
		*mode = lkl_stat.st_mode & ~S_IFMT;
	}

	if (ret)
		fprintf(stderr, "fsimg lstat(%s) error: %s\n",
			path, cptofs ? strerror(errno) : lkl_strerror(ret));

	return ret;
}

static int mkdir_dst(const char *path, int mode)
{
	int ret;

	if (cptofs) {
		ret = lkl_sys_mkdir(path, mode);
		if (ret == -LKL_EEXIST)
			ret = 0;
	} else {
		ret = mkdir(path, mode);
		if (ret < 0 && errno == EEXIST)
			ret = 0;
	}

	if (ret)
		fprintf(stderr, "unable to create directory %s: %s\n",
			path, cptofs ? strerror(errno) : lkl_strerror(ret));

	return ret;
}

static int do_entry(const char *_src, const char *_dst, const char *name)
{
	char src[PATH_MAX], dst[PATH_MAX];
	int type, mode;
	int ret;

	snprintf(src, sizeof(src), "%s/%s", _src, name);
	snprintf(dst, sizeof(dst), "%s/%s", _dst, name);

	ret = stat_src(src, &type, &mode);

	switch (type) {
	case S_IFREG:
	{
		ret = copy_file(src, dst, mode);
		break;
	}
	case S_IFDIR:
		ret = mkdir_dst(dst, mode);
		if (ret)
			break;
		ret = searchdir(src, dst, NULL);
		break;
	case S_IFLNK:
	case S_IFSOCK:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
	default:
		printf("skipping %s: unsupported entry type %d\n", src, type);
	}

	if (ret)
		printf("error processing entry %s, aborting\n", src);

	return ret;
}

static DIR *open_dir(const char *path)
{
	DIR *dir;
	int err;

	if (cptofs)
		dir = opendir(path);
	else
		dir = (DIR *)lkl_opendir(path, &err);

	if (!dir)
		fprintf(stderr, "unable to open directory %s: %s\n",
			path, cptofs ? strerror(errno) : lkl_strerror(err));
	return dir;
}

static const char *read_dir(DIR *dir, const char *path)
{
	struct lkl_dir *lkl_dir = (struct lkl_dir *)dir;
	const char *name = NULL;
	const char *err = NULL;

	if (cptofs) {
		struct dirent *de = readdir(dir);

		if (de)
			name = de->d_name;
	} else {
		struct lkl_linux_dirent64 *de = lkl_readdir(lkl_dir);

		if (de)
			name = de->d_name;
	}

	if (!name) {
		if (cptofs) {
			if (errno)
				err = strerror(errno);
		} else {
			if (lkl_errdir(lkl_dir))
				err = lkl_strerror(lkl_errdir(lkl_dir));
		}
	}

	if (err)
		fprintf(stderr, "error while reading directory %s: %s\n",
			path, err);
	return name;
}

static void close_dir(DIR *dir)
{
	if (cptofs)
		closedir(dir);
	else
		lkl_closedir((struct lkl_dir *)dir);
}

static int searchdir(const char *src, const char *dst, const char *match)
{
	DIR *dir;
	const char *name;
	int ret = 0;

	dir = open_dir(src);
	if (!dir)
		return -1;

	while ((name = read_dir(dir, src))) {
		if (!strcmp(name, ".") || !strcmp(name, "..") ||
		    (match && fnmatch(match, name, 0) != 0))
			continue;

		ret = do_entry(src, dst, name);
		if (ret)
			goto out;
	}

out:
	close_dir(dir);

	return ret;
}

int main(int argc, char **argv)
{
	union lkl_disk_backstore bs;
	long ret;
	char mpoint[32], src_path[PATH_MAX], dst_path[PATH_MAX];
	char *src_path_dir, *src_path_base;
	unsigned int disk_id;

	if (strstr(argv[0], "cptofs")) {
		cptofs = 1;
		ret = argp_parse(&argp_cptofs, argc, argv, 0, 0, &cla);
	} else {
		ret = argp_parse(&argp_cpfromfs, argc, argv, 0, 0, &cla);
	}

	if (ret < 0)
		return -1;

	if (!cla.printk)
		lkl_host_ops.print = NULL;

	bs.fd = open(cla.fsimg_path, cptofs ? O_RDWR : O_RDONLY);
	if (bs.fd < 0) {
		fprintf(stderr, "can't open fsimg %s: %s\n", cla.fsimg_path,
			strerror(errno));
		ret = 1;
		goto out;
	}

	ret = lkl_disk_add(bs);
	if (ret < 0) {
		fprintf(stderr, "can't add disk: %s\n", lkl_strerror(ret));
		goto out_close;
	}
	disk_id = ret;

	rump_init();

	ret = lkl_mount_dev(disk_id, cla.fsimg_type, cptofs ? 0 : LKL_MS_RDONLY,
			    NULL, mpoint, sizeof(mpoint));
	if (ret) {
		fprintf(stderr, "can't mount disk: %s\n", lkl_strerror(ret));
		goto out_close;
	}

	if (cptofs) {
		snprintf(src_path, sizeof(src_path),  "%s", cla.src_path);
		snprintf(dst_path, sizeof(dst_path),  "%s/%s", mpoint,
			 cla.dst_path);
	} else {
		snprintf(src_path, sizeof(src_path),  "%s/%s", mpoint,
			 cla.src_path);
		snprintf(dst_path, sizeof(dst_path),  "%s", cla.dst_path);
	}

	src_path_dir = dirname(strdup(src_path));
	src_path_base = basename(strdup(src_path));

	ret = searchdir(src_path_dir, dst_path, src_path_base);

	ret = lkl_umount_dev(disk_id, 0, 1000);

out_close:
	close(bs.fd);

out:
	lkl_sys_halt();

	return ret;
}
