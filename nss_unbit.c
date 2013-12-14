#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

#define UNBIT_MIN_UID 30000
#define UNBIT_HOME "/accounts/"

static int unbit_magic_buf(char *what, size_t len, char **buffer, size_t *buflen) {
	if (len >= *buflen-1) return -1;	
	strcpy(*buffer, what);
	*buflen -= len+1;
	*buffer += len+1;
	return 0;
}

static enum nss_status unbit_res(char *name, size_t name_len, char *home, size_t home_len, uid_t uid, struct passwd *res, char **buffer, size_t *buflen) {
	res->pw_uid = uid;
        res->pw_gid = (gid_t) uid;
        res->pw_passwd = *buffer;
        if (unbit_magic_buf("x", 1, buffer, buflen)) return NSS_STATUS_UNAVAIL;
        res->pw_gecos = *buffer;
        if (unbit_magic_buf(name, name_len, buffer, buflen)) return NSS_STATUS_UNAVAIL;
        res->pw_dir = *buffer;
        if (unbit_magic_buf(home, home_len, buffer, buflen)) return NSS_STATUS_UNAVAIL;
        res->pw_shell = *buffer;
        if (unbit_magic_buf("/bin/bash", 9, buffer, buflen)) return NSS_STATUS_UNAVAIL;

        return NSS_STATUS_SUCCESS;
}

static enum nss_status unbit_gres(char *name, size_t name_len, gid_t gid, struct group *res, char **buffer, size_t *buflen) {
        res->gr_gid = gid;
        res->gr_passwd = *buffer;
        if (unbit_magic_buf("x", 1, buffer, buflen)) return NSS_STATUS_UNAVAIL;
	if (*buflen < sizeof(char*)) return NSS_STATUS_UNAVAIL;
        res->gr_mem = (char **) *buffer;
	res->gr_mem[0] = NULL;

        return NSS_STATUS_SUCCESS;
}


enum nss_status _nss_unbit_getpwnam_r(char *name, struct passwd *res, char *buffer, size_t buflen, int *errnop) {
	struct stat st;
	char filename[1024];
	size_t name_len = strlen(name);
	uid_t uid = atoi(name);
	if (uid < UNBIT_MIN_UID) return NSS_STATUS_UNAVAIL;
	// security check
	if (name_len + sizeof(UNBIT_HOME) >= 1024) return NSS_STATUS_UNAVAIL;
	memcpy(filename, UNBIT_HOME, sizeof(UNBIT_HOME));
	memcpy(filename + (sizeof(UNBIT_HOME)-1), name, name_len);
	filename[(sizeof(UNBIT_HOME)-1) + name_len] = 0;

	if (stat(filename, &st)) return NSS_STATUS_UNAVAIL;

	if (st.st_uid != uid) return NSS_STATUS_UNAVAIL;
	if (st.st_gid != uid) return NSS_STATUS_UNAVAIL;

	return unbit_res(name, name_len, filename, (sizeof(UNBIT_HOME)-1) + name_len, uid, res, &buffer, &buflen);
}

enum nss_status _nss_unbit_getpwuid_r(uid_t uid, struct passwd *res, char *buffer, size_t buflen, int *errnop) {
        struct stat st;
        char filename[1024];
        if (uid < UNBIT_MIN_UID) return NSS_STATUS_UNAVAIL;
        // security check
	int ret = snprintf(filename, 1024, UNBIT_HOME "%d", (int) uid);
	if (ret <= 0 || ret > 1024) return NSS_STATUS_UNAVAIL;

        if (stat(filename, &st)) return NSS_STATUS_UNAVAIL;

        if (st.st_uid != uid) return NSS_STATUS_UNAVAIL;
        if (st.st_gid != uid) return NSS_STATUS_UNAVAIL;

	char *name = filename + (sizeof(UNBIT_HOME)-1);
	size_t name_len = ret - (sizeof(UNBIT_HOME)-1);

        res->pw_name = buffer;
	if (unbit_magic_buf(name, name_len, &buffer, &buflen)) return NSS_STATUS_UNAVAIL;

	return unbit_res(name, name_len, filename, (sizeof(UNBIT_HOME)-1) + name_len, uid, res, &buffer, &buflen);
}

enum nss_status _nss_unbit_getgrgid_r(gid_t gid, struct group *res, char *buffer, size_t buflen, int *errnop) {
        struct stat st;
        char filename[1024];
        if (gid < UNBIT_MIN_UID) return NSS_STATUS_UNAVAIL;
        // security check
        int ret = snprintf(filename, 1024, UNBIT_HOME "%d", (int) gid);
        if (ret <= 0 || ret > 1024) return NSS_STATUS_UNAVAIL;

        if (stat(filename, &st)) return NSS_STATUS_UNAVAIL;

        if (st.st_uid != gid) return NSS_STATUS_UNAVAIL;
        if (st.st_gid != gid) return NSS_STATUS_UNAVAIL;

        char *name = filename + (sizeof(UNBIT_HOME)-1);
        size_t name_len = ret - (sizeof(UNBIT_HOME)-1);

        res->gr_name = buffer;
        if (unbit_magic_buf(name, name_len, &buffer, &buflen)) return NSS_STATUS_UNAVAIL;

        return unbit_gres(name, name_len, gid, res, &buffer, &buflen);
}

enum nss_status _nss_unbit_getgrnam_r(char *name, struct group *res, char *buffer, size_t buflen, int *errnop) {
        struct stat st;
        char filename[1024];
        size_t name_len = strlen(name);
        gid_t gid = atoi(name);
        if (gid < UNBIT_MIN_UID) return NSS_STATUS_UNAVAIL;
        // security check
        if (name_len + sizeof(UNBIT_HOME) >= 1024) return NSS_STATUS_UNAVAIL;
        memcpy(filename, UNBIT_HOME, sizeof(UNBIT_HOME));
        memcpy(filename + (sizeof(UNBIT_HOME)-1), name, name_len);
        filename[(sizeof(UNBIT_HOME)-1) + name_len] = 0;

        if (stat(filename, &st)) return NSS_STATUS_UNAVAIL;

        if (st.st_uid != gid) return NSS_STATUS_UNAVAIL;
        if (st.st_gid != gid) return NSS_STATUS_UNAVAIL;

        return unbit_gres(name, name_len, gid, res, &buffer, &buflen);
}

