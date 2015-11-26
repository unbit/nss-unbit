#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <math.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#define UNBIT_MIN_UID 30000
#define UNBIT_HOME "/containers/"

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
	res->gr_gid = (gid_t) gid;
        res->gr_passwd = *buffer;
        if (unbit_magic_buf("x", 1, buffer, buflen)) return NSS_STATUS_UNAVAIL;
	if (*buflen < sizeof(char*)) return NSS_STATUS_UNAVAIL;
        res->gr_mem = (char **) *buffer;
	res->gr_mem[0] = NULL;

        return NSS_STATUS_SUCCESS;
}

static enum nss_status unbit_sres(char *name, size_t name_len, struct spwd *res, char **buffer, size_t *buflen) {
        res->sp_pwdp = *buffer;
        if (unbit_magic_buf("!", 1, buffer, buflen)) return NSS_STATUS_UNAVAIL;
	res->sp_lstchg = (long) ((time(NULL)/(3600*24))-1);
	res->sp_min = -1;
	res->sp_max = -1;
	res->sp_warn = -1;
	res->sp_inact = -1;
	res->sp_expire = -1;
	res->sp_flag = 0;
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

	res->pw_name = name;

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

	res->gr_name = name;

        return unbit_gres(name, name_len, gid, res, &buffer, &buflen);
}

enum nss_status _nss_unbit_getspnam_r(char *name, struct spwd *res, char *buffer, size_t buflen, int *errnop) {
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

	res->sp_namp = name;

        return unbit_sres(name, name_len, res, &buffer, &buflen);	
}

static uint32_t unbit_ip(uint32_t uid) {
        if (uid < 30000) return 0;
        // skip the first address as it is always 10.0.0.1
        uint32_t addr = (uid - 30000)+2;
        uint32_t addr0 = 0x0a000000;
        return htonl(addr0 | (addr & 0x00ffffff));
}

static int ends_with(const char *name, const char *with) {
        size_t n_len = strlen(name);
        size_t w_len = strlen(with);

        if (n_len > w_len) {
                if (!strcmp(name + (n_len - w_len), with)) {
                        return (n_len - w_len);
                }
        }

        return 0;
}

static uint32_t str2num(const char *str, int len) {

        int i;
        size_t num = 0;

        uint64_t delta = pow(10, len);

        for (i = 0; i < len; i++) {
		if (str[i] < 48 || str[i] > 57) return 0;
                delta = delta / 10;
                num += delta * (str[i] - 48);
        }

        return num;
}


enum nss_status _nss_unbit_gethostbyname2_r(
    const char *name,
    int af,
    struct hostent * result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

        if (af != AF_INET) goto end;
        int l = ends_with(name, ".local");
        if (l <= 0) goto end;

        uint32_t n = str2num(name, l);
	if (n <= UNBIT_MIN_UID) goto end;

	// pointer to aliases (NULL) + original name + ipv4 + address_list + NULL
	if (buflen < sizeof(char*)+strlen(name)+4+(sizeof(void*)*2)) {
        	*errnop = ERANGE;
        	*h_errnop = NO_RECOVERY;
		return NSS_STATUS_TRYAGAIN;
	}

	*((char**) buffer) = NULL;
    	result->h_aliases = (char**) buffer;
    	size_t idx = sizeof(char*);
	strcpy(buffer + idx, name);
	result->h_name = buffer+idx;
	idx += strlen(name) + 1;
	result->h_addrtype = af;
	result->h_length = 4;
	uint32_t ip = unbit_ip(n);
	memcpy(buffer+idx, &ip, 4);
	idx+=4;
	((char**) (buffer+idx))[0] = buffer+(idx-4);
    	((char**) (buffer+idx))[1] = NULL;
	result->h_addr_list = (char**) (buffer+idx);
	return NSS_STATUS_SUCCESS;
end:
        return NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_unbit_gethostbyname_r (
    const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop) {

    return _nss_unbit_gethostbyname2_r(
        name,
        AF_UNSPEC,
        result,
        buffer,
        buflen,
        errnop,
        h_errnop);
}

