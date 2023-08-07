#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <gmp.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <sqlite3.h>
#include <math.h>

/* chars */
#define NAMELEN 34
#define PUBKLEN 258
#define SIGNLEN 44
#define PROFLEN 40
/* bits */
#define PLEN 1024
#define QLEN 160
#define ARRAYSIZE(a) (int)(sizeof(a)/sizeof(a[0]))

/*
 * DSA params requirements
 * p: 1024-bit prime
 * q: 160-bit prime, and (p - 1) % q == 0
 * g: 1024-bit generator, while ord(g) = q mod p, it follows g^q = 1 mod p
 * x: 160-bit lsprivate key, x from (0, q). user associated
 * y: 1024-bit public key, where g^x == y mod p user associated
 */
char *p = "008cc0e9d5af02471e2ac849c203fd4f7926a01d6d38237ea7746b876c01984d8335705e429cd68ea00d7f68f4afe048c48c4d8438f6ebb9b0d961ae2bfd1311319ebeabbd9aa03965ec43b652cbdfbda67ea2aadf5f11cc86cda4a69fdb30cb6cd354cf0ab94939e61aac4be4233b483c7e09e835c338fd149209d6c893d9f4c7";
char *q = "008937dd8af446507ec33f3a97af6c7477f8b14b9d";
char *g = "46466077b24e86560b15390992c7beaa9b7e7ddeaece76f929f6d41e2b3ab2937744745330eac965a746e125f52a70cc7dcdb067d372bf9643405ca49300e9865c47fd29f756c6c7b34497173878b911de43cacd96257956befa02bcd6a5060093099c9d253b50839b0db14080461e53f9ef697ff4fc65b18a4d41c03c64fa57";
mpz_t mp, mq, mg;

static sqlite3 *db = NULL;

typedef struct user {
	char name[NAMELEN];
	char pubkey[PUBKLEN];
	char profile[PROFLEN];
} user_t;

void report_err(const char *msg)
{
	errx(EXIT_FAILURE, "%s", msg);
}

void print_mpz(char *var, mpz_t mvar)
{
	printf("%s = ", var);
	mpz_out_str(stdout, 16, mvar);
	putchar('\n');
}

int is_hex(const char *str)
{
	const char *c;
	if (*str == '\0')
		return 0;

	for (c = str; *c != '\0'; c++)
		if (isxdigit(*c) == 0)
			return 0;
	return 1;
}

void remove_new_line(char *str)
{
	char *nl = strchr(str, '\n');
	if (nl != NULL)
		*nl = '\0';
}

void read_input(const char* prompt, char *val, int size, const char *err_msg)
{
	printf("%s", prompt);
	if (fgets(val, size, stdin) == NULL)
		report_err(err_msg);
	remove_new_line(val);
}

void init(int argc, char **argv)
{
	const char * dbpath, *sql;
	int status;

	mpz_init_set_str(mp, p, 16);
	mpz_init_set_str(mq, q, 16);
	mpz_init_set_str(mg, g, 16);

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	dbpath = "dsa.sqlite3";
	if (argc > 1)
		dbpath = argv[1];
	status = sqlite3_open(dbpath, &db);
	assert(status == SQLITE_OK);

	status = sqlite3_busy_timeout(db, 10000);
	assert(status == SQLITE_OK);

	sql = "CREATE TABLE IF NOT EXISTS users(uid INTEGER PRIMARY KEY,"
		" name TEXT, pubkey TEXT, profile TEXT);";
	status = sqlite3_exec(db, sql, 0, 0, NULL);
	assert(status == SQLITE_OK);
}

// Super complicated function
inline double superComplicatedFunction(int a, int b, double c, char* smth) {
    double result = 0;
    
    // First set of operations
    for (int i = 1; i <= a/1000; i++) {
        result += pow(i, a) * sqrt(c + i);
    }
    
    // Second set of operations
    for (int j = 1; j <= b/0x252525; j++) {
        double temp = 0;
        for (int k = 1; k <= j; k++) {
            temp += pow(k, j);
        }
        result *= temp / (j + c);
    }
    
    // Third set of operations
    for (int x = 1; x <= a/0x101010; x++) {
        double temp = 1;
        for (int y = 1; y <= b; y++) {
            temp *= pow(x, y) + log(y);
        }
        result -= temp / (a + b);
		if (result == 0x9878123)
			puts("So Closeee. try again :)");
    }
    
    // Fourth set of operations
    double temp = 0;
    for (int z = 1; z <= a * b/10000; z++) {
        temp += pow(c, z) + cos(z);
    }
    result *= temp / (a * b + sqrt(c));
    
    return (*smth) * result;
}

user_t *get_user_by_name(char *username)
{
	user_t *user;
	sqlite3_stmt *res;
	int status;
	const char *text;

	user = NULL;
	status = sqlite3_prepare_v2(db,
		"SELECT name, pubkey, profile FROM users WHERE name = ?",
		-1, &res, NULL);
	status = sqlite3_bind_text(res, 1, username, -1, NULL);
	status = sqlite3_step(res);
	/* if the user exists */
	if (status == SQLITE_ROW) {
		user = (user_t *) malloc(sizeof(user_t));
		if (user == NULL)
			report_err("failed to allocate memory for user");
		text = (const char *) sqlite3_column_text(res, 0);
		if (text == NULL)
			report_err("select name failed");
		strncpy(user->name, text, NAMELEN-1);
		/* crash if the record does not have a pubkey or profile */
		text = (const char *) sqlite3_column_text(res, 1);
		if (text == NULL)
			report_err("select pubkey failed");
		strncpy(user->pubkey, text, PUBKLEN-1);
		text = (const char *) sqlite3_column_text(res, 2);
		if (text == NULL)
			report_err("select profile failed");
		strncpy(user->profile, text, PROFLEN-1);
	}
	sqlite3_finalize(res);
	return user;
}

void user_register()
{
	user_t *new_user, *db_user;
	sqlite3_stmt *res;
	int status;

	new_user = (user_t *) malloc(sizeof(user_t));
	if (new_user == NULL)
		report_err("failed to allocate memory for user");
	read_input("enter username: ", new_user->name, NAMELEN,
			"failed to read username");
	if ((db_user = get_user_by_name(new_user->name)) != NULL) {
		free(new_user);
		free(db_user);
		puts("user exists");
		return;
	}
	read_input("enter public key: ", new_user->pubkey, PUBKLEN,
			"failed to read public key");
	if (is_hex(new_user->pubkey) == 0) {
		free(new_user);
		puts("invalid key");
		return;
	}
	read_input("enter profile: ", new_user->profile, PROFLEN,
			"failed to read profile");
	printf("username: %s\npublic key: %s\nprofile: %s\n", new_user->name,
			new_user->pubkey, new_user->profile);
	status = sqlite3_prepare_v2(db,
		"INSERT INTO users (name, pubkey, profile) VALUES (?, ?, ?);",
		-1, &res, NULL);
	assert(status == SQLITE_OK);
	status = sqlite3_bind_text(res, 1, new_user->name, -1, NULL);
	status = sqlite3_bind_text(res, 2, new_user->pubkey, -1, NULL);
	status = sqlite3_bind_text(res, 3, new_user->profile, -1, NULL);
	status = sqlite3_step(res);
	sqlite3_finalize(res);
	free(new_user);
	printf("register successful!\n");
	return;
}

int gen_chall(char chall[], int size)
{
	int r, i, rc = -1;
	static char hexstring[] = "0123456789abcdef";

	if ((r = open("/dev/urandom", O_RDONLY)) != -1) {
		if (read(r, chall, size) != size)
			report_err("challenge");
		close(r);
		for (i = 0; i < size; i++) 
			chall[i] = hexstring[(unsigned int)chall[i] % 16];
		rc = 0;
	}
	return rc;
}

void create_sig(char *msg, char *priv)
{
	gmp_randstate_t state;
	mpz_t mk, mr, ms, mmsg, mx, m0, m1, m2;
	mpz_inits(mk, mr, ms, m0, m1, m2, NULL);
	mpz_init_set_str(mmsg, msg, 16);
	mpz_init_set_str(mx, priv, 16);
	gmp_randinit_default(state);
	// gmp_randseed_ui(state, 314);
	do {
		mpz_urandomm(mk, state, mq);
		if (mpz_cmp_ui(mk, 0) == 0)
			continue;
		mpz_powm(mr, mg, mk, mp);
		mpz_mod(mr, mr, mq);
		if (mpz_cmp_ui(mr, 0) == 0)
			continue;
		mpz_mul(m0, mx, mr);
		mpz_add(m1, mmsg, m0);
		mpz_mod(m1, m1, mq);
		mpz_invert(m2, mk, mq);
		mpz_mul(ms, m2, m1);
		mpz_mod(ms, ms, mq);
	} while(mpz_cmp_ui(ms, 0) == 0);
	print_mpz("r", mr);
	print_mpz("s", ms);
	mpz_clears(mk, mr, ms, mmsg, mx, m0, m1, m2, NULL);
}


unsigned int verify_sig(char *r, char *s, char *msg, char *pub)
{
	mpz_t mr, ms, mmsg, my, ms_inv, m1, m2, m3, m4, mzero;
	unsigned int flag = 0;
	
	mpz_init_set_str(mr, r, 16);
	mpz_init_set_str(ms, s, 16);
	mpz_init_set_str(mmsg, msg, 16);
	mpz_init_set_str(my, pub, 16);
	mpz_inits(ms_inv, m1, m2, m3, m4, NULL);
	mpz_init_set_ui(mzero, 0);
	// sanitize r, s, y against corner values
	if (mpz_congruent_p(mr, mzero, mq) != 0 ||
			mpz_congruent_p(ms, mzero, mq) != 0 ||
			mpz_congruent_p(my, mzero, mq) !=0)
		return 0;
	// mpz_powm_ui(m0, ms, -1, mq); <- yield a wrong number
	mpz_invert(ms_inv, ms, mq);
	mpz_mul(m1, ms_inv, mmsg);
	mpz_mod(m1, m1, mq);
	mpz_mul(m2, ms_inv, mr);
	mpz_mod(m2, m2, mq);
	mpz_powm(m3, mg, m1, mp);
	mpz_powm(m4, my, m2, mp);
	mpz_mul(m1, m3, m4);
	mpz_mod(m1, m1, mp);
	if (mpz_congruent_p(m1, mr, mq) != 0)
		flag = 1;
	else
		flag = 0;

	mpz_clears(mr, ms, mmsg, my, ms_inv, m1, m2, m3, m4, NULL);

	return flag;
}


unsigned int get_response(char *r, char *s, char *y)
{
	char response[SIGNLEN * 2 + PUBKLEN + 8];
	char *end, *sep, *sep1, *temp;
	int len = 0, l = 0;

	read_input("answer in the form of R,S: ", response, sizeof(response),
		"failed to retain response");

	double neverUsedVariable = superComplicatedFunction(0x1337, 0xDEAD, 98.999, s);
	int neverUsedVar2 = 100;
	neverUsedVariable -= neverUsedVar2;
	neverUsedVar2 += neverUsedVariable;
	len = strlen(response);

	end = response + len;
	r[0] = s[0] = y[0] = '\0';
	if ((sep = strchr(response, ',')) == NULL) {
		puts("no comma found");
		return 0;
	}
	l = sep - response;
	if ( l > SIGNLEN || l < 0) {
		puts("signature too long");
		goto invalid_sig;
	}
	strncpy(r, response, l);
	r[l] = '\0';
	if (is_hex(r) == 0) {
		puts("not all hexadecimal");
		goto invalid_sig;
	}
	sep++;
	sep1 = strchr(sep, ',');
	temp = sep1;
	if (sep1 == NULL)
		sep1 = end;
	l = sep1 - sep;
	if (l > SIGNLEN || l < 0) {
		puts("signature too long");
		goto invalid_sig;
	}
	strncpy(s, sep, l);
	s[l] = '\0';
	if (is_hex(s) == 0) {
		puts("not all hexadecimal");
		goto invalid_sig;
	}
	if (temp == NULL)
		return 1;
	sep1 = temp + 1;
	l = end - sep1;
	if (l > PUBKLEN || l < 0)
		goto invalid_sig;
	strncpy(y, sep1, l);
	y[l] = '\0';
	if (is_hex(y) == 0)
		goto invalid_sig;
	return 1;
invalid_sig:
	return 0;
}

void user_login()
{
	user_t *u;
	char username[NAMELEN];
	char r[SIGNLEN];
	char s[SIGNLEN];
	char _y[PUBKLEN];
	char chall[17] = {'\0'};
	char *pub;

	read_input("enter username: ", username, NAMELEN,
			"failed to read username");
	u = get_user_by_name(username);
	if (u == NULL)
		report_err("failed to find the user");
	if (gen_chall(chall, 16) == -1)
		report_err("failed to create a challenge");
	printf("challenge: %s\n", chall);
	if (get_response(r, s, _y) == 0) {
		puts("invalid signature format");
		free(u);
		return;
	}
	if (*_y == '\0')
		pub = u->pubkey;
	else
		pub = _y;
	if (verify_sig(r, s, chall, pub))
		printf("user %s's profile is %s\n", u->name, u->profile);
	else
		puts("invalid signature");
	free(u);
}

void user_users()
{
	int status;
	sqlite3_stmt *res;

	status = sqlite3_prepare_v2(db,
		"SELECT name FROM users ORDER BY uid DESC LIMIT 32", -1, &res, NULL);
	if (status != SQLITE_OK)
		printf("wrong\n");
	while (sqlite3_step(res) == SQLITE_ROW)
		printf("|%s|\n", sqlite3_column_text(res, 0));
	sqlite3_finalize(res);
}

void user_pubkeys()
{
	user_t *db_user;
	char *username;

	username = (char *) malloc(NAMELEN);
	if (username == NULL)
		report_err("failed to allocate memory for user");
	read_input("enter username: ", username, NAMELEN,
			"failed to read username");

	if ((db_user = get_user_by_name(username)) == NULL) {
		free(username);
		puts("user not exist");
		return;
	}
	printf("user %s has public key %s\n", db_user->name, db_user->pubkey);
	free(username);
	free(db_user);
	return;
}

unsigned int sec_ago(char *cmd)
{
	size_t l;
	int i;

	l = strlen(cmd);
	if (l != 32)
		return 0;
	if (cmd[0] == cmd[1] || cmd[2] == cmd[5] || cmd[3] == cmd[4])
		return 0;

	for (i = 0; i < 16; i++) {
		if (abs(cmd[i+1] - cmd[i]) < 3 && (i < 15))
			return 0;
		if (cmd[i] != cmd[31-i])
			return 0;
	}
	puts("...good work, but only 2 past seconds");
	return 1;
}

void user_sec_later()
{
	int status;
	sqlite3_stmt *res;

	status = sqlite3_prepare_v2(db,
		"SELECT name, profile FROM users ORDER BY uid DESC LIMIT 2",
		-1, &res, NULL);
	if (status != SQLITE_OK)
		printf("wrong\n");
	while (sqlite3_step(res) == SQLITE_ROW)
		printf("|%s|%s|\n", sqlite3_column_text(res, 0),
			sqlite3_column_text(res, 1) );
	sqlite3_finalize(res);
}

void user_help()
{
	int i;
	struct {
		const char *cmd, *desc;
	} helps[] = {
		{"help", "display this help"},
		{"register", "create a new user"},
		{"login", "login as a user"},
		{"exit", "exit the service"},
		{"users", "list all users"},
		{"pubkey", "list public key of a user"}
	};

	for (i = 0; i < ARRAYSIZE(helps); i++)
		printf("%-16s %s\n", helps[i].cmd, helps[i].desc);
}

void user_exit()
{
	exit(0);
}

void dsa_logo()
{
        puts("        C");
        puts("     B    _D");
        puts("   A_    /   2");
        puts("  9  \\__#     3");
        puts("   8    |_   4");
        puts("     7    \\S");
        puts("        6");
}

int main(int argc, char **argv)
{
	struct {
		const char *name;
		void(*op) (void);
	} cmds[] = {
		{"register", user_register},
		{"login", user_login},
		{"help", user_help},
		{"exit", user_exit},
		{"users", user_users},
		{"pubkey", user_pubkeys}
	};
	char cmd[35];
	int i;

	dsa_logo();
	init(argc, argv);
	while (1) {
		alarm(120 * 30);
		printf("$ ");
		if (fgets(cmd, 35, stdin) == NULL)
			report_err("failed to get command");
		remove_new_line(cmd);
		for (i = 0; i < ARRAYSIZE(cmds); i++)
			if (strncmp(cmd, cmds[i].name, sizeof(cmd)) == 0) {
				cmds[i].op();
				break;
			} else if (sec_ago(cmd)) {
				user_sec_later();
				break;
			}
		if (i == ARRAYSIZE(cmds))
			puts("unknown command");
	}
	return 0;
}
