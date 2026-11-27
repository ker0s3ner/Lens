//! Function prototypes: a built-in library for libc / POSIX / macOS / Win32 plus the person's own.
//! The decompiler uses them to give calls the right number of arguments, to mark functions that never return,
//! and to print a function's own signature with real types and parameter names.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
#[cfg(test)]
use std::cell::RefCell;

#[derive(Clone, Debug, PartialEq)]
pub struct Proto {
    pub name: String,
    pub ret: String,
    pub params: Vec<(String, String)>, // (type, name)
    pub variadic: bool,
    pub noreturn: bool,
}

impl Proto {
    pub fn signature(&self) -> String {
    let mut ps: Vec<String> = self.params.iter().map(|(t, n)| {
        if n.is_empty() { t.clone() }
        else if t.contains("(*)") { t.replace("(*)", &format!("(*{n})")) }
        else if t.ends_with('*') { format!("{t}{n}") }
        else { format!("{t} {n}") }
    }).collect();
        if self.variadic { ps.push("...".into()); }
        format!("{} {}({})", self.ret, self.name, if ps.is_empty() { "void".into() } else { ps.join(", ") })
    }
}

const BASE_TYPES: &[&str] = &["void", "int", "char", "short", "long", "float", "double", "unsigned", "signed", "const", "struct", "union", "enum", "size_t", "ssize_t", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "intptr_t", "uintptr_t", "__int128", "__uint128", "__int128_t", "__uint128_t", "bool", "BOOL", "DWORD", "HANDLE", "LPVOID", "LPCSTR", "LPCWSTR", "HMODULE", "UINT", "ULONG", "LONG", "WORD", "BYTE", "off_t", "pid_t", "FILE", "va_list", "time_t", "mode_t", "socklen_t"];

fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') { i += 1; }
            i += 2;
        } else if b[i] == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' { i += 1; }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

fn tidy(t: String) -> String {
    let mut t = t;
    while t.contains("* *") { t = t.replace("* *", "**"); }
    t.trim().to_string()
}

fn collect_typedefs(decls: &[String]) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for d in decls {
        let d = d.trim();
        if !d.starts_with("typedef ") { continue; }
        let body = d.trim_start_matches("typedef ").trim();
        if let Some(start) = body.find("(*") {
            let Some(end) = body[start + 2..].find(')') else { continue };
            let end = start + 2 + end;
            let name = body[start + 2..end].trim();
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') { continue; }
            aliases.insert(name.to_string(), tidy(format!("{} (*){}", body[..start].trim(), body[end + 1..].trim())));
        } else {
            let toks: Vec<&str> = body.split_whitespace().collect();
            if toks.len() >= 2 {
                let name = toks[toks.len() - 1];
                if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    aliases.insert(name.to_string(), tidy(toks[..toks.len() - 1].join(" ")));
                }
            }
        }
    }
    aliases
}

fn resolve_alias(ty: String, aliases: &HashMap<String, String>) -> String {
    let mut current = ty;
    for _ in 0..8 {
        let Some(next) = aliases.get(current.trim()) else { break };
        if next == &current { break; }
        current = next.clone();
    }
    current
}

fn split_top(s: &str) -> Vec<String> {
    let (mut depth, mut cur, mut out) = (0i32, String::new(), vec![]);
    for c in s.chars() {
        match c {
            '(' => { depth += 1; cur.push(c); }
            ')' => { depth -= 1; cur.push(c); }
            ',' if depth == 0 => { out.push(cur.trim().to_string()); cur.clear(); }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() { out.push(cur.trim().to_string()); }
    out
}

/// "const char *fmt" -> ("const char *", "fmt")
fn split_param(p: &str, i: usize) -> (String, String) {
    let p = p.trim();
    if p.contains('(') {
        // Normalize `int (*cmp)(int)` into type `int (*)(int)` plus name `cmp`.
        // Keeping the name separate makes signatures and call metadata useful.
        if let Some(start) = p.find("(*") {
            if let Some(end) = p[start + 2..].find(')') {
                let end = start + 2 + end;
                let name = p[start + 2..end].trim();
                if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    let mut ty = p.to_string();
                    ty.replace_range(start + 1..end, "*");
                    return (ty, name.to_string());
                }
            }
        }
        return (p.to_string(), format!("a{}", i + 1));
    }
    let spaced = p.replace('*', " * ");
    let toks: Vec<&str> = spaced.split_whitespace().collect();
    let name_ok = |t: &str| t.chars().all(|c| c.is_alphanumeric() || c == '_') && !t.is_empty();
    if let Some(last) = toks.last() {
        let only_type = toks.len() == 1 || BASE_TYPES.contains(last) && toks.len() < 2;
        if !only_type && name_ok(last) && !BASE_TYPES.contains(last) && !matches!(*last, "*") {
            let ty = toks[..toks.len() - 1].join(" ").replace(" *", "*").replace("* ", "*");
            let ty = ty.replace('*', " *").replace("  ", " ");
            return (ty.trim().replace(" *", " *"), last.to_string());
        }
    }
    (toks.join(" ").replace(" *", "*").replace('*', " *").trim().to_string(), format!("a{}", i + 1))
}

/// Parses C-style declarations such as `int open(const char *path, int flags, ...);`. Lines that aren't declarations are skipped.
pub fn parse(text: &str) -> (Vec<Proto>, Vec<String>) {
    let clean = strip_comments(text);
    let declarations: Vec<String> = clean.split(';').map(|d| d.trim().replace('\n', " ")).collect();
    let aliases = collect_typedefs(&declarations);
    let mut out = vec![];
    let mut errs = vec![];
    for d in declarations {
        let mut d = d;
        let mut leading_noret = false;
        for attr in ["__attribute__((noreturn))", "__attribute__((__noreturn__))", "[[noreturn]]", "[[gnu::noreturn]]"] {
            if d.trim_start().starts_with(attr) {
                leading_noret = true;
                d = d.trim_start()[attr.len()..].trim().to_string();
            }
        }
        if d.is_empty() || d.starts_with("typedef") || d.starts_with("struct ") && !d.contains('(') || d.starts_with('#') { continue; }
        let Some(open) = d.find('(') else { errs.push(format!("Not a function declaration: {d}")); continue };
        let mut depth = 0i32;
        let mut close = None;
        for (i, c) in d.char_indices().skip(open) {
            if c == '(' { depth += 1 } else if c == ')' { depth -= 1; if depth == 0 { close = Some(i); break; } }
        }
        let Some(close) = close else { errs.push(format!("Missing ) in: {d}")); continue };
        let head = d[..open].trim();
        let mut noret = leading_noret || d[close + 1..].contains("noreturn");
        let head: Vec<&str> = head.split_whitespace().filter(|w| {
            if matches!(*w, "noreturn" | "__noreturn" | "_Noreturn" | "__declspec(noreturn)" | "__attribute__((noreturn))" | "__attribute__((__noreturn__))" | "[[noreturn]]" | "[[gnu::noreturn]]") { noret = true; false } else { !matches!(*w, "extern" | "static" | "inline" | "WINAPI" | "__stdcall" | "__cdecl" | "APIENTRY") }
        }).collect();
        let joined = head.join(" ").replace('*', " * ");
        let mut toks: Vec<&str> = joined.split_whitespace().collect();
        let Some(last) = toks.pop() else { errs.push(format!("No name in: {d}")); continue };
        let operator_name = if matches!(last, "new" | "delete" | "new[]" | "delete[]") {
            if toks.last() == Some(&"operator") { toks.pop(); Some(format!("operator {last}")) } else { None }
        } else { None };
        let name = operator_name.as_deref().unwrap_or(last);
        if toks.is_empty() || (!name.starts_with("operator ") && !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')) { errs.push(format!("Couldn't read: {d}")); continue; }
        let ret = resolve_alias(toks.join(" ").replace(" *", "*").replace('*', " *").trim().to_string(), &aliases);
        let inner = &d[open + 1..close];
        let mut variadic = false;
        let mut params = vec![];
        for (i, p) in split_top(inner).into_iter().enumerate() {
            if p == "..." { variadic = true; continue; }
            if p == "void" && i == 0 { continue; }
            if p.is_empty() { continue; }
            let (t, n) = split_param(&p, params.len());
            params.push((resolve_alias(tidy(t), &aliases), n));
        }
        out.push(Proto { name: name.to_string(), ret: tidy(ret), params, variadic, noreturn: noret });
    }
    (out, errs)
}

static BUILTIN: OnceLock<HashMap<String, Proto>> = OnceLock::new();
static USER: RwLock<Option<HashMap<String, Proto>>> = RwLock::new(None);
#[cfg(test)]
thread_local! { static TEST_USER: RefCell<Option<HashMap<String, Proto>>> = const { RefCell::new(None) }; }

fn builtin() -> &'static HashMap<String, Proto> {
    BUILTIN.get_or_init(|| parse(LIBRARY).0.into_iter().map(|p| (p.name.clone(), p)).collect())
}

pub fn builtin_count() -> usize {
    builtin().len()
}

/// Installs the person's own prototypes (called whenever they change).
pub fn set_user(text: &str) {
    let m: HashMap<String, Proto> = parse(text).0.into_iter().map(|p| (p.name.clone(), p)).collect();
    #[cfg(test)]
    {
        TEST_USER.with(|user| *user.borrow_mut() = Some(m));
        return;
    }
    #[cfg(not(test))]
    if let Ok(mut g) = USER.write() {
        *g = Some(m);
    }
}

fn norm(name: &str) -> String {
    let n = name.trim_start_matches("__imp_").trim_start_matches('_');
    let n = n.split('@').next().unwrap_or(n);
    n.to_string()
}

pub fn find(name: &str) -> Option<Proto> {
    let n = norm(name);
    #[cfg(test)]
    if let Some(p) = TEST_USER.with(|user| user.borrow().as_ref().and_then(|m| m.get(name).or_else(|| m.get(&n)).cloned())) {
        return Some(p);
    }
    if let Ok(g) = USER.read() {
        if let Some(m) = g.as_ref() {
            if let Some(p) = m.get(name).or_else(|| m.get(&n)) {
                return Some(p.clone());
            }
        }
    }
    let b = builtin();
    if let Some(p) = b.get(&n) {
        return Some(p.clone());
    }
    // Win32 A/W variants: CreateFileW -> CreateFile entry
    if n.len() > 3 && (n.ends_with('W') || n.ends_with('A')) {
        if let Some(p) = b.get(&n[..n.len() - 1]) {
            let mut p = p.clone();
            p.name = n;
            return Some(p);
        }
    }
    None
}

pub fn count_builtin_names() -> Vec<String> {
    let mut v: Vec<String> = builtin().keys().cloned().collect();
    v.sort();
    v
}

const LIBRARY: &str = r#"
// ---- program entry
int main(int argc, char **argv, char **envp);
// ---- string / memory
void *memcpy(void *dst, const void *src, size_t n); void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n); int memcmp(const void *a, const void *b, size_t n); void *memchr(const void *s, int c, size_t n);
int memset_s(void *s, size_t smax, int c, size_t n); void *memccpy(void *dst, const void *src, int c, size_t n);
size_t strlen(const char *s); size_t strnlen(const char *s, size_t n); char *strcpy(char *dst, const char *src); char *strncpy(char *dst, const char *src, size_t n);
char *strcat(char *dst, const char *src); char *strncat(char *dst, const char *src, size_t n); int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n); int strcasecmp(const char *a, const char *b); int strncasecmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c); char *strrchr(const char *s, int c); char *strstr(const char *h, const char *n); char *strdup(const char *s);
char *strtok(char *s, const char *delim); size_t strspn(const char *s, const char *accept); size_t strcspn(const char *s, const char *reject);
char *strerror(int errnum); char *strpbrk(const char *s, const char *accept); size_t strlcpy(char *dst, const char *src, size_t n); size_t strlcat(char *dst, const char *src, size_t n);
// ---- stdlib
void *malloc(size_t size); void *calloc(size_t n, size_t size); void *realloc(void *p, size_t size); void free(void *p);
void *operator new(size_t size); void operator delete(void *p); void *operator new[](size_t size); void operator delete[](void *p);
void exit(int status) noreturn; void abort(void) noreturn; void _exit(int status) noreturn; int atexit(void (*fn)(void));
int atoi(const char *s); long atol(const char *s); long strtol(const char *s, char **end, int base); unsigned long strtoul(const char *s, char **end, int base);
double strtod(const char *s, char **end); double atof(const char *s); char *getenv(const char *name); int setenv(const char *name, const char *value, int overwrite);
int putenv(char *s); int system(const char *cmd); int abs(int x); long labs(long x); int rand(void); void srand(unsigned seed);
void qsort(void *base, size_t n, size_t size, int (*cmp)(const void *, const void *)); void *bsearch(const void *key, const void *base, size_t n, size_t size, int (*cmp)(const void *, const void *));
// ---- stdio
int printf(const char *fmt, ...); int fprintf(FILE *f, const char *fmt, ...); int sprintf(char *buf, const char *fmt, ...); int snprintf(char *buf, size_t n, const char *fmt, ...);
int vprintf(const char *fmt, va_list ap); int vfprintf(FILE *f, const char *fmt, va_list ap); int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int scanf(const char *fmt, ...); int sscanf(const char *s, const char *fmt, ...); int fscanf(FILE *f, const char *fmt, ...);
int puts(const char *s); int putchar(int c); int fputs(const char *s, FILE *f); int fputc(int c, FILE *f); int getchar(void); int fgetc(FILE *f);
char *fgets(char *buf, int n, FILE *f); FILE *fopen(const char *path, const char *mode); int fclose(FILE *f); size_t fread(void *buf, size_t size, size_t n, FILE *f);
size_t fwrite(const void *buf, size_t size, size_t n, FILE *f); int fseek(FILE *f, long off, int whence); long ftell(FILE *f); int fflush(FILE *f);
int feof(FILE *f); int ferror(FILE *f); void perror(const char *s); int remove(const char *path); int rename(const char *from, const char *to);
void err(int eval, const char *fmt, ...) noreturn; void errx(int eval, const char *fmt, ...) noreturn; void warn(const char *fmt, ...); void warnx(const char *fmt, ...);
char *setlocale(int cat, const char *loc); int fchmod(int fd, mode_t mode); int rmdir(const char *path); int readlink(const char *path, char *buf, size_t n);
// ---- POSIX
int open(const char *path, int flags, ...); int close(int fd); ssize_t read(int fd, void *buf, size_t n); ssize_t write(int fd, const void *buf, size_t n);
ssize_t pread(int fd, void *buf, size_t n, off_t off); ssize_t pwrite(int fd, const void *buf, size_t n, off_t off);
ssize_t readv(int fd, const void *iov, int count); ssize_t writev(int fd, const void *iov, int count);
off_t lseek(int fd, off_t off, int whence); int stat(const char *path, void *st); int fstat(int fd, void *st); int unlink(const char *path); int access(const char *path, int mode);
int mkdir(const char *path, mode_t mode); int chdir(const char *path); char *getcwd(char *buf, size_t n); int dup(int fd); int dup2(int from, int to); int pipe(int fds[2]);
pid_t fork(void); pid_t getpid(void); int execve(const char *path, char *const argv[], char *const envp[]); int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]); pid_t waitpid(pid_t pid, int *status, int options); int kill(pid_t pid, int sig); unsigned sleep(unsigned s); int usleep(unsigned us);
int posix_spawn(pid_t *pid, const char *path, const void *actions, const void *attr, char *const argv[], char *const envp[]); int posix_spawnp(pid_t *pid, const char *file, const void *actions, const void *attr, char *const argv[], char *const envp[]);
pid_t waitid(int idtype, unsigned id, void *info, int options); int getrusage(int who, void *usage); pid_t setsid(void); pid_t setpgid(pid_t pid, pid_t pgid);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off); int munmap(void *addr, size_t len); int mprotect(void *addr, size_t len, int prot);
void *dlopen(const char *path, int mode); void *dlsym(void *h, const char *name); int dlclose(void *h); int ioctl(int fd, unsigned long req, ...);
int dladdr(const void *addr, void *info); char *dlerror(void); void *dlvsym(void *h, const char *name, const char *version);
int fcntl(int fd, int cmd, ...); int isatty(int fd); int getopt(int argc, char *const argv[], const char *opts); uid_t getuid(void); int chmod(const char *path, mode_t mode);
char *realpath(const char *path, char *resolved); int strerror_r(int errnum, char *buf, size_t buflen);
time_t time(time_t *t); int gettimeofday(void *tv, void *tz); int clock_gettime(int clockid, void *tp); int clock_getres(int clockid, void *res); int nanosleep(const void *req, void *rem); int signal(int sig, void *handler); int sigaction(int sig, const void *act, void *old);
int sigprocmask(int how, const void *set, void *old); int sigemptyset(void *set); int sigaddset(void *set, int sig); int raise(int sig); int killpg(int pgrp, int sig);
// ---- sockets
int socket(int domain, int type, int proto); int connect(int fd, const void *addr, socklen_t len); int bind(int fd, const void *addr, socklen_t len); int listen(int fd, int backlog);
int accept(int fd, void *addr, socklen_t *len); ssize_t send(int fd, const void *buf, size_t n, int flags); ssize_t recv(int fd, void *buf, size_t n, int flags);
ssize_t sendto(int fd, const void *buf, size_t n, int flags, const void *addr, socklen_t len); ssize_t recvfrom(int fd, void *buf, size_t n, int flags, void *addr, socklen_t *len);
int setsockopt(int fd, int level, int opt, const void *val, socklen_t len); int getaddrinfo(const char *node, const char *svc, const void *hints, void **res); int select(int n, void *r, void *w, void *e, void *tv);
void freeaddrinfo(void *res); int getnameinfo(const void *addr, socklen_t len, char *host, socklen_t hostlen, char *svc, socklen_t svclen, int flags); const char *inet_ntop(int family, const void *src, char *dst, socklen_t size);
int poll(void *fds, unsigned long nfds, int timeout); int epoll_create1(int flags); int epoll_ctl(int epfd, int op, int fd, void *event); int epoll_wait(int epfd, void *events, int maxevents, int timeout);
// ---- threads
int pthread_create(void *t, const void *attr, void *(*fn)(void *), void *arg); int pthread_join(void *t, void **ret); int pthread_mutex_lock(void *m); int pthread_mutex_unlock(void *m);
int pthread_mutex_init(void *m, const void *attr); void pthread_exit(void *ret) noreturn;
int pthread_cond_init(void *cond, const void *attr); int pthread_cond_wait(void *cond, void *mutex); int pthread_cond_signal(void *cond); int pthread_cond_broadcast(void *cond);
int pthread_rwlock_init(void *lock, const void *attr); int pthread_rwlock_rdlock(void *lock); int pthread_rwlock_wrlock(void *lock); int pthread_rwlock_unlock(void *lock);
int sem_init(void *sem, int shared, unsigned value); int sem_wait(void *sem); int sem_post(void *sem); int sem_destroy(void *sem);
int pthread_attr_init(void *attr); int pthread_attr_destroy(void *attr); int pthread_attr_setstacksize(void *attr, size_t size);
// ---- runtime
void assert_rtn(const char *func, const char *file, int line, const char *expr) noreturn; void stack_chk_fail(void) noreturn; void cxa_throw(void *ex, void *type, void *dtor) noreturn;
void *cxa_allocate_exception(size_t n); void cxa_free_exception(void *exception); int cxa_atexit(void (*fn)(void *), void *arg, void *dso); void *cxa_begin_catch(void *exception); void cxa_end_catch(void); void cxa_rethrow(void) noreturn; void cxa_pure_virtual(void) noreturn; int cxa_guard_acquire(unsigned long long *guard); void cxa_guard_release(unsigned long long *guard); void cxa_guard_abort(unsigned long long *guard); void *cxa_vec_new(size_t count, size_t size, size_t padding, void *ctor, void *dtor); void cxa_vec_delete(void *array, size_t size, size_t padding, void *dtor); void cxa_vec_cleanup(void *array, size_t count, size_t size, void *dtor); void longjmp(void *env, int val) noreturn; int setjmp(void *env);
void cxa_vec_ctor(void *array, size_t count, size_t size, void *ctor); void cxa_vec_dtor(void *array, size_t count, size_t size, void *dtor); void cxa_vec_cleanup2(void *array, size_t count, size_t size, void *dtor);
void *cxa_vec_new2(size_t count, size_t size, size_t padding, void *ctor, void *dtor, void *alloc); void cxa_vec_delete2(void *array, size_t size, size_t padding, void *dtor, void *dealloc);
void *cxa_vec_new3(size_t count, size_t size, size_t padding, void *ctor, void *dtor, void *alloc); void cxa_vec_delete3(void *array, size_t size, size_t padding, void *dtor, void *dealloc);
void cxa_throw_bad_array_new_length(void) noreturn; void cxa_bad_alloc(void) noreturn; void cxa_call_unexpected(void *exception) noreturn;
void objc_msgSend(void *self, const char *sel, ...); void *objc_alloc(void *cls); void *objc_retain(void *o); void objc_release(void *o); void *objc_getClass(const char *name);
void *sel_registerName(const char *name); void CFRelease(const void *cf); const void *CFRetain(const void *cf); void NSLog(void *fmt, ...);
// ---- Win32
HANDLE CreateFile(LPCWSTR name, DWORD access, DWORD share, void *sec, DWORD disp, DWORD flags, HANDLE tmpl); BOOL ReadFile(HANDLE h, LPVOID buf, DWORD n, DWORD *read, void *ov);
BOOL WriteFile(HANDLE h, LPCVOID buf, DWORD n, DWORD *written, void *ov); BOOL CloseHandle(HANDLE h); HMODULE LoadLibrary(LPCWSTR name); void *GetProcAddress(HMODULE m, LPCSTR name);
HMODULE GetModuleHandle(LPCWSTR name); LPVOID VirtualAlloc(LPVOID addr, size_t n, DWORD type, DWORD prot); BOOL VirtualFree(LPVOID addr, size_t n, DWORD type);
BOOL VirtualProtect(LPVOID addr, size_t n, DWORD prot, DWORD *old); void ExitProcess(UINT code) noreturn; void ExitThread(DWORD code) noreturn; void Sleep(DWORD ms);
BOOL GetFileSizeEx(HANDLE h, void *size); BOOL SetFilePointerEx(HANDLE h, long long distance, long long *newpos, DWORD method); BOOL ReadFileEx(HANDLE h, LPVOID buf, DWORD n, void *offset, void *complete);
HANDLE CreateFileMapping(HANDLE h, void *sec, DWORD protect, DWORD high, DWORD low, LPCWSTR name); LPVOID MapViewOfFile(HANDLE map, DWORD access, DWORD high, DWORD low, size_t n); BOOL UnmapViewOfFile(LPVOID addr);
DWORD GetLastError(void); HANDLE CreateThread(void *sec, size_t stack, void *fn, LPVOID arg, DWORD flags, DWORD *id); HANDLE CreateProcess(LPCWSTR app, LPWSTR cmd, void *pa, void *ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, void *si, void *pi);
DWORD WaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL waitall, DWORD ms); BOOL GetExitCodeProcess(HANDLE h, DWORD *code);
int MessageBox(HANDLE wnd, LPCWSTR text, LPCWSTR caption, UINT type); HANDLE HeapAlloc(HANDLE heap, DWORD flags, size_t n); BOOL HeapFree(HANDLE heap, DWORD flags, LPVOID p);
HANDLE GetProcessHeap(void); BOOL IsDebuggerPresent(void); DWORD WaitForSingleObject(HANDLE h, DWORD ms); LONG RegOpenKeyEx(HANDLE key, LPCWSTR sub, DWORD opt, DWORD sam, HANDLE *out);
int WSAStartup(WORD ver, void *data); int closesocket(int s);
"#;

/// Replaces whole-word occurrences of `from` in `text`.
pub fn replace_word(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let f = from.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hit = b[i..].starts_with(f)
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            && b.get(i + f.len()).map(|c| !(c.is_ascii_alphanumeric() || *c == b'_')).unwrap_or(true);
        if hit {
            out.push_str(to);
            i += f.len();
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prototypes() {
        let (p, e) = parse("int open(const char *path, int flags, ...); void exit(int s) noreturn; char *strdup(const char *);");
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(p[0].name, "open");
        assert_eq!(p[0].params.len(), 2);
        assert_eq!(p[0].params[0].1, "path");
        assert!(p[0].variadic);
        assert!(p[1].noreturn);
        assert_eq!(p[2].params[0].0.replace(' ', ""), "constchar*");
    }

    #[test]
    fn preserves_named_function_pointer_parameters() {
        let (p, e) = parse("void register_cb(int (*callback)(int, void *));");
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(p[0].params[0].1, "callback");
        assert_eq!(p[0].signature(), "void register_cb(int (*callback)(int, void *))");
    }

    #[test]
    fn resolves_function_pointer_typedef_parameters() {
        let (p, e) = parse("typedef int (*callback_t)(int, void *); typedef callback_t callback_alias_t; void register_cb(callback_alias_t cb); callback_t get_cb(void);");
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(p[0].params[0].0, "int (*)(int, void *)");
        assert_eq!(p[1].ret, "int (*)(int, void *)");
    }

    #[test]
    fn parses_common_noreturn_attributes() {
        let (p, e) = parse("__attribute__((noreturn)) void die(void); [[noreturn]] void halt(void); __attribute__((__noreturn__)) void abort2(void); [[gnu::noreturn]] void halt2(void);");
        assert!(e.is_empty(), "{e:?}");
        assert!(p.iter().all(|proto| proto.noreturn));
    }

    #[test]
    fn library_loads_and_normalises_names() {
        assert!(builtin_count() > 150);
        assert_eq!(find("_memcpy").unwrap().params.len(), 3);
        assert_eq!(find("__imp_CreateFileW").unwrap().params.len(), 7);
        assert!(find("exit").unwrap().noreturn);
        assert!(find("no_such_function_xyz").is_none());
        assert_eq!(find("operator new").unwrap().ret, "void *");
        assert_eq!(find("operator delete").unwrap().params.len(), 1);
        assert_eq!(find("operator new[]").unwrap().ret, "void *");
        assert_eq!(find("operator delete[]").unwrap().params.len(), 1);
        assert_eq!(find("__cxa_begin_catch").unwrap().ret, "void *");
        assert!(find("__cxa_pure_virtual").unwrap().noreturn);
        assert_eq!(find("__cxa_guard_acquire").unwrap().ret, "int");
        assert_eq!(find("__cxa_guard_release").unwrap().params.len(), 1);
        assert_eq!(find("__cxa_vec_new").unwrap().ret, "void *");
        assert_eq!(find("__cxa_vec_delete").unwrap().params.len(), 4);
        assert_eq!(find("pread").unwrap().params.len(), 4);
        assert_eq!(find("pwrite").unwrap().params.len(), 4);
        assert_eq!(find("readv").unwrap().params.len(), 3);
        assert_eq!(find("writev").unwrap().params.len(), 3);
        assert_eq!(find("realpath").unwrap().ret, "char *");
        assert_eq!(find("strerror_r").unwrap().params.len(), 3);
        assert_eq!(find("memset_s").unwrap().params.len(), 4);
        assert_eq!(find("memccpy").unwrap().params.len(), 4);
        assert_eq!(find("__cxa_vec_ctor").unwrap().params.len(), 4);
        assert_eq!(find("__cxa_vec_dtor").unwrap().params.len(), 4);
        assert_eq!(find("__cxa_vec_new2").unwrap().params.len(), 6);
        assert_eq!(find("__cxa_vec_delete2").unwrap().params.len(), 5);
        assert_eq!(find("__cxa_vec_new3").unwrap().params.len(), 6);
        assert_eq!(find("__cxa_vec_delete3").unwrap().params.len(), 5);
        assert!(find("__cxa_bad_alloc").unwrap().noreturn);
        assert!(find("__cxa_throw_bad_array_new_length").unwrap().noreturn);
        assert!(find("__cxa_call_unexpected").unwrap().noreturn);
        assert_eq!(find("GetFileSizeEx").unwrap().params.len(), 2);
        assert_eq!(find("SetFilePointerEx").unwrap().params.len(), 4);
        assert_eq!(find("ReadFileEx").unwrap().params.len(), 5);
        assert_eq!(find("CreateFileMappingW").unwrap().params.len(), 6);
        assert_eq!(find("MapViewOfFile").unwrap().params.len(), 5);
        assert_eq!(find("UnmapViewOfFile").unwrap().params.len(), 1);
        assert_eq!(find("WaitForMultipleObjects").unwrap().params.len(), 4);
        assert_eq!(find("GetExitCodeProcess").unwrap().params.len(), 2);
        assert_eq!(find("freeaddrinfo").unwrap().params.len(), 1);
        assert_eq!(find("getnameinfo").unwrap().params.len(), 7);
        assert_eq!(find("inet_ntop").unwrap().params.len(), 4);
        assert_eq!(find("poll").unwrap().params.len(), 3);
        assert_eq!(find("epoll_create1").unwrap().params.len(), 1);
        assert_eq!(find("epoll_ctl").unwrap().params.len(), 4);
        assert_eq!(find("epoll_wait").unwrap().params.len(), 4);
        assert_eq!(find("pthread_cond_wait").unwrap().params.len(), 2);
        assert_eq!(find("pthread_cond_broadcast").unwrap().params.len(), 1);
        assert_eq!(find("pthread_rwlock_wrlock").unwrap().params.len(), 1);
        assert_eq!(find("sem_init").unwrap().params.len(), 3);
        assert_eq!(find("sem_post").unwrap().params.len(), 1);
        assert_eq!(find("pthread_attr_setstacksize").unwrap().params.len(), 2);
        assert_eq!(find("dladdr").unwrap().params.len(), 2);
        assert_eq!(find("dlerror").unwrap().ret, "char *");
        assert_eq!(find("dlvsym").unwrap().params.len(), 3);
        assert_eq!(find("sigprocmask").unwrap().params.len(), 3);
        assert_eq!(find("sigemptyset").unwrap().params.len(), 1);
        assert_eq!(find("sigaddset").unwrap().params.len(), 2);
        assert_eq!(find("raise").unwrap().params.len(), 1);
        assert_eq!(find("killpg").unwrap().params.len(), 2);
        assert_eq!(find("posix_spawn").unwrap().params.len(), 6);
        assert_eq!(find("posix_spawnp").unwrap().params.len(), 6);
        assert_eq!(find("waitid").unwrap().params.len(), 4);
        assert_eq!(find("getrusage").unwrap().params.len(), 2);
        assert_eq!(find("setsid").unwrap().params.len(), 0);
        assert_eq!(find("setpgid").unwrap().params.len(), 2);
        assert_eq!(find("clock_gettime").unwrap().params.len(), 2);
        assert_eq!(find("clock_getres").unwrap().params.len(), 2);
    }

    #[test]
    fn word_replace() {
        assert_eq!(replace_word("a1 + a10 + (a1)", "a1", "key"), "key + a10 + (key)");
    }
}
