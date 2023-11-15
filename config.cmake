cmake_minimum_required(VERSION 3.10)

# CMake preprocessor variables based on the provided checks

# Define if building universal (internal helper macro)
if(AC_APPLE_UNIVERSAL_BUILD)
    add_compile_definitions(-DAC_APPLE_UNIVERSAL_BUILD)
endif()

# define to use both <string.h> and <strings.h>
if(BOTH_STRINGS_H)
    add_compile_definitions(-DBOTH_STRINGS_H)
endif()

# define if cross compiling
if(CROSS_COMPILING)
    add_compile_definitions(-DCROSS_COMPILING)
endif()

# set to the number of arguments ctime_r() expects
if(CTIME_R_NARGS)
    add_compile_definitions(-DCTIME_R_NARGS)
endif()

# define if toupper() requires islower()
if(C_UPPER_LOWER)
    add_compile_definitions(-DC_UPPER_LOWER)
endif()

# define if sys_errlist is not declared in stdio.h or errno.h
if(DECL_SYS_ERRLIST)
    add_compile_definitions(-DDECL_SYS_ERRLIST)
endif()

# define to enable slapi library
if(ENABLE_SLAPI)
    add_compile_definitions(-DENABLE_SLAPI)
endif()

# defined to be the EXE extension
if(EXEEXT)
    add_compile_definitions(-DEXEEXT)
endif()

# set to the number of arguments gethostbyaddr_r() expects
if(GETHOSTBYADDR_R_NARGS)
    add_compile_definitions(-DGETHOSTBYADDR_R_NARGS)
endif()

# set to the number of arguments gethostbyname_r() expects
if(GETHOSTBYNAME_R_NARGS)
    add_compile_definitions(-DGETHOSTBYNAME_R_NARGS)
endif()

# Define to 1 if `TIOCGWINSZ' requires <sys/ioctl.h>.
if(GWINSZ_IN_SYS_IOCTL)
    add_compile_definitions(-DGWINSZ_IN_SYS_IOCTL)
endif()

# define if you have AIX security lib
if(HAVE_AIX_SECURITY)
    add_compile_definitions(-DHAVE_AIX_SECURITY)
endif()

if(WIN32)
    add_compile_definitions(ber_socklen_t "int")
else()
    add_compile_definitions(ber_socklen_t "int")
endif()

CHECK_INCLUDE_FILE("filio.h" HAVE_FILIO_H)
CHECK_FUNCTION_EXISTS(flock HAVE_FLOCK)
CHECK_FUNCTION_EXISTS(fmemopen HAVE_FMEMOPEN)

# Define to 1 if you have the `fstat' function.
check_function_exists(fstat HAVE_FSTAT)

# Define to 1 if you have the `gai_strerror' function.
check_function_exists(gai_strerror HAVE_GAI_STRERROR)

# Define to 1 if you have the `getaddrinfo' function.
check_function_exists(getaddrinfo HAVE_GETADDRINFO)

# Define to 1 if you have the `getdtablesize' function.
check_function_exists(getdtablesize HAVE_GETDTABLESIZE)

# Define to 1 if you have the `geteuid' function.
check_function_exists(geteuid HAVE_GETEUID)

# Define to 1 if you have the `getgrgid' function.
check_function_exists(getgrgid HAVE_GETGRGID)

# Define to 1 if you have the `gethostbyaddr_r' function.
check_function_exists(gethostbyaddr_r HAVE_GETHOSTBYADDR_R)

# Define to 1 if you have the `gethostbyname_r' function.
check_function_exists(gethostbyname_r HAVE_GETHOSTBYNAME_R)

# Define to 1 if you have the `gethostname' function.
check_function_exists(gethostname HAVE_GETHOSTNAME)

# Define to 1 if you have the `getnameinfo' function.
check_function_exists(getnameinfo HAVE_GETNAMEINFO)

# Define to 1 if you have the `getopt' function.
check_function_exists(getopt HAVE_GETOPT)

# Define to 1 if you have the <getopt.h> header file.
check_include_file(getopt.h HAVE_GETOPT_H)

# Define to 1 if you have the `getpassphrase' function.
check_function_exists(getpassphrase HAVE_GETPASSPHRASE)

# Define to 1 if you have the `getpeereid' function.
check_function_exists(getpeereid HAVE_GETPEEREID)

# Define to 1 if you have the `getpeerucred' function.
check_function_exists(getpeerucred HAVE_GETPEERUCRED)

# Define to 1 if you have the `getpwnam' function.
check_function_exists(getpwnam HAVE_GETPWNAM)

# Define to 1 if you have the `getpwuid' function.
check_function_exists(getpwuid HAVE_GETPWUID)

# Define to 1 if you have the `getspnam' function.
check_function_exists(getspnam HAVE_GETSPNAM)

# Define to 1 if you have the `gettimeofday' function.
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)

# Define to 1 if you have the <gmp.h> header file.
check_include_file(gmp.h HAVE_GMP_H)

# Define to 1 if you have the `gmtime_r' function.
check_function_exists(gmtime_r HAVE_GMTIME_R)

# Define if you have GNUtls.
find_package(GnuTLS)
if(GNUTLS_FOUND)
  set(HAVE_GNUTLS 1)
endif()

# Define to 1 if you have the <gnutls/gnutls.h> header file.
check_include_file(gnutls/gnutls.h HAVE_GNUTLS_GNUTLS_H)

# if you have GNU Pth
find_package(Pth)
if(Pth_FOUND)
  set(HAVE_GNU_PTH 1)
endif()

# Define if you have OpenSSL.
find_package(OpenSSL)
if(OPENSSL_FOUND)
  set(HAVE_OPENSSL 1)
  set(HAVE_OPENSSL_BN_H yes)
  set(HAVE_OPENSSL_CRYPTO_H yes)
  set(HAVE_OPENSSL_SSL_H yes)
endif()

# Define to 1 if you have the <grp.h> header file.
check_include_file(grp.h HAVE_GRP_H)

# Define to 1 if you have the `hstrerror' function.
check_function_exists(hstrerror HAVE_HSTRERROR)

# Define to you if inet_aton(3) is available.
check_function_exists(inet_aton HAVE_INET_ATON)

# Define to 1 if you have the `inet_ntoa_b' function.
check_function_exists(inet_ntoa_b HAVE_INET_NTOA_B)

# Define to 1 if you have the `inet_ntop' function.
check_function_exists(inet_ntop HAVE_INET_NTOP)

# Define to 1 if you have the `initgroups' function.
check_function_exists(initgroups HAVE_INITGROUPS)

# Define to 1 if you have the <inttypes.h> header file.
check_include_file(inttypes.h HAVE_INTTYPES_H)

# Define to 1 if you have the `ioctl' function.
check_function_exists(ioctl HAVE_IOCTL)

# Define to 1 if you have the <io.h> header file.
check_include_file(io.h HAVE_IO_H)

# Define if your system supports kqueue.
check_symbol_exists(kqueue "" HAVE_KQUEUE)

# Define if you have libargon2.
check_library_exists(argon2 argon2i_hash_password argon2.h HAVE_LIBARGON2)

# Define if you have -levent.
check_library_exists(event event_base_new event.h HAVE_LIBEVENT)

# Define to 1 if you have the `gen' library (-lgen).
check_library_exists(gen main "" HAVE_LIBGEN)

# Define to 1 if you have the `gmp' library (-lgmp).
check_library_exists(gmp __gmpz_init "" HAVE_LIBGMP)

# Define to 1 if you have the `inet' library (-linet).
check_library_exists(inet main "" HAVE_LIBINET)

# Define to 1 if you have the `inet' library (-lnet).
check_library_exists(net main "" HAVE_LIBNET)

# Define to 1 if you have the `nsl' library (-lnsl).
check_library_exists(nsl main "" HAVE_LIBNSL)

# Define to 1 if you have the `nsl_s' library (-lnsl_s).
check_library_exists(nsl_s main "" HAVE_LIBNSL_S)

# Define to 1 if you have the `socket' library (-lsocket).
check_library_exists(socket main "" HAVE_LIBSOCKET)

# Define if you have libsodium.
check_library_exists(sodium sodium_init "" HAVE_LIBSODIUM)

# Define to 1 if you have the <libutil.h> header file.
check_include_file(libutil.h HAVE_LIBUTIL_H)

# Define to 1 if you have the `V3' library (-lV3).
check_library_exists(V3 __init__ "" HAVE_LIBV3)

# Define to 1 if you have the <limits.h> header file.
check_include_file(limits.h HAVE_LIMITS_H)

# If you have LinuxThreads.
check_symbol_exists(LinuxThreads "" HAVE_LINUX_THREADS)

# Define to 1 if you have the <locale.h> header file.
check_include_file(locale.h HAVE_LOCALE_H)

# Define to 1 if you have the `localtime_r' function.
check_function_exists(localtime_r HAVE_LOCALTIME_R)

# Define to 1 if you have the `lockf' function.
check_function_exists(lockf HAVE_LOCKF)

# Define to 1 if the system has the type `long long'.
check_type_size("long long" HAVE_LONG_LONG)

# Define to 1 if you have the <ltdl.h> header file.
check_include_file(ltdl.h HAVE_LTDL_H)

# Define to 1 if you have the <malloc.h> header file.
check_include_file(malloc.h HAVE_MALLOC_H)

# Define to 1 if you have the `memcpy' function.
check_function_exists(memcpy HAVE_MEMCPY)

# Define to 1 if you have the `memmove' function.
check_function_exists(memmove HAVE_MEMMOVE)

# Define to 1 if you have the <memory.h> header file.
check_include_file(memory.h HAVE_MEMORY_H)

# Define to 1 if you have the `memrchr' function.
check_function_exists(memrchr HAVE_MEMRCHR)

# Define to 1 if you have the `mkstemp' function.
check_function_exists(mkstemp HAVE_MKSTEMP)

# Define to 1 if you have the `mktemp' function.
check_function_exists(mktemp HAVE_MKTEMP)

# Define this if you have mkversion.
check_symbol_exists(mkversion "" HAVE_MKVERSION)

# Define to 1 if you have the <ndir.h> header file, and it defines `DIR'.
check_include_file(ndir.h HAVE_NDIR_H)

# Define to 1 if you have the <netinet/tcp.h> header file.
check_include_file(netinet/tcp.h HAVE_NETINET_TCP_H)

# Define if strerror_r returns char* instead of int.
check_symbol_exists(strerror_r "string.h" HAVE_NONPOSIX_STRERROR_R)

# If you have NT Event Log.
check_symbol_exists(NTEventLog "" HAVE_NT_EVENT_LOG)

# If you have NT Service Manager.
check_symbol_exists(NTServiceManager "" HAVE_NT_SERVICE_MANAGER)

# If you have NT Threads.
check_symbol_exists(NTThreads "" HAVE_NT_THREADS)

# Define to 1 if you have the `pipe' function.
check_function_exists(pipe HAVE_PIPE)

# Define to 1 if you have the `poll' function.
check_function_exists(poll HAVE_POLL)

# Define to 1 if you have the <poll.h> header file.
check_include_file(poll.h HAVE_POLL_H)

# Define to 1 if you have the <process.h> header file.
check_include_file(process.h HAVE_PROCESS_H)

# Define to 1 if you have the <psap.h> header file.
check_include_file(psap.h HAVE_PSAP_H)

# Define to pthreads API spec revision.
check_symbol_exists(PTHREADS "" HAVE_PTHREADS)

# Define if you have pthread_detach function.
check_symbol_exists(pthread_detach "pthread.h" HAVE_PTHREAD_DETACH)

# Define to 1 if you have the `pthread_getconcurrency' function.
check_function_exists(pthread_getconcurrency HAVE_PTHREAD_GETCONCURRENCY)

# Define to 1 if you have the <pthread.h> header file.
check_include_file(pthread.h HAVE_PTHREAD_H)

# Define to 1 if you have the `pthread_kill' function.
check_function_exists(pthread_kill HAVE_PTHREAD_KILL)

# Define to 1 if you have the `pthread_kill_other_threads_np' function.
check_function_exists(pthread_kill_other_threads_np HAVE_PTHREAD_KILL_OTHER_THREADS_NP)

# Define if you have pthread_rwlock_destroy function.
check_symbol_exists(pthread_rwlock_destroy "pthread.h" HAVE_PTHREAD_RWLOCK_DESTROY)

# Define to 1 if you have the `pthread_setconcurrency' function.
check_function_exists(pthread_setconcurrency HAVE_PTHREAD_SETCONCURRENCY)

# Define to 1 if you have the `pthread_yield' function.
check_function_exists(pthread_yield HAVE_PTHREAD_YIELD)

# Define to 1 if you have the <pth.h> header file.
check_include_file(pth.h HAVE_PTH_H)

# Define to 1 if the system has the type `ptrdiff_t'.
check_type_size("ptrdiff_t" HAVE_PTRDIFF_T)

# Define to 1 if you have the <pwd.h> header file.
check_include_file(pwd.h HAVE_PWD_H)

# Define to 1 if you have the `read' function.
check_function_exists(read HAVE_READ)

# Define to 1 if you have the `recv' function.
check_function_exists(recv HAVE_RECV)

# Define to 1 if you have the `recvfrom' function.
check_function_exists(recvfrom HAVE_RECVFROM)

# Define to 1 if you have the <regex.h> header file.
check_include_file(regex.h HAVE_REGEX_H)

# Define to 1 if you have the <resolv.h> header file.
check_include_file(resolv.h HAVE_RESOLV_H)

# Define if you have res_query().
check_symbol_exists(res_query "resolv.h" HAVE_RES_QUERY)

# Define to 1 if you have the <sasl.h> header file.
check_include_file(sasl.h HAVE_SASL_H)

# Define to 1 if you have the <sasl/sasl.h> header file.
check_include_file(sasl/sasl.h HAVE_SASL_SASL_H)

# Define if your SASL library has sasl_version().
check_function_exists(sasl_version HAVE_SASL_VERSION)

# Define to 1 if you have the <sched.h> header file.
check_include_file(sched.h HAVE_SCHED_H)

# Define to 1 if you have the `sched_yield' function.
check_function_exists(sched_yield HAVE_SCHED_YIELD)

# Define to 1 if you have the `send' function.
check_function_exists(send HAVE_SEND)

# Define to 1 if you have the `sendmsg' function.
check_function_exists(sendmsg HAVE_SENDMSG)

# Define to 1 if you have the `sendto' function.
check_function_exists(sendto HAVE_SENDTO)

# Define to 1 if you have the `setegid' function.
check_function_exists(setegid HAVE_SETEGID)

# Define to 1 if you have the `seteuid' function.
check_function_exists(seteuid HAVE_SETEUID)

# Define to 1 if you have the `setgid' function.
check_function_exists(setgid HAVE_SETGID)

# Define to 1 if you have the `setpwfile' function.
check_function_exists(setpwfile HAVE_SETPWFILE)

# Define to 1 if you have the `setsid' function.
check_function_exists(setsid HAVE_SETSID)

# Define to 1 if you have the `setuid' function.
check_function_exists(setuid HAVE_SETUID)

# Define to 1 if you have the <sgtty.h> header file.
check_include_file(sgtty.h HAVE_SGTTY_H)

# Define to 1 if you have the <shadow.h> header file.
check_include_file(shadow.h HAVE_SHADOW_H)

# Define to 1 if you have the `sigaction' function.
check_function_exists(sigaction HAVE_SIGACTION)

# Define to 1 if you have the `signal' function.
check_function_exists(signal HAVE_SIGNAL)

# Define to 1 if you have the `sigset' function.
check_function_exists(sigset HAVE_SIGSET)

# Define if you have -lslp.
check_library_exists(slp slp_open slp.h HAVE_SLP)

# Define to 1 if you have the <slp.h> header file.
check_include_file(slp.h HAVE_SLP_H)

# Define to 1 if you have the `snprintf' function.
check_function_exists(snprintf HAVE_SNPRINTF)

# Define to 1 if you have the <sodium.h> header file.
check_include_file(sodium.h HAVE_SODIUM_H)

# Define if you have spawnlp().
check_symbol_exists(spawnlp "" HAVE_SPAWNLP)

# Define to 1 if you have the <sqlext.h> header file.
check_include_file(sqlext.h HAVE_SQLEXT_H)

# Define to 1 if you have the <sql.h> header file.
check_include_file(sql.h HAVE_SQL_H)

# Define to 1 if you have the <stddef.h> header file.
check_include_file(stddef.h HAVE_STDDEF_H)

# Define to 1 if you have the <stdint.h> header file.
check_include_file(stdint.h HAVE_STDINT_H)

# Define to 1 if you have the <stdlib.h> header file.
check_include_file(stdlib.h HAVE_STDLIB_H)

# Define to 1 if you have the `strdup' function.
check_function_exists(strdup HAVE_STRDUP)

# Define to 1 if you have the `strerror' function.
check_function_exists(strerror HAVE_STRERROR)

# Define to 1 if you have the `strerror_r' function.
check_function_exists(strerror_r HAVE_STRERROR_R)

# Define to 1 if you have the `strftime' function.
check_function_exists(strftime HAVE_STRFTIME)

# Define to 1 if you have the <strings.h> header file.
check_include_file(strings.h HAVE_STRINGS_H)

# Define to 1 if you have the <string.h> header file.
check_include_file(string.h HAVE_STRING_H)

# Define to 1 if you have the `strpbrk' function.
check_function_exists(strpbrk HAVE_STRPBRK)

# Define to 1 if you have the `strrchr' function.
check_function_exists(strrchr HAVE_STRRCHR)

# Define to 1 if you have the `strsep' function.
check_function_exists(strsep HAVE_STRSEP)

# Define to 1 if you have the `strspn' function.
check_function_exists(strspn HAVE_STRSPN)

# Define to 1 if you have the `strstr' function.
check_function_exists(strstr HAVE_STRSTR)

# Define to 1 if you have the `strtol' function.
check_function_exists(strtol HAVE_STRTOL)

# Define to 1 if you have the `strtoll' function.
check_function_exists(strtoll HAVE_STRTOLL)

# Define to 1 if you have the `strtoq' function.
check_function_exists(strtoq HAVE_STRTOQ)

# Define to 1 if you have the `strtoul' function.
check_function_exists(strtoul HAVE_STRTOUL)

# Define to 1 if you have the `strtoull' function.
check_function_exists(strtoull HAVE_STRTOULL)

# Define to 1 if you have the `strtoq' function.
check_function_exists(strtoq HAVE_STRTOQ)

# Define to 1 if `msg_accrightslen' is a member of `struct msghdr'.
check_symbol_exists(msg_accrightslen "sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTSLEN)

# Define to 1 if `msg_control' is a member of `struct msghdr'.
check_symbol_exists(msg_control "sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_CONTROL)

# Define to 1 if `pw_gecos' is a member of `struct passwd'.
check_symbol_exists(pw_gecos "pwd.h" HAVE_STRUCT_PASSWD_PW_GECOS)

# Define to 1 if `pw_passwd' is a member of `struct passwd'.
check_symbol_exists(pw_passwd "pwd.h" HAVE_STRUCT_PASSWD_PW_PASSWD)

# Define to 1 if `st_blksize' is a member of `struct stat'.
check_symbol_exists(st_blksize "sys/stat.h" HAVE_STRUCT_STAT_ST_BLKSIZE)

# Define to 1 if `st_fstype' is a member of `struct stat'.
check_symbol_exists(st_fstype "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE)

# Define to 1 if `st_fstype' is char *.
check_symbol_exists(st_fstype_char "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE_CHAR)

# Define to 1 if `st_fstype' is int.
check_symbol_exists(st_fstype_int "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE_INT)

# Define to 1 if `st_vfstype' is a member of `struct stat'.
check_symbol_exists(st_vfstype "sys/stat.h" HAVE_STRUCT_STAT_ST_VFSTYPE)

# Define to 1 if you have the <synch.h> header file.
check_include_file(synch.h HAVE_SYNCH_H)

# Define to 1 if you have the `sysconf' function.
check_function_exists(sysconf HAVE_SYSCONF)

# Define to 1 if you have the <sysexits.h> header file.
check_include_file(sysexits.h HAVE_SYSEXITS_H)

# Define to 1 if you have the <syslog.h> header file.
check_include_file(syslog.h HAVE_SYSLOG_H)

# Define to 1 if you have the <syslog.h> header file.
check_include_file(syslog.h HAVE_SYSLOG_H)

# Define if you have systemd.
check_library_exists(systemd sd_listen_fds "systemd/sdaemon.h" HAVE_SYSTEMD)

# Define to 1 if you have the <systemd/sdaemon.h> header file.
check_include_file(systemd/sdaemon.h HAVE_SYSTEMD_SD_DAEMON_H)

# Define to 1 if you have the <sys/devpoll.h> header file.
check_include_file(sys/devpoll.h HAVE_SYS_DEVPOLL_H)

# Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
check_include_file(sys/dir.h HAVE_SYS_DIR_H)

# Define to 1 if you have the <sys/epoll.h> header file.
check_include_file(sys/epoll.h HAVE_SYS_EPOLL_H)

# Define if you actually have sys_errlist in your libs.
check_symbol_exists(sys_errlist "stdlib.h" HAVE_SYS_ERRLIST)

# Define to 1 if you have the <sys/errno.h> header file.
check_include_file(sys/errno.h HAVE_SYS_ERRNO_H)

# Define to 1 if you have the <sys/event.h> header file.
check_include_file(sys/event.h HAVE_SYS_EVENT_H)

# Define to 1 if you have the <sys/file.h> header file.
check_include_file(sys/file.h HAVE_SYS_FILE_H)

# Define to 1 if you have the <sys/filio.h> header file.
check_include_file(sys/filio.h HAVE_SYS_FILIO_H)

# Define to 1 if you have the <sys/fstyp.h> header file.
check_include_file(sys/fstyp.h HAVE_SYS_FSTYP_H)

# Define to 1 if you have the <sys/ioctl.h> header file.
check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)

# Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
check_include_file(sys/ndir.h HAVE_SYS_NDIR_H)

# Define to 1 if you have the <sys/param.h> header file.
check_include_file(sys/param.h HAVE_SYS_PARAM_H)

# Define to 1 if you have the <sys/poll.h> header file.
check_include_file(sys/poll.h HAVE_SYS_POLL_H)

# Define to 1 if you have the <sys/privgrp.h> header file.
check_include_file(sys/privgrp.h HAVE_SYS_PRIVGRP_H)

# Define to 1 if you have the <sys/resource.h> header file.
check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)

# Define to 1 if you have the <sys/select.h> header file.
check_include_file(sys/select.h HAVE_SYS_SELECT_H)

# Define to 1 if you have the <sys/socket.h> header file.
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)

# Define to 1 if you have the <sys/stat.h> header file.
check_include_file(sys/stat.h HAVE_SYS_STAT_H)

# Define to 1 if you have the <sys/syslog.h> header file.
check_include_file(sys/syslog.h HAVE_SYS_SYSLOG_H)

# Define to 1 if you have the <sys/time.h> header file.
check_include_file(sys/time.h HAVE_SYS_TIME_H)

# Define to 1 if you have the <sys/types.h> header file.
check_include_file(sys/types.h HAVE_SYS_TYPES_H)

# Define to 1 if you have the <sys/ucred.h> header file.
check_include_file(sys/ucred.h HAVE_SYS_UCRED_H)

# Define to 1 if you have the <sys/uio.h> header file.
check_include_file(sys/uio.h HAVE_SYS_UIO_H)

# Define to 1 if you have the <sys/un.h> header file.
check_include_file(sys/un.h HAVE_SYS_UN_H)

# Define to 1 if you have the <sys/uuid.h> header file.
check_include_file(sys/uuid.h HAVE_SYS_UUID_H)

# Define to 1 if you have the <sys/vmount.h> header file.
check_include_file(sys/vmount.h HAVE_SYS_VMOUNT_H)

# Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible.
check_include_file(sys/wait.h HAVE_SYS_WAIT_H)

# Define if you have -lwrap.
check_library_exists(wrap hosts_access "tcpd.h" HAVE_TCPD)

# Define to 1 if you have the <tcpd.h> header file.
check_include_file(tcpd.h HAVE_TCPD_H)

# Define to 1 if you have the <termios.h> header file.
check_include_file(termios.h HAVE_TERMIOS_H)

# If you have Solaris LWP (thr) package.
check_symbol_exists(thr "thread.h" HAVE_THR)

# Define to 1 if you have the <thread.h> header file.
check_include_file(thread.h HAVE_THREAD_H)

# Define to 1 if you have the `thr_getconcurrency' function.
check_function_exists(thr_getconcurrency HAVE_THR_GETCONCURRENCY)

# Define to 1 if you have the `thr_setconcurrency' function.
check_function_exists(thr_setconcurrency HAVE_THR_SETCONCURRENCY)

# Define to 1 if you have the `thr_yield' function.
check_function_exists(thr_yield HAVE_THR_YIELD)

# Define if you have TLS.
check_symbol_exists(TLS "" HAVE_TLS)

# Define to 1 if you have the <unistd.h> header file.
check_include_file(unistd.h HAVE_UNISTD_H)

# Define to 1 if you have the <utime.h> header file.
check_include_file(utime.h HAVE_UTIME_H)

# Define if you have uuid_generate().
check_function_exists(uuid_generate HAVE_UUID_GENERATE)

# Define if you have uuid_to_str().
check_function_exists(uuid_to_str HAVE_UUID_TO_STR)

# Define to 1 if you have the <uuid/uuid.h> header file.
check_include_file(uuid/uuid.h HAVE_UUID_UUID_H)

# Define to 1 if you have the `vprintf' function.
check_function_exists(vprintf HAVE_VPRINTF)

# Define to 1 if you have the `vsnprintf' function.
check_function_exists(vsnprintf HAVE_VSNPRINTF)

# Define to 1 if you have the `wait4' function.
check_function_exists(wait4 HAVE_WAIT4)

# Define to 1 if you have the `waitpid' function.
check_function_exists(waitpid HAVE_WAITPID)

# Define if you have winsock.
check_library_exists(ws2_32 WSAStartup "winsock.h" HAVE_WINSOCK)

# Define if you have winsock2.
check_library_exists(ws2_32 WSAStartup "winsock2.h" HAVE_WINSOCK2)

# Define to 1 if you have the <winsock2.h> header file.
check_include_file(winsock2.h HAVE_WINSOCK2_H)

# Define to 1 if you have the <winsock.h> header file.
check_include_file(winsock.h HAVE_WINSOCK_H)

# Define to 1 if you have the `write' function.
check_function_exists(write HAVE_WRITE)

# Define if select implicitly yields.
check_symbol_exists(select_imp_yields "" HAVE_YIELDING_SELECT)

# Define to 1 if you have the `_vsnprintf' function.
check_function_exists(_vsnprintf HAVE__VSNPRINTF)

# Define to 32-bit or greater integer type.
check_type_size("int" LBER_INT_T)

# Define to large integer type.
check_type_size("long long" LBER_LEN_T)

# Define to socket descriptor type.
check_type_size("int" LBER_SOCKET_T)

# Define to large integer type.
check_type_size("long long" LBER_TAG_T)

# Define to 1 if library is reentrant.
set(LDAP_API_FEATURE_X_OPENLDAP_REENTRANT 1)

# Define to 1 if library is thread-safe.
set(LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE 1)

# Define to LDAP VENDOR VERSION.
set(LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS "2.5.16")

# Define this to add debugging code.
set(LDAP_DEBUG 1)

# Define if LDAP libs are dynamic.
set(LDAP_LIBS_DYNAMIC 1)

# Define to support PF_INET6.
set(LDAP_PF_INET6 1)

# Define to support PF_LOCAL.
set(LDAP_PF_LOCAL 1)

# Define this to add SLAPI code.
set(LDAP_SLAPI 1)

# Define this to add syslog code.
set(LDAP_SYSLOG 1)

# Version.
set(LDAP_VENDOR_VERSION "2.5.16")

# Major.
set(LDAP_VENDOR_VERSION_MAJOR "2")

# Minor.
set(LDAP_VENDOR_VERSION_MINOR "5")

# Patch.
set(LDAP_VENDOR_VERSION_PATCH "16")

# Define if sched_yield yields the entire process.
set(REPLACE_BROKEN_YIELD 1)

# Define as the return type of signal handlers (int or void).
set(RET_SIGTYPE int)

# Define to the type of arg 1 for select.
set(SELECT_TYPE_ARG1 int)

# Define to the type of args 2, 3, and 4 for select.
set(SELECT_TYPE_ARG234 int)

# Define to the type of arg 5 for select.
set(SELECT_TYPE_ARG5 socklen_t)

# The size of int, as computed by sizeof.
set(SIZEOF_INT 4)

# The size of long, as computed by sizeof.
set(SIZEOF_LONG 4)

# The size of long long, as computed by sizeof.
set(SIZEOF_LONG_LONG 8)

# The size of short, as computed by sizeof.
set(SIZEOF_SHORT 2)

# The size of wchar_t, as computed by sizeof.
set(SIZEOF_WCHAR_T 4)

# Define to support per-object ACIs.
set(SLAPD_ACI_ENABLED 1)

# Define to support LDAP Async Metadirectory backend.
set(SLAPD_ASYNCMETA 1)

# Define to support cleartext passwords.
set(SLAPD_CLEARTEXT 1)

# Define to support crypt(3) passwords.
set(SLAPD_CRYPT 1)

# Define to support DNS SRV backend.
set(SLAPD_DNSSRV 1)

# Define to support LDAP backend.
set(SLAPD_LDAP 1)

# Define to support MDB backend.
set(SLAPD_MDB 1)

# Define to support LDAP Metadirectory backend.
set(SLAPD_META 1)

# Define to support modules.
set(SLAPD_MODULES 1)

# Dynamically linked module.
set(SLAPD_MOD_DYNAMIC 1)

# Statically linked module.
set(SLAPD_MOD_STATIC 1)

# Define to support NDB backend.
set(SLAPD_NDB 1)

# Define to support NULL backend.
set(SLAPD_NULL 1)

# Define for Inirectory Access Logging overlay.
set(SLAPD_OVER_ACCESSLOG 1)

# Define for Audit Logging overlay.
set(SLAPD_OVER_AUDITLOG 1)

# Define for Automatic Certificate Authority overlay.
set(SLAPD_OVER_AUTOCA 1)

# Define for Collect overlay.
set(SLAPD_OVER_COLLECT 1)

# Define for Attribute Constraint overlay.
set(SLAPD_OVER_CONSTRAINT 1)

# Define for Dynamic Directory Services overlay.
set(SLAPD_OVER_DDS 1)

# Define for Dynamic Directory Services overlay.
set(SLAPD_OVER_DEREF 1)

# Define for Dynamic Group overlay.
set(SLAPD_OVER_DYNGROUP 1)

# Define for Dynamic List overlay.
set(SLAPD_OVER_DYNLIST 1)

# Define for Home Directory Management overlay.
set(SLAPD_OVER_HOMEDIR 1)

# Define for Reverse Group Membership overlay.
set(SLAPD_OVER_MEMBEROF 1)

# Define for OTP 2-factor Authentication overlay.
set(SLAPD_OVER_OTP 1)

# Define for Password Policy overlay.
set(SLAPD_OVER_PPOLICY 1)

# Define for Proxy Cache overlay.
set(SLAPD_OVER_PROXYCACHE 1)

# Define for Referential Integrity overlay.
set(SLAPD_OVER_REFINT 1)

# Define for Deferred Authentication overlay.
set(SLAPD_OVER_REMOTEAUTH 1)

# Define for Return Code overlay.
set(SLAPD_OVER_RETCODE 1)

# Define for Rewrite/Remap overlay.
set(SLAPD_OVER_RWM 1)

# Define for Sequential Modify overlay.
set(SLAPD_OVER_SEQMOD 1)

# Define for ServerSideSort/VLV overlay.
set(SLAPD_OVER_SSSVLV 1)

# Define for Syncrepl Provider overlay.
set(SLAPD_OVER_SYNCPROV 1)

# Define for Translucent Proxy overlay.
set(SLAPD_OVER_TRANSLUCENT 1)

# Define for Attribute Uniqueness overlay.
set(SLAPD_OVER_UNIQUE 1)

# Define for Value Sorting overlay.
set(SLAPD_OVER_VALSORT 1)

# Define to support PASSWD backend.
set(SLAPD_PASSWD 1)

# Define to support PERL backend.
set(SLAPD_PERL 1)

# Define for Argon2 Password hashing module.
set(SLAPD_PWMOD_PW_ARGON2 1)

# Define to support relay backend.
set(SLAPD_RELAY 1)

# Define to support reverse lookups.
set(SLAPD_RLOOKUPS 1)

# Define to support SOCK backend.
set(SLAPD_SOCK 1)

# Define to support SASL passwords.
set(SLAPD_SPASSWD 1)

# Define to support SQL backend.
set(SLAPD_SQL 1)

# Define to support WiredTiger backend.
set(SLAPD_WT 1)

# Define to support run-time loadable ACL.
set(SLAP_DYNACL 1)

# Define to 1 if you have the ANSI C header files.
set(STDC_HEADERS 1)

# Define to 1 if you can safely include both <sys/time.h> and <time.h>.
set(TIME_WITH_SYS_TIME 1)

# Define to 1 if your <sys/time.h> declares `struct tm'.
set(TM_IN_SYS_TIME 1)

# Set to urandom device.
set(URANDOM_DEVICE "/dev/urandom")

# Define to use OpenSSL BIGNUM for MP.
set(USE_MP_BIGNUM 1)

# Define to use GMP for MP.
set(USE_MP_GMP 1)

# Define to use 'long' for MP.
set(USE_MP_LONG 1)

# Define to use 'long long' for MP.
set(USE_MP_LONG_LONG 1)

#add_compile_definitions(HAVE_FILIO_H=${HAVE_FILIO_H})
#add_compile_definitions(HAVE_FLOCK=${HAVE_FLOCK})
#add_compile_definitions(HAVE_FMEMOPEN=${HAVE_FMEMOPEN})
#add_compile_definitions(HAVE_FSTAT=${HAVE_FSTAT})
#add_compile_definitions(HAVE_GAI_STRERROR=${HAVE_GAI_STRERROR})
#add_compile_definitions(HAVE_GETADDRINFO=${HAVE_GETADDRINFO})
#add_compile_definitions(HAVE_GETDTABLESIZE=${HAVE_GETDTABLESIZE})
#add_compile_definitions(HAVE_GETEUID=${HAVE_GETEUID})
#add_compile_definitions(HAVE_GETGRGID=${HAVE_GETGRGID})
#add_compile_definitions(HAVE_GETHOSTBYADDR_R=${HAVE_GETHOSTBYADDR_R})
#add_compile_definitions(HAVE_GETHOSTBYNAME_R=${HAVE_GETHOSTBYNAME_R})
#add_compile_definitions(HAVE_GETHOSTNAME=${HAVE_GETHOSTNAME})
#add_compile_definitions(HAVE_GETNAMEINFO=${HAVE_GETNAMEINFO})
#add_compile_definitions(HAVE_GETOPT=${HAVE_GETOPT})
#add_compile_definitions(HAVE_GETOPT_H=${HAVE_GETOPT_H})
#add_compile_definitions(HAVE_GETPASSPHRASE=${HAVE_GETPASSPHRASE})
#add_compile_definitions(HAVE_GETPEEREID=${HAVE_GETPEEREID})
#add_compile_definitions(HAVE_GETPEERUCRED=${HAVE_GETPEERUCRED})
#add_compile_definitions(HAVE_GETPWNAM=${HAVE_GETPWNAM})
#add_compile_definitions(HAVE_GETPWUID=${HAVE_GETPWUID})
#add_compile_definitions(HAVE_GETSPNAM=${HAVE_GETSPNAM})
#add_compile_definitions(HAVE_GETTIMEOFDAY=${HAVE_GETTIMEOFDAY})
#add_compile_definitions(HAVE_GMP_H=${HAVE_GMP_H})
#add_compile_definitions(HAVE_GMTIME_R=${HAVE_GMTIME_R})
#add_compile_definitions(HAVE_GNUTLS=${HAVE_GNUTLS})
#add_compile_definitions(HAVE_GNUTLS_GNUTLS_H=${HAVE_GNUTLS_GNUTLS_H})
#add_compile_definitions(HAVE_GNU_PTH=${HAVE_GNU_PTH})
#add_compile_definitions(HAVE_OPENSSL=${HAVE_OPENSSL})
#add_compile_definitions(HAVE_OPENSSL_BN_H=${HAVE_OPENSSL_BN_H})
#add_compile_definitions(HAVE_OPENSSL_CRYPTO_H=${HAVE_OPENSSL_CRYPTO_H})
#add_compile_definitions(HAVE_OPENSSL_SSL_H=${HAVE_OPENSSL_SSL_H})
#add_compile_definitions(HAVE_GRP_H=${HAVE_GRP_H})
#add_compile_definitions(HAVE_HSTRERROR=${HAVE_HSTRERROR})
#add_compile_definitions(HAVE_INET_ATON=${HAVE_INET_ATON})
#add_compile_definitions(HAVE_INET_NTOA_B=${HAVE_INET_NTOA_B})
#add_compile_definitions(HAVE_INET_NTOP=${HAVE_INET_NTOP})
#add_compile_definitions(HAVE_INITGROUPS=${HAVE_INITGROUPS})
#add_compile_definitions(HAVE_INTTYPES_H=${HAVE_INTTYPES_H})
#add_compile_definitions(HAVE_IOCTL=${HAVE_IOCTL})
#add_compile_definitions(HAVE_IO_H=${HAVE_IO_H})
#add_compile_definitions(HAVE_KQUEUE=${HAVE_KQUEUE})
#add_compile_definitions(HAVE_LIBARGON2=${HAVE_LIBARGON2})
#add_compile_definitions(HAVE_LIBEVENT=${HAVE_LIBEVENT})
#add_compile_definitions(HAVE_LIBGEN=${HAVE_LIBGEN})
#add_compile_definitions(HAVE_LIBGMP=${HAVE_LIBGMP})
#add_compile_definitions(HAVE_LIBINET=${HAVE_LIBINET})
#add_compile_definitions(HAVE_LIBNET=${HAVE_LIBNET})

# Add compile definitions based on condition

if(HAVE_FILIO_H)
    add_compile_definitions(HAVE_FILIO_H)
endif()

if(HAVE_FLOCK)
    add_compile_definitions(HAVE_FLOCK)
endif()

if(HAVE_FMEMOPEN)
    add_compile_definitions(HAVE_FMEMOPEN)
endif()

if(HAVE_FSTAT)
    add_compile_definitions(HAVE_FSTAT)
endif()

if(HAVE_GAI_STRERROR)
    add_compile_definitions(HAVE_GAI_STRERROR)
endif()

if(HAVE_GETADDRINFO)
    add_compile_definitions(HAVE_GETADDRINFO)
endif()

if(HAVE_GETDTABLESIZE)
    add_compile_definitions(HAVE_GETDTABLESIZE)
endif()

if(HAVE_GETEUID)
    add_compile_definitions(HAVE_GETEUID)
endif()

if(HAVE_GETGRGID)
    add_compile_definitions(HAVE_GETGRGID)
endif()

if(HAVE_GETHOSTBYADDR_R)
    add_compile_definitions(HAVE_GETHOSTBYADDR_R)
endif()

if(HAVE_GETHOSTBYNAME_R)
    add_compile_definitions(HAVE_GETHOSTBYNAME_R)
endif()

if(HAVE_GETHOSTNAME)
    add_compile_definitions(HAVE_GETHOSTNAME)
endif()

if(HAVE_GETNAMEINFO)
    add_compile_definitions(HAVE_GETNAMEINFO)
endif()

if(HAVE_GETOPT)
    add_compile_definitions(HAVE_GETOPT)
endif()

if(HAVE_GETOPT_H)
    add_compile_definitions(HAVE_GETOPT_H)
endif()

if(HAVE_GETPASSPHRASE)
    add_compile_definitions(HAVE_GETPASSPHRASE)
endif()

if(HAVE_GETPEEREID)
    add_compile_definitions(HAVE_GETPEEREID)
endif()

if(HAVE_GETPEERUCRED)
    add_compile_definitions(HAVE_GETPEERUCRED)
endif()

if(HAVE_GETPWNAM)
    add_compile_definitions(HAVE_GETPWNAM)
endif()

if(HAVE_GETPWUID)
    add_compile_definitions(HAVE_GETPWUID)
endif()

if(HAVE_GETSPNAM)
    add_compile_definitions(HAVE_GETSPNAM)
endif()

if(HAVE_GETTIMEOFDAY)
    add_compile_definitions(HAVE_GETTIMEOFDAY)
endif()

if(HAVE_GMP_H)
    add_compile_definitions(HAVE_GMP_H)
endif()

if(HAVE_GMTIME_R)
    add_compile_definitions(HAVE_GMTIME_R)
endif()

if(HAVE_GNUTLS)
    add_compile_definitions(HAVE_GNUTLS)
endif()

if(HAVE_GNUTLS_GNUTLS_H)
    add_compile_definitions(HAVE_GNUTLS_GNUTLS_H)
endif()

if(HAVE_GNU_PTH)
    add_compile_definitions(HAVE_GNU_PTH)
endif()

if(HAVE_OPENSSL)
    add_compile_definitions(HAVE_OPENSSL)
endif()

if(HAVE_OPENSSL_BN_H)
    add_compile_definitions(HAVE_OPENSSL_BN_H)
endif()

if(HAVE_OPENSSL_CRYPTO_H)
    add_compile_definitions(HAVE_OPENSSL_CRYPTO_H)
endif()

if(HAVE_OPENSSL_SSL_H)
    add_compile_definitions(HAVE_OPENSSL_SSL_H)
endif()

if(HAVE_GRP_H)
    add_compile_definitions(HAVE_GRP_H)
endif()

if(HAVE_HSTRERROR)
    add_compile_definitions(HAVE_HSTRERROR)
endif()

if(HAVE_INET_ATON)
    add_compile_definitions(HAVE_INET_ATON)
endif()

if(HAVE_INET_NTOA_B)
    add_compile_definitions(HAVE_INET_NTOA_B)
endif()

if(HAVE_INET_NTOP)
    add_compile_definitions(HAVE_INET_NTOP)
endif()

if(HAVE_INITGROUPS)
    add_compile_definitions(HAVE_INITGROUPS)
endif()

if(HAVE_INTTYPES_H)
    add_compile_definitions(HAVE_INTTYPES_H)
endif()

if(HAVE_IOCTL)
    add_compile_definitions(HAVE_IOCTL)
endif()

if(HAVE_IO_H)
    add_compile_definitions(HAVE_IO_H)
endif()

if(HAVE_KQUEUE)
    add_compile_definitions(HAVE_KQUEUE)
endif()

if(HAVE_LIBARGON2)
    add_compile_definitions(HAVE_LIBARGON2)
endif()

if(HAVE_LIBEVENT)
    add_compile_definitions(HAVE_LIBEVENT)
endif()

if(HAVE_LIBGEN)
    add_compile_definitions(HAVE_LIBGEN)
endif()

if(HAVE_LIBGMP)
    add_compile_definitions(HAVE_LIBGMP)
endif()

if(HAVE_LIBINET)
    add_compile_definitions(HAVE_LIBINET)
endif()

if(HAVE_LIBNET)
    add_compile_definitions(HAVE_LIBNET)
endif()


# CMake preprocessor variables based on the provided checks

# Define to 1 if you have the `nsl' library (-lnsl).
if(HAVE_LIBNSL)
    add_compile_definitions(HAVE_LIBNSL)
endif()

# Define to 1 if you have the `nsl_s' library (-lnsl_s).
if(HAVE_LIBNSL_S)
    add_compile_definitions(HAVE_LIBNSL_S)
endif()

# Define to 1 if you have the `socket' library (-lsocket).
if(HAVE_LIBSOCKET)
    add_compile_definitions(HAVE_LIBSOCKET)
endif()

# Define if you have libsodium.
if(HAVE_LIBSODIUM)
    add_compile_definitions(HAVE_LIBSODIUM)
endif()

# Define to 1 if you have the <libutil.h> header file.
if(HAVE_LIBUTIL_H)
    add_compile_definitions(HAVE_LIBUTIL_H)
endif()

# Define to 1 if you have the `V3' library (-lV3).
if(HAVE_LIBV3)
    add_compile_definitions(HAVE_LIBV3)
endif()

# Define to 1 if you have the <limits.h> header file.
if(HAVE_LIMITS_H)
    add_compile_definitions(HAVE_LIMITS_H)
endif()

# If you have LinuxThreads.
if(HAVE_LINUX_THREADS)
    add_compile_definitions(HAVE_LINUX_THREADS)
endif()

# Define to 1 if you have the <locale.h> header file.
if(HAVE_LOCALE_H)
    add_compile_definitions(HAVE_LOCALE_H)
endif()

# Define to 1 if you have the `localtime_r' function.
if(HAVE_LOCALTIME_R)
    add_compile_definitions(HAVE_LOCALTIME_R)
endif()

# Define to 1 if you have the `lockf' function.
if(HAVE_LOCKF)
    add_compile_definitions(HAVE_LOCKF)
endif()

# Define to 1 if the system has the type `long long'.
if(HAVE_LONG_LONG)
    add_compile_definitions(HAVE_LONG_LONG)
endif()

# Define to 1 if you have the <ltdl.h> header file.
if(HAVE_LTDL_H)
    add_compile_definitions(HAVE_LTDL_H)
endif()

# Define to 1 if you have the <malloc.h> header file.
if(HAVE_MALLOC_H)
    add_compile_definitions(HAVE_MALLOC_H)
endif()

# Define to 1 if you have the `memcpy' function.
if(HAVE_MEMCPY)
    add_compile_definitions(HAVE_MEMCPY)
endif()

# Define to 1 if you have the `memmove' function.
if(HAVE_MEMMOVE)
    add_compile_definitions(HAVE_MEMMOVE)
endif()

# Define to 1 if you have the <memory.h> header file.
if(HAVE_MEMORY_H)
    add_compile_definitions(HAVE_MEMORY_H)
endif()

# Define to 1 if you have the `memrchr' function.
if(HAVE_MEMRCHR)
    add_compile_definitions(HAVE_MEMRCHR)
endif()

# Define to 1 if you have the `mkstemp' function.
if(HAVE_MKSTEMP)
    add_compile_definitions(HAVE_MKSTEMP)
endif()

# Define to 1 if you have the `mktemp' function.
if(HAVE_MKTEMP)
    add_compile_definitions(HAVE_MKTEMP)
endif()

# Define this if you have mkversion.
if(HAVE_MKVERSION)
    add_compile_definitions(HAVE_MKVERSION)
endif()

# Define to 1 if you have the <ndir.h> header file, and it defines `DIR'.
if(HAVE_NDIR_H)
    add_compile_definitions(HAVE_NDIR_H)
endif()

# Define to 1 if you have the <netinet/tcp.h> header file.
if(HAVE_NETINET_TCP_H)
    add_compile_definitions(HAVE_NETINET_TCP_H)
endif()

# Define if strerror_r returns char* instead of int.
if(HAVE_NONPOSIX_STRERROR_R)
    add_compile_definitions(HAVE_NONPOSIX_STRERROR_R)
endif()

# If you have NT Event Log.
if(HAVE_NT_EVENT_LOG)
    add_compile_definitions(HAVE_NT_EVENT_LOG)
endif()

# If you have NT Service Manager.
if(HAVE_NT_SERVICE_MANAGER)
    add_compile_definitions(HAVE_NT_SERVICE_MANAGER)
endif()

# If you have NT Threads.
if(HAVE_NT_THREADS)
    add_compile_definitions(HAVE_NT_THREADS)
endif()

# Define to 1 if you have the `pipe' function.
if(HAVE_PIPE)
    add_compile_definitions(HAVE_PIPE)
endif()

# Define to 1 if you have the `poll' function.
if(HAVE_POLL)
    add_compile_definitions(HAVE_POLL)
endif()

# Define to 1 if you have the <poll.h> header file.
if(HAVE_POLL_H)
    add_compile_definitions(HAVE_POLL_H)
endif()

# Define to 1 if you have the <process.h> header file.
if(HAVE_PROCESS_H)
    add_compile_definitions(HAVE_PROCESS_H)
endif()

# Define to 1 if you have the <psap.h> header file.
if(HAVE_PSAP_H)
    add_compile_definitions(HAVE_PSAP_H)
endif()

# Define to pthreads API spec revision.
if(HAVE_PTHREADS)
    add_compile_definitions(HAVE_PTHREADS)
endif()

# Define if you have pthread_detach function.
if(HAVE_PTHREAD_DETACH)
    add_compile_definitions(HAVE_PTHREAD_DETACH)
endif()

# Define to 1 if you have the `pthread_getconcurrency' function.
if(HAVE_PTHREAD_GETCONCURRENCY)
    add_compile_definitions(HAVE_PTHREAD_GETCONCURRENCY)
endif()

# Define to 1 if you have the <pthread.h> header file.
if(HAVE_PTHREAD_H)
    add_compile_definitions(HAVE_PTHREAD_H)
endif()

# Define to 1 if you have the `pthread_kill' function.
if(HAVE_PTHREAD_KILL)
    add_compile_definitions(HAVE_PTHREAD_KILL)
endif()

# Define to 1 if you have the `pthread_kill_other_threads_np' function.
if(HAVE_PTHREAD_KILL_OTHER_THREADS_NP)
    add_compile_definitions(HAVE_PTHREAD_KILL_OTHER_THREADS_NP)
endif()

# Define if you have pthread_rwlock_destroy function.
if(HAVE_PTHREAD_RWLOCK_DESTROY)
    add_compile_definitions(HAVE_PTHREAD_RWLOCK_DESTROY)
endif()

# Define to 1 if you have the `pthread_setconcurrency' function.
check_function_exists(pthread_setconcurrency HAVE_PTHREAD_SETCONCURRENCY)
if (HAVE_PTHREAD_SETCONCURRENCY)
    add_compile_definitions(HAVE_PTHREAD_SETCONCURRENCY)
endif()

# Define to 1 if you have the `pthread_yield' function.
check_function_exists(pthread_yield HAVE_PTHREAD_YIELD)
if (HAVE_PTHREAD_YIELD)
    add_compile_definitions(HAVE_PTHREAD_YIELD)
endif()

# Define to 1 if you have the <pth.h> header file.
check_include_file(pth.h HAVE_PTH_H)
if (HAVE_PTH_H)
    add_compile_definitions(HAVE_PTH_H)
endif()

# Define to 1 if the system has the type `ptrdiff_t'.
check_type_size("ptrdiff_t" HAVE_PTRDIFF_T)
if (HAVE_PTRDIFF_T)
    add_compile_definitions(HAVE_PTRDIFF_T)
endif()

#add_compile_definitions(ptrdiff_t "long")

# Define to 1 if you have the <pwd.h> header file.
check_include_file(pwd.h HAVE_PWD_H)
if (HAVE_PWD_H)
    add_compile_definitions(HAVE_PWD_H)
endif()

# Define to 1 if you have the `read' function.
check_function_exists(read HAVE_READ)
if (HAVE_READ)
    add_compile_definitions(HAVE_READ)
endif()

# Define to 1 if you have the `recv' function.
check_function_exists(recv HAVE_RECV)
if (HAVE_RECV)
    add_compile_definitions(HAVE_RECV)
endif()

# Define to 1 if you have the `recvfrom' function.
check_function_exists(recvfrom HAVE_RECVFROM)
if (HAVE_RECVFROM)
    add_compile_definitions(HAVE_RECVFROM)
endif()

# Define to 1 if you have the <regex.h> header file.
check_include_file(regex.h HAVE_REGEX_H)
if (HAVE_REGEX_H)
    add_compile_definitions(HAVE_REGEX_H)
endif()

# Define to 1 if you have the <resolv.h> header file.
check_include_file(resolv.h HAVE_RESOLV_H)
if (HAVE_RESOLV_H)
    add_compile_definitions(HAVE_RESOLV_H)
endif()

# Define if you have res_query().
check_symbol_exists(res_query "resolv.h" HAVE_RES_QUERY)
if (HAVE_RES_QUERY)
    add_compile_definitions(HAVE_RES_QUERY)
endif()

# Define to 1 if you have the <sasl.h> header file.
check_include_file(sasl.h HAVE_SASL_H)
if (HAVE_SASL_H)
    add_compile_definitions(HAVE_SASL_H)
endif()

# Define to 1 if you have the <sasl/sasl.h> header file.
check_include_file(sasl/sasl.h HAVE_SASL_SASL_H)
if (HAVE_SASL_SASL_H)
    add_compile_definitions(HAVE_SASL_SASL_H)
endif()

# Define if your SASL library has sasl_version().
check_function_exists(sasl_version HAVE_SASL_VERSION)
if (HAVE_SASL_VERSION)
    add_compile_definitions(HAVE_SASL_VERSION)
endif()

# Define to 1 if you have the <sched.h> header file.
check_include_file(sched.h HAVE_SCHED_H)
if (HAVE_SCHED_H)
    add_compile_definitions(HAVE_SCHED_H)
endif()

# Define to 1 if you have the `sched_yield' function.
check_function_exists(sched_yield HAVE_SCHED_YIELD)
if (HAVE_SCHED_YIELD)
    add_compile_definitions(HAVE_SCHED_YIELD)
endif()

# Define to 1 if you have the `send' function.
check_function_exists(send HAVE_SEND)
if (HAVE_SEND)
    add_compile_definitions(HAVE_SEND)
endif()

# Define to 1 if you have the `sendmsg' function.
check_function_exists(sendmsg HAVE_SENDMSG)
if (HAVE_SENDMSG)
    add_compile_definitions(HAVE_SENDMSG)
endif()

# Define to 1 if you have the `sendto' function.
check_function_exists(sendto HAVE_SENDTO)
if (HAVE_SENDTO)
    add_compile_definitions(HAVE_SENDTO)
endif()

# Define to 1 if you have the `setegid' function.
check_function_exists(setegid HAVE_SETEGID)
if (HAVE_SETEGID)
    add_compile_definitions(HAVE_SETEGID)
endif()

# Define to 1 if you have the `seteuid' function.
check_function_exists(seteuid HAVE_SETEUID)
if (HAVE_SETEUID)
    add_compile_definitions(HAVE_SETEUID)
endif()

# Define to 1 if you have the `setgid' function.
check_function_exists(setgid HAVE_SETGID)
if (HAVE_SETGID)
    add_compile_definitions(HAVE_SETGID)
endif()

# Define to 1 if you have the `setpwfile' function.
check_function_exists(setpwfile HAVE_SETPWFILE)
if (HAVE_SETPWFILE)
    add_compile_definitions(HAVE_SETPWFILE)
endif()

# Define to 1 if you have the `setsid' function.
check_function_exists(setsid HAVE_SETSID)
if (HAVE_SETSID)
    add_compile_definitions(HAVE_SETSID)
endif()

# Define to 1 if you have the `setuid' function.
check_function_exists(setuid HAVE_SETUID)
if (HAVE_SETUID)
    add_compile_definitions(HAVE_SETUID)
endif()

# Define to 1 if you have the <sgtty.h> header file.
check_include_file(sgtty.h HAVE_SGTTY_H)
if (HAVE_SGTTY_H)
    add_compile_definitions(HAVE_SGTTY_H)
endif()

# Define to 1 if you have the <shadow.h> header file.
check_include_file(shadow.h HAVE_SHADOW_H)
if (HAVE_SHADOW_H)
    add_compile_definitions(HAVE_SHADOW_H)
endif()

# Define to 1 if you have the `sigaction' function.
check_function_exists(sigaction HAVE_SIGACTION)
if (HAVE_SIGACTION)
    add_compile_definitions(HAVE_SIGACTION)
endif()

# Define to 1 if you have the `signal' function.
check_function_exists(signal HAVE_SIGNAL)
if (HAVE_SIGNAL)
    add_compile_definitions(HAVE_SIGNAL)
endif()

# Define to 1 if you have the `sigset' function.
check_function_exists(sigset HAVE_SIGSET)
if (HAVE_SIGSET)
    add_compile_definitions(HAVE_SIGSET)
endif()

# Define if you have -lslp.
check_library_exists(slp slp_open slp.h HAVE_SLP)
if (HAVE_SLP)
    add_compile_definitions(HAVE_SLP)
endif()

# Define to 1 if you have the <slp.h> header file.
check_include_file(slp.h HAVE_SLP_H)
if (HAVE_SLP_H)
    add_compile_definitions(HAVE_SLP_H)
endif()

# Define to 1 if you have the `snprintf' function.
check_function_exists(snprintf HAVE_SNPRINTF)
if (HAVE_SNPRINTF)
    add_compile_definitions(HAVE_SNPRINTF)
endif()

# Define to 1 if you have the <sodium.h> header file.
check_include_file(sodium.h HAVE_SODIUM_H)
if (HAVE_SODIUM_H)
    add_compile_definitions(HAVE_SODIUM_H)
endif()

# Define if you have spawnlp().
check_symbol_exists(spawnlp "" HAVE_SPAWNLP)
if (HAVE_SPAWNLP)
    add_compile_definitions(HAVE_SPAWNLP)
endif()

# Define to 1 if you have the <sqlext.h> header file.
check_include_file(sqlext.h HAVE_SQLEXT_H)
if (HAVE_SQLEXT_H)
    add_compile_definitions(HAVE_SQLEXT_H)
endif()

# Define to 1 if you have the <sql.h> header file.
check_include_file(sql.h HAVE_SQL_H)
if (HAVE_SQL_H)
    add_compile_definitions(HAVE_SQL_H)
endif()

# Define to 1 if you have the <stddef.h> header file.
check_include_file(stddef.h HAVE_STDDEF_H)
if (HAVE_STDDEF_H)
    add_compile_definitions(HAVE_STDDEF_H)
endif()

# Define to 1 if you have the <stdint.h> header file.
check_include_file(stdint.h HAVE_STDINT_H)
if (HAVE_STDINT_H)
    add_compile_definitions(HAVE_STDINT_H)
endif()

# Define to 1 if you have the <stdlib.h> header file.
check_include_file(stdlib.h HAVE_STDLIB_H)
if (HAVE_STDLIB_H)
    add_compile_definitions(HAVE_STDLIB_H)
endif()

# Define to 1 if you have the `strdup' function.
check_function_exists(strdup HAVE_STRDUP)
if (HAVE_STRDUP)
    add_compile_definitions(HAVE_STRDUP)
endif()

# Define to 1 if you have the `strerror' function.
check_function_exists(strerror HAVE_STRERROR)
if (HAVE_STRERROR)
    add_compile_definitions(HAVE_STRERROR)
endif()

# Define to 1 if you have the `strerror_r' function.
check_function_exists(strerror_r HAVE_STRERROR_R)
if (HAVE_STRERROR_R)
    add_compile_definitions(HAVE_STRERROR_R)
endif()

# Define to 1 if you have the `strftime' function.
check_function_exists(strftime HAVE_STRFTIME)
if (HAVE_STRFTIME)
    add_compile_definitions(HAVE_STRFTIME)
endif()

# Define to 1 if you have the <strings.h> header file.
check_include_file(strings.h HAVE_STRINGS_H)
if (HAVE_STRINGS_H)
    add_compile_definitions(HAVE_STRINGS_H)
endif()

# Define to 1 if you have the <string.h> header file.
check_include_file(string.h HAVE_STRING_H)
if (HAVE_STRING_H)
    add_compile_definitions(HAVE_STRING_H)
endif()

# Define to 1 if you have the `strpbrk' function.
check_function_exists(strpbrk HAVE_STRPBRK)
if (HAVE_STRPBRK)
    add_compile_definitions(HAVE_STRPBRK)
endif()

# Define to 1 if you have the `strrchr' function.
check_function_exists(strrchr HAVE_STRRCHR)
if (HAVE_STRRCHR)
    add_compile_definitions(HAVE_STRRCHR)
endif()

# Define to 1 if you have the `strsep' function.
check_function_exists(strsep HAVE_STRSEP)
if (HAVE_STRSEP)
    add_compile_definitions(HAVE_STRSEP)
endif()

# Define to 1 if you have the `strspn' function.
check_function_exists(strspn HAVE_STRSPN)
if (HAVE_STRSPN)
    add_compile_definitions(HAVE_STRSPN)
endif()

# Define to 1 if you have the `strstr' function.
check_function_exists(strstr HAVE_STRSTR)
if (HAVE_STRSTR)
    add_compile_definitions(HAVE_STRSTR)
endif()

# Define to 1 if you have the `strtol' function.
check_function_exists(strtol HAVE_STRTOL)
if (HAVE_STRTOL)
    add_compile_definitions(HAVE_STRTOL)
endif()

# Define to 1 if you have the `strtoll' function.
check_function_exists(strtoll HAVE_STRTOLL)
if (HAVE_STRTOLL)
    add_compile_definitions(HAVE_STRTOLL)
endif()

# Define to 1 if you have the `strtoq' function.
check_function_exists(strtoq HAVE_STRTOQ)
if (HAVE_STRTOQ)
    add_compile_definitions(HAVE_STRTOQ)
endif()

# Define to 1 if you have the `strtoul' function.
check_function_exists(strtoul HAVE_STRTOUL)
if (HAVE_STRTOUL)
    add_compile_definitions(HAVE_STRTOUL)
endif()

# Define to 1 if you have the `strtoull' function.
check_function_exists(strtoull HAVE_STRTOULL)
if (HAVE_STRTOULL)
    add_compile_definitions(HAVE_STRTOULL)
endif()

# Define to 1 if you have the `strtoq' function.
check_function_exists(strtoq HAVE_STRTOQ)
if (HAVE_STRTOQ)
    add_compile_definitions(HAVE_STRTOQ)
endif()

# Define to 1 if `msg_accrightslen' is a member of `struct msghdr'.
check_symbol_exists(msg_accrightslen "sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTSLEN)
if (HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTSLEN)
    add_compile_definitions(HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTSLEN)
endif()

# Define to 1 if `msg_control' is a member of `struct msghdr'.
check_symbol_exists(msg_control "sys/socket.h" HAVE_STRUCT_MSGHDR_MSG_CONTROL)
if (HAVE_STRUCT_MSGHDR_MSG_CONTROL)
    add_compile_definitions(HAVE_STRUCT_MSGHDR_MSG_CONTROL)
endif()

# Define to 1 if `pw_gecos' is a member of `struct passwd'.
check_symbol_exists(pw_gecos "pwd.h" HAVE_STRUCT_PASSWD_PW_GECOS)
if (HAVE_STRUCT_PASSWD_PW_GECOS)
    add_compile_definitions(HAVE_STRUCT_PASSWD_PW_GECOS)
endif()

# Define to 1 if `pw_passwd' is a member of `struct passwd'.
check_symbol_exists(pw_passwd "pwd.h" HAVE_STRUCT_PASSWD_PW_PASSWD)
if (HAVE_STRUCT_PASSWD_PW_PASSWD)
    add_compile_definitions(HAVE_STRUCT_PASSWD_PW_PASSWD)
endif()

# Define to 1 if `st_blksize' is a member of `struct stat'.
check_symbol_exists(st_blksize "sys/stat.h" HAVE_STRUCT_STAT_ST_BLKSIZE)
if (HAVE_STRUCT_STAT_ST_BLKSIZE)
    add_compile_definitions(HAVE_STRUCT_STAT_ST_BLKSIZE)
endif()

# Define to 1 if `st_fstype' is a member of `struct stat'.
check_symbol_exists(st_fstype "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE)
if (HAVE_STRUCT_STAT_ST_FSTYPE)
    add_compile_definitions(HAVE_STRUCT_STAT_ST_FSTYPE)
endif()

# Define to 1 if `st_fstype' is char *.
check_symbol_exists(st_fstype_char "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE_CHAR)
if (HAVE_STRUCT_STAT_ST_FSTYPE_CHAR)
    add_compile_definitions(HAVE_STRUCT_STAT_ST_FSTYPE_CHAR)
endif()

# Define to 1 if `st_fstype' is int.
check_symbol_exists(st_fstype_int "sys/stat.h" HAVE_STRUCT_STAT_ST_FSTYPE_INT)
if (HAVE_STRUCT_STAT_ST_FSTYPE_INT)
    add_compile_definitions(HAVE_STRUCT_STAT_ST_FSTYPE_INT)
endif()

# Define to 1 if `st_vfstype' is a member of `struct stat'.
check_symbol_exists(st_vfstype "sys/stat.h" HAVE_STRUCT_STAT_ST_VFSTYPE)
if (HAVE_STRUCT_STAT_ST_VFSTYPE)
    add_compile_definitions(HAVE_STRUCT_STAT_ST_VFSTYPE)
endif()

# Define to 1 if you have the <synch.h> header file.
check_include_file(synch.h HAVE_SYNCH_H)
if (HAVE_SYNCH_H)
    add_compile_definitions(HAVE_SYNCH_H)
endif()

# Define to 1 if you have the `sysconf' function.
check_function_exists(sysconf HAVE_SYSCONF)
if (HAVE_SYSCONF)
    add_compile_definitions(HAVE_SYSCONF)
endif()

# Define to 1 if you have the <sysexits.h> header file.
check_include_file(sysexits.h HAVE_SYSEXITS_H)
if (HAVE_SYSEXITS_H)
    add_compile_definitions(HAVE_SYSEXITS_H)
endif()

# Define to 1 if you have the <syslog.h> header file.
check_include_file(syslog.h HAVE_SYSLOG_H)
if (HAVE_SYSLOG_H)
    add_compile_definitions(HAVE_SYSLOG_H)
endif()

# Define if you have systemd.
check_library_exists(systemd sd_listen_fds "systemd/sdaemon.h" HAVE_SYSTEMD)
if (HAVE_SYSTEMD)
    add_compile_definitions(HAVE_SYSTEMD)
endif()

# Define to 1 if you have the <systemd/sdaemon.h> header file.
check_include_file(systemd/sdaemon.h HAVE_SYSTEMD_SD_DAEMON_H)
if (HAVE_SYSTEMD_SD_DAEMON_H)
    add_compile_definitions(HAVE_SYSTEMD_SD_DAEMON_H)
endif()

# Define to 1 if you have the <sys/devpoll.h> header file.
check_include_file(sys/devpoll.h HAVE_SYS_DEVPOLL_H)
if (HAVE_SYS_DEVPOLL_H)
    add_compile_definitions(HAVE_SYS_DEVPOLL_H)
endif()

# Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
check_include_file(sys/dir.h HAVE_SYS_DIR_H)
if (HAVE_SYS_DIR_H)
    add_compile_definitions(HAVE_SYS_DIR_H)
endif()

# Define to 1 if you have the <sys/epoll.h> header file.
check_include_file(sys/epoll.h HAVE_SYS_EPOLL_H)
if (HAVE_SYS_EPOLL_H)
    add_compile_definitions(HAVE_SYS_EPOLL_H)
endif()

# Define if you actually have sys_errlist in your libs.
check_symbol_exists(sys_errlist "stdlib.h" HAVE_SYS_ERRLIST)
if (HAVE_SYS_ERRLIST)
    add_compile_definitions(HAVE_SYS_ERRLIST)
endif()

# Define to 1 if you have the <sys/errno.h> header file.
check_include_file(sys/errno.h HAVE_SYS_ERRNO_H)
if (HAVE_SYS_ERRNO_H)
    add_compile_definitions(HAVE_SYS_ERRNO_H)
endif()

# Define to 1 if you have the <sys/event.h> header file.
check_include_file(sys/event.h HAVE_SYS_EVENT_H)
if (HAVE_SYS_EVENT_H)
    add_compile_definitions(HAVE_SYS_EVENT_H)
endif()

# Define to 1 if you have the <sys/file.h> header file.
check_include_file(sys/file.h HAVE_SYS_FILE_H)
if (HAVE_SYS_FILE_H)
    add_compile_definitions(HAVE_SYS_FILE_H)
endif()

# Define to 1 if you have the <sys/filio.h> header file.
check_include_file(sys/filio.h HAVE_SYS_FILIO_H)
if (HAVE_SYS_FILIO_H)
    add_compile_definitions(HAVE_SYS_FILIO_H)
endif()

# Define to 1 if you have the <sys/fstyp.h> header file.
check_include_file(sys/fstyp.h HAVE_SYS_FSTYP_H)
if (HAVE_SYS_FSTYP_H)
    add_compile_definitions(HAVE_SYS_FSTYP_H)
endif()

# Define to 1 if you have the <sys/ioctl.h> header file.
check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)
if (HAVE_SYS_IOCTL_H)
    add_compile_definitions(HAVE_SYS_IOCTL_H)
endif()

# Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
check_include_file(sys/ndir.h HAVE_SYS_NDIR_H)
if (HAVE_SYS_NDIR_H)
    add_compile_definitions(HAVE_SYS_NDIR_H)
endif()

# Define to 1 if you have the <sys/param.h> header file.
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
if (HAVE_SYS_PARAM_H)
    add_compile_definitions(HAVE_SYS_PARAM_H)
endif()

# Define to 1 if you have the <sys/poll.h> header file.
check_include_file(sys/poll.h HAVE_SYS_POLL_H)
if (HAVE_SYS_POLL_H)
    add_compile_definitions(HAVE_SYS_POLL_H)
endif()

# Define to 1 if you have the <sys/privgrp.h> header file.
check_include_file(sys/privgrp.h HAVE_SYS_PRIVGRP_H)
if (HAVE_SYS_PRIVGRP_H)
    add_compile_definitions(HAVE_SYS_PRIVGRP_H)
endif()

# Define to 1 if you have the <sys/resource.h> header file.
check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
if (HAVE_SYS_RESOURCE_H)
    add_compile_definitions(HAVE_SYS_RESOURCE_H)
endif()

# Define to 1 if you have the <sys/select.h> header file.
check_include_file(sys/select.h HAVE_SYS_SELECT_H)
if (HAVE_SYS_SELECT_H)
    add_compile_definitions(HAVE_SYS_SELECT_H)
endif()

# Define to 1 if you have the <sys/socket.h> header file.
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
if (HAVE_SYS_SOCKET_H)
    add_compile_definitions(HAVE_SYS_SOCKET_H)
endif()

# Define to 1 if you have the <sys/stat.h> header file.
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
if (HAVE_SYS_STAT_H)
    add_compile_definitions(HAVE_SYS_STAT_H)
endif()

# Define to 1 if you have the <sys/syslog.h> header file.
check_include_file(sys/syslog.h HAVE_SYS_SYSLOG_H)
if (HAVE_SYS_SYSLOG_H)
    add_compile_definitions(HAVE_SYS_SYSLOG_H)
endif()

# Define to 1 if you have the <sys/time.h> header file.
check_include_file(sys/time.h HAVE_SYS_TIME_H)
if (HAVE_SYS_TIME_H)
    add_compile_definitions(HAVE_SYS_TIME_H)
endif()

# Define to 1 if you have the <sys/types.h> header file.
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
if (HAVE_SYS_TYPES_H)
    add_compile_definitions(HAVE_SYS_TYPES_H)
endif()

# Define to 1 if you have the <sys/ucred.h> header file.
check_include_file(sys/ucred.h HAVE_SYS_UCRED_H)
if (HAVE_SYS_UCRED_H)
    add_compile_definitions(HAVE_SYS_UCRED_H)
endif()

# Define to 1 if you have the <sys/uio.h> header file.
check_include_file(sys/uio.h HAVE_SYS_UIO_H)
if (HAVE_SYS_UIO_H)
    add_compile_definitions(HAVE_SYS_UIO_H)
endif()

# Define to 1 if you have the <sys/un.h> header file.
check_include_file(sys/un.h HAVE_SYS_UN_H)
if (HAVE_SYS_UN_H)
    add_compile_definitions(HAVE_SYS_UN_H)
endif()

# Define to 1 if you have the <sys/uuid.h> header file.
check_include_file(sys/uuid.h HAVE_SYS_UUID_H)
if (HAVE_SYS_UUID_H)
    add_compile_definitions(HAVE_SYS_UUID_H)
endif()

# Define to 1 if you have the <sys/vmount.h> header file.
check_include_file(sys/vmount.h HAVE_SYS_VMOUNT_H)
if (HAVE_SYS_VMOUNT_H)
    add_compile_definitions(HAVE_SYS_VMOUNT_H)
endif()

# Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible.
check_include_file(sys/wait.h HAVE_SYS_WAIT_H)
if (HAVE_SYS_WAIT_H)
    add_compile_definitions(HAVE_SYS_WAIT_H)
endif()

# Define if you have -lwrap.
check_library_exists(wrap hosts_access "tcpd.h" HAVE_TCPD)
if (HAVE_TCPD)
    add_compile_definitions(HAVE_TCPD)
endif()

# Define to 1 if you have the <tcpd.h> header file.
check_include_file(tcpd.h HAVE_TCPD_H)
if (HAVE_TCPD_H)
    add_compile_definitions(HAVE_TCPD_H)
endif()

# Define to 1 if you have the <termios.h> header file.
check_include_file(termios.h HAVE_TERMIOS_H)
if (HAVE_TERMIOS_H)
    add_compile_definitions(HAVE_TERMIOS_H)
endif()

# If you have Solaris LWP (thr) package.
check_symbol_exists(thr "thread.h" HAVE_THR)
if (HAVE_THR)
    add_compile_definitions(HAVE_THR)
endif()

# Define to 1 if you have the <thread.h> header file.
check_include_file(thread.h HAVE_THREAD_H)
if (HAVE_THREAD_H)
    add_compile_definitions(HAVE_THREAD_H)
endif()

# Define to 1 if you have the `thr_getconcurrency' function.
check_function_exists(thr_getconcurrency HAVE_THR_GETCONCURRENCY)
if (HAVE_THR_GETCONCURRENCY)
    add_compile_definitions(HAVE_THR_GETCONCURRENCY)
endif()

# Define to 1 if you have the `thr_setconcurrency' function.
check_function_exists(thr_setconcurrency HAVE_THR_SETCONCURRENCY)
if (HAVE_THR_SETCONCURRENCY)
    add_compile_definitions(HAVE_THR_SETCONCURRENCY)
endif()

# Define to 1 if you have the `thr_yield' function.
check_function_exists(thr_yield HAVE_THR_YIELD)
if (HAVE_THR_YIELD)
    add_compile_definitions(HAVE_THR_YIELD)
endif()

# Define if you have TLS.
check_symbol_exists(TLS "" HAVE_TLS)
if (HAVE_TLS)
    add_compile_definitions(HAVE_TLS)
endif()

# Define to 1 if you have the <unistd.h> header file.
check_include_file(unistd.h HAVE_UNISTD_H)
if (HAVE_UNISTD_H)
    add_compile_definitions(HAVE_UNISTD_H)
endif()

# Define to 1 if you have the <utime.h> header file.
check_include_file(utime.h HAVE_UTIME_H)
if (HAVE_UTIME_H)
    add_compile_definitions(HAVE_UTIME_H)
endif()

# Define if you have uuid_generate().
check_function_exists(uuid_generate HAVE_UUID_GENERATE)
if (HAVE_UUID_GENERATE)
    add_compile_definitions(HAVE_UUID_GENERATE)
endif()

# Define if you have uuid_to_str().
check_function_exists(uuid_to_str HAVE_UUID_TO_STR)
if (HAVE_UUID_TO_STR)
    add_compile_definitions(HAVE_UUID_TO_STR)
endif()

# Define to 1 if you have the <uuid/uuid.h> header file.
check_include_file(uuid/uuid.h HAVE_UUID_UUID_H)
if (HAVE_UUID_UUID_H)
    add_compile_definitions(HAVE_UUID_UUID_H)
endif()

# Define to 1 if you have the `vprintf' function.
check_function_exists(vprintf HAVE_VPRINTF)
if (HAVE_VPRINTF)
    add_compile_definitions(HAVE_VPRINTF)
endif()

# Define to 1 if you have the `vsnprintf' function.
check_function_exists(vsnprintf HAVE_VSNPRINTF)
if (HAVE_VSNPRINTF)
    add_compile_definitions(HAVE_VSNPRINTF)
endif()

# Define to 1 if you have the `wait4' function.
check_function_exists(wait4 HAVE_WAIT4)
if (HAVE_WAIT4)
    add_compile_definitions(HAVE_WAIT4)
endif()

# Define to 1 if you have the `waitpid' function.
check_function_exists(waitpid HAVE_WAITPID)
if (HAVE_WAITPID)
    add_compile_definitions(HAVE_WAITPID)
endif()

# Define if you have winsock.
check_library_exists(ws2_32 WSAStartup "winsock.h" HAVE_WINSOCK)
if (HAVE_WINSOCK)
    add_compile_definitions(HAVE_WINSOCK)
endif()

# Define if you have winsock2.
check_library_exists(ws2_32 WSAStartup "winsock2.h" HAVE_WINSOCK2)
if (HAVE_WINSOCK2)
    add_compile_definitions(HAVE_WINSOCK2)
endif()

# Define to 1 if you have the <winsock2.h> header file.
check_include_file(winsock2.h HAVE_WINSOCK2_H)
if (HAVE_WINSOCK2_H)
    add_compile_definitions(HAVE_WINSOCK2_H)
endif()

# Define to 1 if you have the <winsock.h> header file.
check_include_file(winsock.h HAVE_WINSOCK_H)
if (HAVE_WINSOCK_H)
    add_compile_definitions(HAVE_WINSOCK_H)
endif()

# Define to 1 if you have the `write' function.
check_function_exists(write HAVE_WRITE)
if (HAVE_WRITE)
    add_compile_definitions(HAVE_WRITE)
endif()

# Define if select implicitly yields.
check_symbol_exists(select_imp_yields "" HAVE_YIELDING_SELECT)
if (HAVE_YIELDING_SELECT)
    add_compile_definitions(HAVE_YIELDING_SELECT)
endif()

# Define to 1 if you have the `_vsnprintf' function.
check_function_exists(_vsnprintf HAVE__VSNPRINTF)
if (HAVE__VSNPRINTF)
    add_compile_definitions(HAVE__VSNPRINTF)
endif()

# Define to 32-bit or greater integer type.
# check_type_size("int" LBER_INT_T)
set(LBER_INT_T "int")
add_compile_definitions(LBER_INT_T=${LBER_INT_T})

# Define to large integer type.
#check_type_size("long long" LBER_LEN_T)
set(LBER_LEN_T "long long")
add_compile_definitions(LBER_LEN_T=${LBER_LEN_T})

# Define to socket descriptor type.
#check_type_size("int" LBER_SOCKET_T)
set(LBER_SOCKET_T "int")
add_compile_definitions(LBER_SOCKET_T=${LBER_SOCKET_T})

# Define to large integer type.
#check_type_size("long long" LBER_TAG_T)
set(LBER_TAG_T "long long")
add_compile_definitions(LBER_TAG_T=${LBER_TAG_T})

check_type_size("long" SIZEOF_LONG)
add_compile_definitions(SIZEOF_LONG=${SIZEOF_LONG})

check_type_size("int" SIZEOF_INT)
add_compile_definitions(SIZEOF_INTß=${SIZEOF_INT})

check_type_size("short" SIZEOF_SHORT)
add_compile_definitions(SIZEOF_SHORT=${SIZEOF_SHORT})
