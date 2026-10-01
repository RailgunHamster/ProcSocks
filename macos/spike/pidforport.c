/*
 * pidforport —— 查「哪个进程拥有本地 TCP 端口 X」
 *
 * 这是 ProcSocks macOS 后端的核心原语：
 * pf 把连接重定向到我们时，客户端的**源端口是保留的**（已由 spike #1 实测确认），
 * 所以拿到 peer 端口后扫一遍全系统 socket 表，就能定位到发起连接的进程，
 * 再取其可执行文件路径去跑 ProcSocks 现有的正则规则。
 *
 * 只依赖 libproc，不需要任何 Apple entitlement。
 * 查别的用户的进程需要 root；查自己的进程不需要。
 *
 * 用法: pidforport <local_tcp_port> [--raw]
 */
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <local_tcp_port>\n", argv[0]);
        return 2;
    }

    int want = atoi(argv[1]);
    if (want <= 0 || want > 65535) {
        fprintf(stderr, "端口不合法: %s\n", argv[1]);
        return 2;
    }

    /* 1. 拿到全系统 pid 列表 */
    int nbytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (nbytes <= 0) {
        fprintf(stderr, "proc_listpids 失败\n");
        return 1;
    }
    int cap = nbytes / (int)sizeof(pid_t) + 32;
    pid_t *pids = calloc((size_t)cap, sizeof(pid_t));
    if (!pids) return 1;

    nbytes = proc_listpids(PROC_ALL_PIDS, 0, pids, cap * (int)sizeof(pid_t));
    if (nbytes <= 0) {
        fprintf(stderr, "proc_listpids(2) 失败\n");
        free(pids);
        return 1;
    }
    int npids = nbytes / (int)sizeof(pid_t);

    /* 2. 逐个进程枚举 fd，找 TCP socket 且本地端口匹配 */
    for (int i = 0; i < npids; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;

        int fdsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdsize <= 0) continue;                 /* 权限不足或进程已退出，跳过 */

        int fd_cap = fdsize / (int)sizeof(struct proc_fdinfo) + 8;
        struct proc_fdinfo *fds = malloc((size_t)fd_cap * sizeof(struct proc_fdinfo));
        if (!fds) continue;

        fdsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds,
                              fd_cap * (int)sizeof(struct proc_fdinfo));
        if (fdsize <= 0) { free(fds); continue; }
        int nfds = fdsize / (int)sizeof(struct proc_fdinfo);

        for (int j = 0; j < nfds; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;

            struct socket_fdinfo si;
            int r = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                   &si, (int)sizeof(si));
            if (r != (int)sizeof(si)) continue;
            if (si.psi.soi_kind != SOCKINFO_TCP) continue;
            if (si.psi.soi_family != AF_INET && si.psi.soi_family != AF_INET6) continue;

            struct in_sockinfo *ini = &si.psi.soi_proto.pri_tcp.tcpsi_ini;

            /* macOS 这里端口的字节序在不同版本上表现不一致，两种都试 */
            int raw_lport = ini->insi_lport;
            int lport_a = ntohs((uint16_t)raw_lport);
            int lport_b = (uint16_t)raw_lport;
            if (lport_a != want && lport_b != want) continue;

            char path[PROC_PIDPATHINFO_MAXSIZE];
            memset(path, 0, sizeof(path));
            proc_pidpath(pid, path, (uint32_t)sizeof(path));

            char laddr[INET6_ADDRSTRLEN] = {0};
            char faddr[INET6_ADDRSTRLEN] = {0};
            if (si.psi.soi_family == AF_INET) {
                inet_ntop(AF_INET, &ini->insi_laddr.ina_46.i46a_addr4, laddr, sizeof(laddr));
                inet_ntop(AF_INET, &ini->insi_faddr.ina_46.i46a_addr4, faddr, sizeof(faddr));
            } else {
                inet_ntop(AF_INET6, &ini->insi_laddr.ina_6, laddr, sizeof(laddr));
                inet_ntop(AF_INET6, &ini->insi_faddr.ina_6, faddr, sizeof(faddr));
            }

            printf("pid=%d\n", (int)pid);
            printf("path=%s\n", path);
            printf("local=%s:%d\n", laddr, lport_a == want ? lport_a : lport_b);
            printf("foreign=%s:%d\n", faddr, ntohs((uint16_t)ini->insi_fport));
            printf("state=%d\n", si.psi.soi_proto.pri_tcp.tcpsi_state);
            printf("raw_lport=%d (ntohs=%d, plain=%d)\n", raw_lport, lport_a, lport_b);

            free(fds);
            free(pids);
            return 0;
        }
        free(fds);
    }

    free(pids);
    printf("not found\n");
    return 1;
}
