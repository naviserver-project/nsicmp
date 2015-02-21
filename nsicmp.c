/*
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 *
 */

/*
 * nsicmp.c -- ICMP module
 *
 *  ICMP requests
 *    ns_ping host {-count n -timeout n -size n}
 *    performs ICMP ECHO queries
 *     where
 *       -count n specifies to send n ICMP packets
 *       -timeout n specifies to wait n seconds for reply
 *       -size n specifies n bytes of data to be sent
 *       all these options are optional
 *
 *     returns the following Tcl list:
 *      { requests_sent requests_received loss_percentage rtt_min rtt_avg rtt_max }
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define SNMP_VERSION  "1.0"

#define timediff(t1, t2) ((double)(t2.tv_sec - t1.tv_sec) * 1000.0 + (double)(t2.tv_usec - t1.tv_usec) / 1000.0)
#define stimediff(t1, t2) ((double)(t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec) / 1000000.0)
#define freeports(p)  while (p) { IcmpPort *next = p->next; ns_free(p); p = next; }

typedef struct _icmpPort {
    struct _icmpPort *next, *prev;
    int fd;
    int id;
    int count;
    int timeout;
    int sent;
    int received;
    float rtt_min;
    float rtt_avg;
    float rtt_max;
    struct sockaddr_in sa;
    struct timeval send_time;
    struct timeval recv_time;
    char *host;
    char *name;
} IcmpPort;

typedef struct _server {
    char *name;
    int id;
    int size;
    int count;
    int timeout;
    int sockets;
    Ns_Cond cond;
    Ns_Mutex mutex;
    IcmpPort *head;
    IcmpPort *tail;
} Server;

static int PingCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static int IcmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);

static Ns_TclTraceProc IcmpInterpInit;

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Load the config parameters, setup the structures, and
 *	listen on the trap port.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Server will listen for SNMP traps on specified address and port.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    const char *path;
    Server *srvPtr;
    IcmpPort *icmp;
    int i, sock;

    Ns_Log(Notice, "nsicmp module version %s server: %s", SNMP_VERSION, server);

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (Server *) ns_calloc(1, sizeof(Server));
    srvPtr->name = server;
    if (!Ns_ConfigGetInt(path, "size", &srvPtr->size)) {
        srvPtr->size = 56;
    }
    if (!Ns_ConfigGetInt(path, "timeout", &srvPtr->timeout)) {
        srvPtr->timeout = 2;
    }
    if (!Ns_ConfigGetInt(path, "count", &srvPtr->count)) {
        srvPtr->count = 2;
    }
    if (!Ns_ConfigGetInt(path, "sockets", &srvPtr->sockets)) {
        srvPtr->sockets = 1;
    }
    // Initialize ICMP system
    if (srvPtr->sockets > 0) {
        for (i = 0; i < srvPtr->sockets; i++) {
            if ((sock = Ns_SockListenRaw(IPPROTO_ICMP)) == -1) {
                Ns_Log(Error, "nsicmp: couldn't create icmp socket: %s", strerror(errno));
                return NS_ERROR;
            }
            icmp = (IcmpPort *) ns_calloc(1, sizeof(IcmpPort));
            icmp->fd = sock;
            icmp->next = srvPtr->head;
            if (icmp->next) {
                icmp->next->prev = icmp;
            }
            srvPtr->head = icmp;
        }
        for (icmp = srvPtr->head; icmp->next; icmp = icmp->next) {
            srvPtr->tail = icmp;
        }
        Ns_Log(Notice, "nsicmp: allocated %d ICMP ports", srvPtr->sockets);
    }
    Ns_MutexSetName2(&srvPtr->mutex, "nsicmp", "icmp");
    Ns_TclRegisterTrace(server, IcmpInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * IcmpInterpInit --
 *
 *      Add ns_ping and ns_icmp commands to interp.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static int IcmpInterpInit(Tcl_Interp * interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_ping", PingCmd, (ClientData) arg, NULL);
    Tcl_CreateObjCommand(interp, "ns_icmp", IcmpCmd, (ClientData) arg, NULL);
    return NS_OK;
}

// Calculate checksum for given buffer
static int IcmpChksum(u_short * p, int n)
{
    register u_short answer;
    register long sum = 0;
    u_short odd_byte = 0;

    while (n > 1) {
        sum += *p++;
        n -= 2;
    }
    if (n == 1) {
        *(u_char *) (&odd_byte) = *(u_char *) p;
        sum += odd_byte;
    }
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* ones-complement,  truncate */
    return (answer);
}

static IcmpPort *IcmpLock(Server * server)
{
    Ns_Time timeout;
    IcmpPort *port;
    int status = NS_OK;

    Ns_GetTime(&timeout);
    Ns_IncrTime(&timeout, 2, 0);

    // Get next available socket
    Ns_MutexLock(&server->mutex);
    while (status == NS_OK && !(port = server->head)) {
        status = Ns_CondTimedWait(&server->cond, &server->mutex, &timeout);
    }
    if (port != NULL) {
        server->head = port->next;
        if (port->next) {
            port->next->prev = NULL;
        }
        if (port == server->tail) {
            server->tail = NULL;
        }
        if ((port->id = ++server->id) > 65535) {
            server->id = port->id = 1;
        }
        port->host = port->name = 0;
        port->next = port->prev = 0;
        port->sent = port->received = 0;
        port->count = port->timeout = 0;
        port->send_time.tv_sec = port->send_time.tv_usec = 0;
        port->recv_time.tv_sec = port->recv_time.tv_usec = 0;
        port->rtt_min = port->rtt_max = port->rtt_avg = 0;
    }
    Ns_MutexUnlock(&server->mutex);
    return port;
}

static void IcmpUnlock(Server * server, IcmpPort *port)
{
    IcmpPort *next;

    Ns_MutexLock(&server->mutex);
    while (port) {
        next = port->next;
        if (server->tail) {
            port->prev = server->tail;
            server->tail->next = port;
        }
        if (server->head == NULL) {
            server->head = port;
        }
        server->tail = port;
        port->next = 0;
        port = next;
    }
    Ns_CondBroadcast(&server->cond);
    Ns_MutexUnlock(&server->mutex);
}

static int IcmpCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;
    IcmpPort *port;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "args");
        return TCL_ERROR;
    }
    if (!strcmp(Tcl_GetString(objv[1]), "sockets")) {
        Tcl_SetObjResult(interp, Tcl_NewIntObj(server->sockets));
    } else
    if (!strcmp(Tcl_GetString(objv[1]), "list")) {
        Tcl_Obj *list = Tcl_NewListObj(0, 0);
        Ns_MutexLock(&server->mutex);
        for (port = server->head; port; port = port->next) {
            Tcl_ListObjAppendElement(interp, list, Tcl_NewIntObj(port->fd));
        }
        Ns_MutexUnlock(&server->mutex);
        Tcl_SetObjResult(interp, list);
    }
    return TCL_OK;
}

// Check host availability by simulating PING
static int PingCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *server = (Server *) arg;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-alert 0|1? ?-timeout n? ?-debug 0|1? ?-count n? ?-size n? host ...");
        return TCL_ERROR;
    }

    struct ip *ip;
    float elapsed;
    char buf[4096];
    struct icmp *icp;
    struct timeval tv;
    time_t start_time;
    struct pollfd pfds[1];
    struct sockaddr_in sa;
    int i, nports, nwait, len, hlen, loss;
    IcmpPort *sock, *port, *ports = NULL;
    socklen_t slen = sizeof(struct sockaddr);
    int count = server->count, size = server->size, timeout = server->timeout;
    int alert = 1, wait = 0, debug = 0, names = 0;

    if ((sock = IcmpLock(server)) == NULL) {
        Tcl_AppendResult(interp, "noResources: no ICMP sockets", 0);
        return TCL_ERROR;
    }

    for (i = 1; i < objc; i++) {
        if (!strcmp(Tcl_GetString(objv[i]), "-alert")) {
            if (i < objc - 1) {
                alert = atoi(Tcl_GetString(objv[i + 1]));
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-wait")) {
            if (i < objc - 1) {
                wait = atoi(Tcl_GetString(objv[i + 1]));
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-debug")) {
            if (i < objc - 1) {
                debug = atoi(Tcl_GetString(objv[i + 1]));
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-size")) {
            if (i < objc - 1) {
                if ((size = atoi(Tcl_GetString(objv[i + 1]))) < 56 || size > (int) sizeof(buf) - 8) {
                    size = 56;
                }
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-timeout")) {
            if (i < objc - 1) {
                if ((len = atoi(Tcl_GetString(objv[i + 1]))) <= 0) {
                    len = 2;
                }
                // Apply to last port
                if (ports != NULL) {
                    ports->timeout = len;
                } else {
                    timeout = len;
                }
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-count")) {
            if (i < objc - 1) {
                if ((len = atoi(Tcl_GetString(objv[i + 1]))) <= 0) {
                    len = 3;
                }
                // Apply to last port
                if (ports != NULL) {
                    ports->count = len;
                } else {
                    count = len;
                }
            }
            i++;
        } else
        if (!strcmp(Tcl_GetString(objv[i]), "-name")) {
            if (i < objc - 1 && ports != NULL) {
                ports->name = Tcl_GetString(objv[i + 1]);
                // If name is given, return full format
                names = 1;
            }
            i++;
        } else {
           // Add to the list of sockets
           port = ns_calloc(1, sizeof(IcmpPort));
           port->next = ports;
           ports = port;
           ports->fd = sock->fd;
           ports->id = sock->id;
           ports->count = count;
           ports->timeout = timeout;
           ports->host = Tcl_GetString(objv[i]);
           // If multiple hosts, return with names
           names = ports->next ? 1 : 0;
           // Resolve given host name
           if (Ns_GetSockAddr(&ports->sa, ports->host, 0) != NS_OK) {
               Tcl_AppendResult(interp, "noHost: unknown host ", ports->host, 0);
               IcmpUnlock(server, sock);
               freeports(ports);
               return TCL_ERROR;
           }
        }
    }
    if (ports == NULL) {
        Tcl_AppendResult(interp, "no hosts specified", 0);
        IcmpUnlock(server, sock);
        return TCL_ERROR;
    }
    start_time = time(0);

    while (1) {

        nports = 0;

        for (port = ports; port; port = port->next) {
             gettimeofday(&tv, 0);
             // Time since last send
             elapsed = stimediff(port->send_time, tv);
             if (port->received < port->count) {
                 // All packets are sent and timed out since last send
                 if (elapsed > port->timeout && port->sent == port->count) {
                     continue;
                 }
                 nports++;
             }
             if (port->sent < port->count && (port->sent == port->received || elapsed >= port->timeout)) {
                 icp = (struct icmp *) buf;
                 icp->icmp_type = ICMP_ECHO;
                 icp->icmp_code = 0;
                 icp->icmp_cksum = 0;
                 icp->icmp_seq = port->sent;
                 icp->icmp_id = port->id;
                 memcpy(&buf[8], &tv, sizeof(struct timeval));
                 len = size + 8;
                 icp->icmp_cksum = IcmpChksum((u_short *) icp, len);

                 if (sendto(port->fd, buf, len, 0, (struct sockaddr *) &port->sa, sizeof(port->sa)) != len) {
                     Ns_Log(Error, "ns_ping: %d/%d: %s: sendto error: %s", port->id, port->fd, ns_inet_ntoa(port->sa.sin_addr), strerror(errno));
                     continue;
                 }
                 port->sent++;
                 port->send_time = tv;
                 port->recv_time.tv_sec = 0;
                 port->recv_time.tv_usec = 0;
                 if (debug) {
                     Ns_Log(Notice, "ns_ping: %d/%d: %s: sending %d of %d, received %d, last send %.2f secs ago", port->id, port->fd, ns_inet_ntoa(port->sa.sin_addr), port->sent, port->count, port->received, elapsed);
                 }
             }
        }

        // Check the total time we spent pinging
        if (!nports || (wait > 0 && time(0) - start_time > wait)) {
            break;
        }
        pfds[0].fd = sock->fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        nwait = 500;
again:
        do {
            len = ns_poll(pfds, 1, nwait);
        } while (len < 0  && errno == EINTR);

        if (len <= 0) {
            continue;
        }
        gettimeofday(&tv, 0);
        // Receive reply packet and parse it
        if ((len = recvfrom(sock->fd, buf, sizeof(buf), 0, (struct sockaddr *) &sa, &slen)) <= 0) {
            Ns_Log(Error, "ns_ping: %d/%d: recvfrom error: %s", sock->id, sock->fd, strerror(errno));
            continue;
        }
        // IP header
        ip = (struct ip *) buf;
        if (len < (hlen = ip->ip_hl << 2) + ICMP_MINLEN) {
            if (debug) {
                Ns_Log(Notice, "ns_ping: %d/%d: corrupted packet from %s, %d bytes", sock->id, sock->fd, ns_inet_ntoa(sa.sin_addr), len);
            }
            goto again;
        }
        // ICMP header
        icp = (struct icmp *) (buf + hlen);
        if (debug) {
            Ns_Log(Notice, "ns_ping: %d/%d: received from %s %d bytes, type %d, id %d, seq %d", sock->id, sock->fd, ns_inet_ntoa(sa.sin_addr), len, icp->icmp_type, icp->icmp_id, icp->icmp_seq);
        }
        // Wrong packet
        if (icp->icmp_type != ICMP_ECHOREPLY || icp->icmp_id != sock->id) {
            if (debug) {
                Ns_Log(Notice, "ns_ping: %d/%d: invalid type %d or id %d from %s", sock->id, sock->fd, icp->icmp_type, icp->icmp_id, ns_inet_ntoa(sa.sin_addr));
            }
            goto again;
        }
        // Find the host
        for (port = ports; port; port = port->next) {
            if (port->sa.sin_addr.s_addr == sa.sin_addr.s_addr && port->received < port->sent) {
                gettimeofday(&port->recv_time, 0);
                // Take send time from the ICMP header
                memcpy(&tv, &buf[hlen + 8], sizeof(struct timeval));
                // Calculate round trip time
                elapsed = timediff(tv, port->recv_time);
                if (!port->rtt_min || elapsed < port->rtt_min) {
                    port->rtt_min = elapsed;
                }
                if (!port->rtt_max || elapsed > port->rtt_max) {
                    port->rtt_max = elapsed;
                }
                port->received++;
                port->rtt_avg = (port->rtt_avg * (port->received - 1) / port->received) + (elapsed / port->received);
                nwait = 0;
                goto again;
            }
        }
    }
    IcmpUnlock(server, sock);

    // In case of one host, fire exception, no result
    if (alert && !ports->received && !ports->next) {
        Tcl_AppendResult(interp, "noConnectivity: no reply from ", ns_inet_ntoa(ports->sa.sin_addr), 0);
        freeports(ports);
        return TCL_ERROR;
    }

    Tcl_Obj *obj = Tcl_NewListObj(0, 0);
    Tcl_SetObjResult(interp, obj);

    // Calculate statistics for all ports
    for (port = ports; port; port = port->next) {
         if (names) {
             obj = Tcl_NewListObj(0, 0);
             Tcl_ListObjAppendElement(interp, obj, Tcl_NewStringObj(port->name ? port->name : port->host, -1));
             Tcl_ListObjAppendElement(interp, Tcl_GetObjResult(interp), obj);
         }
         loss = port->received > 0 ? 100 - ((port->received * 100) / port->sent) : !port->sent ? 0 : 100;
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(port->sent));
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(port->received));
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewIntObj(loss));
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(port->rtt_min));
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(port->rtt_avg));
         Tcl_ListObjAppendElement(interp, obj, Tcl_NewDoubleObj(port->rtt_max));
    }
    freeports(ports);
    return TCL_OK;
}

