#include "xtun.h"
#include "xsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <iphlpapi.h>
#include <netioapi.h>
#include <bcrypt.h>
#include <sddl.h>

struct XtDevice {
    HMODULE dll;
    void *adapter, *session;
    void *(WINAPI *CreateAdapter)(LPCWSTR, LPCWSTR, const GUID *);
    void (WINAPI *CloseAdapter)(void *);
    void (WINAPI *GetAdapterLUID)(void *, NET_LUID *);
    void *(WINAPI *StartSession)(void *, DWORD);
    void (WINAPI *EndSession)(void *);
    HANDLE (WINAPI *GetReadWaitEvent)(void *);
    BYTE *(WINAPI *ReceivePacket)(void *, DWORD *);
    void (WINAPI *ReleaseReceivePacket)(void *, BYTE *);
    BYTE *(WINAPI *AllocateSendPacket)(void *, DWORD);
    void (WINAPI *SendPacket)(void *, BYTE *);
    HANDLE stop, thread;
    CRITICAL_SECTION lock;
    NET_LUID luid;
    MIB_UNICASTIPADDRESS_ROW address;
    MIB_IPFORWARD_ROW2 routes[XT_MAX_ROUTES + 3]; unsigned route_count;
    int address_set, failed;
    XtDeviceStats stats;
    unsigned head, count;
    struct { DWORD n; BYTE bytes[XT_MTU]; } queue[64];
};
uint64_t xt_now(void) { return GetTickCount64(); }
int xt_random(void *out, size_t n) { return n <= ULONG_MAX && BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0; }
int xt_key_write(const char *path, const void *data, size_t n) {
    WCHAR wide[2048]; PSECURITY_DESCRIPTOR sd = NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 2048) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)", SDDL_REVISION_1, &sd, NULL)) return 0;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), sd, FALSE};
    HANDLE f = CreateFileW(wide, GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    LocalFree(sd);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD written = 0; int ok = WriteFile(f, data, (DWORD)n, &written, NULL) && written == n;
    CloseHandle(f); return ok;
}
static void on_signal(int sig) { (void)sig; xt_stop = 1; }
static BOOL WINAPI console_signal(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) { xt_stop = 1; return TRUE; }
    return FALSE;
}
void xt_install_signals(void) { signal(SIGINT, on_signal); signal(SIGTERM, on_signal); SetConsoleCtrlHandler(console_signal, TRUE); }
static DWORD WINAPI reader(void *p) {
    XtDevice *d = p; HANDLE waits[2] = {d->stop, d->GetReadWaitEvent(d->session)};
    while (WaitForSingleObject(d->stop, 0) == WAIT_TIMEOUT) {
        DWORD n; BYTE *packet = d->ReceivePacket(d->session, &n);
        if (!packet) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) { EnterCriticalSection(&d->lock); d->failed = 1; LeaveCriticalSection(&d->lock); break; }
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_FAILED) {
                EnterCriticalSection(&d->lock); d->failed = 1; LeaveCriticalSection(&d->lock); break;
            }
            continue;
        }
        EnterCriticalSection(&d->lock);
        if (n <= XT_MTU && d->count < 64) {
            unsigned tail = (d->head+d->count) % 64;
            memcpy(d->queue[tail].bytes, packet, n); d->queue[tail].n = n; ++d->count;
        } else if (n > XT_MTU) ++d->stats.oversize;
        else ++d->stats.queue_full;
        LeaveCriticalSection(&d->lock);
        d->ReleaseReceivePacket(d->session, packet);
    }
    return 0;
}
XtDevice *xt_device_open(const XtConfig *c, char error[256]) {
    XtDevice *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    InitializeCriticalSection(&d->lock);
    WCHAR path[2048], name[32];
    DWORD length = GetModuleFileNameW(NULL, path, 2048);
    if (!length || length >= 2048) goto bad;
    WCHAR *slash = wcsrchr(path, L'\\');
    if (!slash || slash-path > 2000) goto bad;
    wcscpy(slash+1, L"wintun.dll");
    d->dll = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!d->dll) goto bad;
#define LOAD(name) do { FARPROC proc = GetProcAddress(d->dll, "Wintun" #name); memcpy(&d->name, &proc, sizeof(proc)); if (!d->name) goto bad; } while (0)
    LOAD(CreateAdapter); LOAD(CloseAdapter); LOAD(GetAdapterLUID); LOAD(StartSession); LOAD(EndSession);
    LOAD(GetReadWaitEvent); LOAD(ReceivePacket); LOAD(ReleaseReceivePacket); LOAD(AllocateSendPacket); LOAD(SendPacket);
#undef LOAD
    if (!MultiByteToWideChar(CP_UTF8, 0, c->name, -1, name, 32)) goto bad;
    d->adapter = d->CreateAdapter(name, L"XTun", NULL);
    if (!d->adapter) goto bad;
    d->GetAdapterLUID(d->adapter, &d->luid);
    d->session = d->StartSession(d->adapter, 0x400000);
    if (!d->session) goto bad;
    InitializeUnicastIpAddressEntry(&d->address);
    d->address.InterfaceLuid = d->luid;
    d->address.Address.si_family = AF_INET;
    d->address.Address.Ipv4.sin_addr.s_addr = htonl(c->address);
    d->address.OnLinkPrefixLength = 32;
    d->address.DadState = IpDadStatePreferred;
    DWORD status = CreateUnicastIpAddressEntry(&d->address);
    if (status != NO_ERROR) { SetLastError(status); goto bad; }
    d->address_set = 1;
    MIB_IPINTERFACE_ROW iface;
    InitializeIpInterfaceEntry(&iface); iface.Family = AF_INET; iface.InterfaceLuid = d->luid;
    status = GetIpInterfaceEntry(&iface);
    if (status != NO_ERROR) { SetLastError(status); goto bad; }
    iface.NlMtu = XT_MTU; iface.SitePrefixLength = 0; iface.UseAutomaticMetric = FALSE; iface.Metric = 5;
    iface.DadTransmits = 0; iface.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    status = SetIpInterfaceEntry(&iface);
    if (status != NO_ERROR) { SetLastError(status); goto bad; }
    d->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!d->stop) goto bad;
    d->thread = CreateThread(NULL, 0, reader, d, 0, NULL);
    if (!d->thread) goto bad;
    return d;
bad:
    snprintf(error, 256, "Windows error %lu (administrator access and adjacent signed wintun.dll required)", GetLastError());
    xt_device_close(d); return NULL;
}
static DWORD add_route(XtDevice *d, NET_LUID luid, uint32_t network, UINT8 prefix,
                       SOCKADDR_INET next_hop, ULONG metric) {
    MIB_IPFORWARD_ROW2 route;
    InitializeIpForwardEntry(&route);
    route.InterfaceLuid = luid;
    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(network);
    route.DestinationPrefix.PrefixLength = prefix;
    route.NextHop = next_hop;
    route.Metric = metric;
    route.Protocol = MIB_IPPROTO_NETMGMT;
    DWORD status = CreateIpForwardEntry2(&route);
    if (status == NO_ERROR) d->routes[d->route_count++] = route;
    return status;
}
static void remove_routes(XtDevice *d) {
    while (d->route_count) {
        DWORD status = DeleteIpForwardEntry2(&d->routes[--d->route_count]);
        if (status != NO_ERROR && status != ERROR_NOT_FOUND)
            fprintf(stderr, "route cleanup failed: %lu\n", status);
    }
}
static DWORD best_route(uint32_t ip, MIB_IPFORWARD_ROW2 *route) {
    SOCKADDR_INET dest = {0}, source;
    dest.si_family = AF_INET;
    dest.Ipv4.sin_addr.s_addr = htonl(ip);
    DWORD index;
    DWORD status = GetBestInterfaceEx((struct sockaddr *)&dest, &index);
    if (status != NO_ERROR) return status;
    return GetBestRoute2(NULL, index, NULL, &dest, 0, route, &source);
}
static DWORD set_adapter_dns(XtDevice *d, uint32_t ip) {
    /* Windows SDK DNS_INTERFACE_SETTINGS v1, absent in older MinGW headers. */
    struct {
        ULONG Version;
        ULONG64 Flags;
        PWSTR Domain, NameServer, SearchList;
        ULONG RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName;
        PWSTR ProfileNameServer;
    } settings = {0};
    typedef DWORD (WINAPI *SetDnsSettings)(GUID, const void *);
    HMODULE dll = GetModuleHandleW(L"iphlpapi.dll");
    FARPROC proc = dll ? GetProcAddress(dll, "SetInterfaceDnsSettings") : NULL;
    if (!proc) return ERROR_NOT_SUPPORTED;
    SetDnsSettings set_dns;
    memcpy(&set_dns, &proc, sizeof(set_dns));
    GUID guid;
    DWORD status = ConvertInterfaceLuidToGuid(&d->luid, &guid);
    if (status != NO_ERROR) return status;
    WCHAR name[16];
    if (swprintf(name, sizeof(name)/sizeof(*name), L"%u.%u.%u.%u",
                 ip >> 24, (ip >> 16) & 255u, (ip >> 8) & 255u, ip & 255u) < 0)
        return ERROR_INVALID_PARAMETER;
    settings.Version = 1;
    settings.Flags = 0x0002; /* DNS_SETTING_NAMESERVER */
    settings.NameServer = name;
    return set_dns(guid, &settings);
}
int xt_device_routes(XtDevice *d, const XtConfig *c, char error[256]) {
    SOCKADDR_INET on_link = {0};
    on_link.si_family = AF_INET;
    DWORD status;
    NET_LUID outer_luid = {0};
    const char *operation = "endpoint route lookup";
    if (c->full_tunnel) {
        MIB_IPFORWARD_ROW2 outer;
        status = best_route(c->endpoint_address, &outer);
        if (status != NO_ERROR) goto bad;
        if (outer.InterfaceLuid.Value == d->luid.Value) { status = ERROR_INVALID_PARAMETER; goto bad; }
        outer_luid = outer.InterfaceLuid;
        if (outer.DestinationPrefix.PrefixLength != 32) {
            operation = "endpoint route creation";
            status = add_route(d, outer.InterfaceLuid, c->endpoint_address, 32, outer.NextHop, outer.Metric);
            if (status != NO_ERROR) goto bad;
        }
    }
    operation = "tunnel route creation";
    for (unsigned i = 0; i < c->route_count; ++i) {
        const XtRoute *r = &c->routes[i];
        status = add_route(d, d->luid, r->network, (UINT8)r->prefix, on_link, 5);
        if (status != NO_ERROR) goto bad;
    }
    if (c->full_tunnel) {
        /* Cover the original default without replacing it or changing its metric. */
        status = add_route(d, d->luid, 0, 1, on_link, 5);
        if (status != NO_ERROR) goto bad;
        status = add_route(d, d->luid, 0x80000000u, 1, on_link, 5);
        if (status != NO_ERROR) goto bad;
        MIB_IPFORWARD_ROW2 route;
        operation = "endpoint route verification";
        status = best_route(c->endpoint_address, &route);
        if (status != NO_ERROR) goto bad;
        if (route.InterfaceLuid.Value != outer_luid.Value || route.DestinationPrefix.PrefixLength != 32) {
            status = ERROR_INVALID_PARAMETER; goto bad;
        }
        if (c->dns_address) {
            operation = "DNS route verification";
            status = best_route(c->dns_address, &route);
            if (status != NO_ERROR) goto bad;
            if (route.InterfaceLuid.Value != d->luid.Value) { status = ERROR_INVALID_PARAMETER; goto bad; }
            operation = "Wintun DNS setup";
            status = set_adapter_dns(d, c->dns_address);
            if (status != NO_ERROR) goto bad;
        }
    }
    return 1;
bad:
    snprintf(error, 256, "%s failed: %lu", operation, status);
    remove_routes(d);
    return 0;
}
int xt_device_read(XtDevice *d, void *out, size_t cap) {
    int n = 0; EnterCriticalSection(&d->lock);
    if (d->failed) n = -1;
    else if (d->count) {
        n = (int)d->queue[d->head].n;
        if ((size_t)n <= cap) memcpy(out, d->queue[d->head].bytes, (size_t)n); else n = -1;
        d->head = (d->head+1) % 64; --d->count;
    }
    LeaveCriticalSection(&d->lock); return n;
}
int xt_device_write(XtDevice *d, const void *bytes, size_t n) {
    BYTE *packet = d->AllocateSendPacket(d->session, (DWORD)n);
    if (!packet) {
        DWORD error = GetLastError();
        EnterCriticalSection(&d->lock);
        if (error == ERROR_BUFFER_OVERFLOW) ++d->stats.write_ring_full;
        else ++d->stats.write_error;
        LeaveCriticalSection(&d->lock);
        return 0;
    }
    memcpy(packet, bytes, n); d->SendPacket(d->session, packet); return (int)n;
}
XtDeviceStats xt_device_stats(XtDevice *d) {
    if (!d) return (XtDeviceStats){0};
    EnterCriticalSection(&d->lock);
    XtDeviceStats stats = d->stats;
    LeaveCriticalSection(&d->lock);
    return stats;
}
void xt_device_close(XtDevice *d) {
    if (!d) return;
    if (d->stop) SetEvent(d->stop);
    if (d->thread) { WaitForSingleObject(d->thread, INFINITE); CloseHandle(d->thread); }
    if (d->stop) CloseHandle(d->stop);
    remove_routes(d);
    if (d->address_set) DeleteUnicastIpAddressEntry(&d->address);
    if (d->session) d->EndSession(d->session);
    if (d->adapter) d->CloseAdapter(d->adapter);
    if (d->dll) FreeLibrary(d->dll);
    DeleteCriticalSection(&d->lock); free(d);
}
#else
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct XtDevice { int fd, index; char name[IFNAMSIZ]; XtRoute routes[XT_MAX_ROUTES]; unsigned route_count; };
uint64_t xt_now(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000; }
int xt_random(void *out, size_t n) {
    size_t at = 0;
    while (at < n) { ssize_t got = getrandom((char *)out+at, n-at, 0); if (got < 0 && errno == EINTR) continue; if (got <= 0) return 0; at += (size_t)got; }
    return 1;
}
int xt_key_write(const char *path, const void *data, size_t n) {
    int f = open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
    if (f < 0) return 0;
    ssize_t written = write(f, data, n); int ok = written == (ssize_t)n;
    if (close(f)) ok = 0;
    return ok;
}
static void on_signal(int sig) { (void)sig; xt_stop = 1; }
void xt_install_signals(void) { signal(SIGINT, on_signal); signal(SIGTERM, on_signal); }
static int route_change(XtDevice *d, const XtRoute *r, int add) {
    struct {
        struct nlmsghdr h;
        struct rtmsg msg;
        unsigned char attrs[64];
    } request = {0};
    request.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.h.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    request.h.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|(add ? NLM_F_CREATE|NLM_F_EXCL : 0);
    request.h.nlmsg_seq = 1;
    request.msg.rtm_family = AF_INET; request.msg.rtm_dst_len = (unsigned char)r->prefix;
    request.msg.rtm_table = RT_TABLE_MAIN; request.msg.rtm_protocol = RTPROT_STATIC;
    request.msg.rtm_scope = RT_SCOPE_LINK; request.msg.rtm_type = RTN_UNICAST;
    struct rtattr *a = (void *)((unsigned char *)&request + NLMSG_ALIGN(request.h.nlmsg_len));
    a->rta_type = RTA_DST; a->rta_len = RTA_LENGTH(4); uint32_t network = htonl(r->network);
    memcpy(RTA_DATA(a), &network, 4); request.h.nlmsg_len = NLMSG_ALIGN(request.h.nlmsg_len)+RTA_ALIGN(a->rta_len);
    a = (void *)((unsigned char *)&request + NLMSG_ALIGN(request.h.nlmsg_len));
    a->rta_type = RTA_OIF; a->rta_len = RTA_LENGTH(sizeof(d->index)); memcpy(RTA_DATA(a), &d->index, sizeof(d->index));
    request.h.nlmsg_len = NLMSG_ALIGN(request.h.nlmsg_len)+RTA_ALIGN(a->rta_len);
    int fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return 0;
    struct timeval timeout = {2,0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_nl address = {0}; address.nl_family = AF_NETLINK;
    int ok = 0;
    if (sendto(fd, &request, request.h.nlmsg_len, 0, (void *)&address, sizeof(address)) == (ssize_t)request.h.nlmsg_len) {
        unsigned char response[4096]; ssize_t n = recv(fd, response, sizeof(response), 0);
        for (struct nlmsghdr *h = (void *)response; n > 0 && NLMSG_OK(h,n); h = NLMSG_NEXT(h,n))
            if (h->nlmsg_type == NLMSG_ERROR && h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                int code = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                ok = code == 0; if (code) errno = -code; break;
            }
    }
    int saved = errno; close(fd); errno = saved; return ok;
}
XtDevice *xt_device_open(const XtConfig *c, char error[256]) {
    XtDevice *d = calloc(1, sizeof(*d)); if (!d) return NULL;
    d->fd = -1;
    if (if_nametoindex(c->name)) { snprintf(error, 256, "interface already exists; refusing to modify it"); free(d); return NULL; }
    d->fd = open("/dev/net/tun", O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (d->fd < 0) goto bad;
    struct ifreq req = {0};
    if (strlen(c->name) >= IFNAMSIZ) { errno = EINVAL; goto bad; }
    strcpy(req.ifr_name, c->name); req.ifr_flags = IFF_TUN|IFF_NO_PI;
    if (ioctl(d->fd, TUNSETIFF, &req) < 0) goto bad;
    strcpy(d->name, req.ifr_name); d->index = (int)if_nametoindex(d->name);
    int s = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if (s < 0) goto bad;
    struct sockaddr_in *ip = (void *)&req.ifr_addr; ip->sin_family = AF_INET; ip->sin_addr.s_addr = htonl(c->address);
    int ok = ioctl(s, SIOCSIFADDR, &req) == 0;
    ip->sin_addr.s_addr = htonl(UINT32_MAX); ok = ok && ioctl(s, SIOCSIFNETMASK, &req) == 0;
    req.ifr_mtu = XT_MTU; ok = ok && ioctl(s, SIOCSIFMTU, &req) == 0;
    req.ifr_flags = IFF_UP|IFF_POINTOPOINT; ok = ok && ioctl(s, SIOCSIFFLAGS, &req) == 0;
    int saved = errno; close(s); errno = saved;
    if (!ok) goto bad;
    return d;
bad:
    snprintf(error, 256, "%s", strerror(errno)); xt_device_close(d); return NULL;
}
int xt_device_routes(XtDevice *d, const XtConfig *c, char error[256]) {
    for (unsigned i = 0; i < c->route_count; ++i) {
        if (!route_change(d, &c->routes[i], 1)) { snprintf(error, 256, "%s", strerror(errno)); return 0; }
        d->routes[d->route_count++] = c->routes[i];
    }
    return 1;
}
int xt_device_read(XtDevice *d, void *out, size_t cap) {
    ssize_t n = read(d->fd, out, cap);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    return (int)n;
}
int xt_device_write(XtDevice *d, const void *bytes, size_t n) { return (int)write(d->fd, bytes, n); }
int xt_device_fd(const XtDevice *d) { return d->fd; }
XtDeviceStats xt_device_stats(XtDevice *d) { (void)d; return (XtDeviceStats){0}; }
void xt_device_close(XtDevice *d) {
    if (!d) return;
    for (unsigned i = 0; i < d->route_count; ++i) (void)route_change(d, &d->routes[i], 0);
    if (d->fd >= 0) close(d->fd); /* nonpersistent TUN disappears */
    free(d);
}
#endif
