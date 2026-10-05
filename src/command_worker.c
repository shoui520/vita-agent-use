/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "command_worker.h"
#include "notification_worker.h"
#include <string.h>
static void trace(struct vau_command_worker *w,unsigned stage,int result,int detail)
{
    if(w->trace && (stage!=w->trace_stage || result!=w->trace_result || detail!=w->trace_detail)) {
        w->trace_stage=stage;w->trace_result=result;w->trace_detail=detail;
        w->trace(stage,result,detail);
    }
}
static int disconnect(struct vau_command_worker *w)
{
    trace(w,5,w->driver.error,w->client.error);
    for(unsigned i=0;i<VAU_AUTH_SLOTS;i++) {
        struct vau_session *session=&w->service->auth.entries[i].session;
        for(unsigned j=0;j<4;j++)if(session->log_ids[j]) {
            char result[3500];
            if(w->api->log_watch)(void)w->api->log_watch(w->api->context,session->subject,2,NULL,NULL,session->log_ids[j],result,sizeof(result));
            session->log_ids[j]=0;
        }
        session->perf_push=0;
        if(session->run_id[0]){strcpy(session->run_phase,"connection_lost");session->run_id[0]=0;}
    }
    if(w->api->approval_cancel)w->api->approval_cancel(w->api->context);
    if (w->connected) vau_tls_driver_close(&w->driver,w->driver.error);
    w->connected=0;
    int rc=vau_net_waiter_detach(&w->waiter);
    if (rc>=0) vau_net_close(&w->client);
    return rc;
}
int vau_command_worker_close(struct vau_command_worker *w,int error)
{
    if (!w || !w->initialized) return VAU_INVALID;
    w->running=0; w->error=error;
    if (!w->service->auth.stopped) vau_auth_stop(&w->service->auth);
    if (w->notifications) (void)vau_notification_worker_poll(w->notifications,w->api->clock(w->api->context));
    int rc=disconnect(w);
    trace(w,6,error,w->waiter.error);
    int closed=vau_net_waiter_close(&w->waiter);
    if (closed<0) rc=closed;
    /* Never close a descriptor while a failed detach/destroy retains interest.
     * Keeping it owned lets a later close retry finish in the correct order. */
    if (w->waiter.fd!=w->client.fd || w->waiter.id<0) vau_net_close(&w->client);
    if (w->waiter.fd!=w->listener.fd || w->waiter.id<0) vau_net_close(&w->listener);
    if (w->service->input.initialized) {
        int input=vau_input_owner_poll(&w->service->input,&w->service->auth);
        if (input<0) rc=input;
    }
    if (rc<0) w->error=rc;
    return rc;
}
static int live_grant(const struct vau_service *s,uint64_t now)
{
    for(unsigned i=0;i<VAU_AUTH_SLOTS;i++)
        if(s->auth.entries[i].handle && now<s->auth.entries[i].expires_us)return 1;
    return 0;
}
int vau_command_worker_init(struct vau_command_worker *w,struct vau_service *s,
    const struct vau_native_api *api,struct vau_tls_server *server,uint16_t port)
{
    if (!w || !s || !api || !api->clock || !server || !server->ready || server->pairing || !port)
        return VAU_INVALID;
    memset(w,0,sizeof(*w));
    w->service=s; w->api=api; w->server=server; w->initialized=1;
    vau_net_socket_init(&w->listener); vau_net_socket_init(&w->client); vau_net_waiter_init(&w->waiter);
    int rc=vau_service_transport_poll(s);
    if(rc>=0 && !live_grant(s,api->clock(api->context)))rc=VAU_EXPIRED;
    if (rc>=0) rc=vau_net_waiter_open(&w->waiter);
    if (rc>=0) rc=vau_net_listen(&w->listener,port);
    if (rc<0) { (void)vau_command_worker_close(w,rc); return rc; }
    w->last_us=api->clock(api->context); w->next_accept_us=w->last_us;
    w->generation=s->auth.stop_generation; w->running=1;
    return VAU_OK;
}
int vau_command_worker_attach_notifications(struct vau_command_worker *w,
    struct vau_notification_worker *notifications)
{
    if (!w || !w->initialized || !w->running || w->notifications || !notifications ||
        !notifications->initialized || !notifications->started || notifications->service!=w->service ||
        atomic_load_explicit(&notifications->stopping,memory_order_acquire) ||
        atomic_load_explicit(&notifications->exited,memory_order_acquire)) return VAU_DENIED;
    w->notifications=notifications;
    return VAU_OK;
}
static int fail(struct vau_command_worker *w,int error)
{ (void)vau_command_worker_close(w,error); return error; }
int vau_command_worker_step(struct vau_command_worker *w)
{
    if (!w || !w->running) return VAU_DENIED;
    uint64_t now=w->api->clock(w->api->context);
    int available=vau_service_poll(w->service);
    /* Native content work must be observed even when stop ends this session. */
    if(w->api->approval_poll)w->api->approval_poll(w->api->context);
    if (now<w->last_us || w->service->auth.stopped ||
        w->generation!=w->service->auth.stop_generation) return fail(w,VAU_DENIED);
    w->last_us=now;
    /* Once every transient grant expires/revokes, return ownership to the
     * saved-peer listener. Persistent consent is kept on disk; this is not a
     * physical stop or a request to pair the PC again. */
    if(!live_grant(w->service,now))return fail(w,VAU_EXPIRED);
    if(available<0) {
        int detail=w->service->stop.observation_error;
        if(!w->monitor_paused || available!=w->monitor_result || detail!=w->monitor_detail)
            trace(w,7,available,detail);
        w->monitor_paused=1;
        w->monitor_result=available;w->monitor_detail=detail;
    }
    if(available>=0 && w->monitor_paused) {w->monitor_paused=0;trace(w,8,0,0);}
    if (w->notifications) (void)vau_notification_worker_poll(w->notifications,now);
    if (!w->connected) {
        trace(w,1,0,0);
        if (now<w->next_accept_us) {
            uint64_t remaining=w->next_accept_us-now;
            int rc=vau_net_pause(remaining<VAU_WORKER_WAIT_US ? (unsigned)remaining : VAU_WORKER_WAIT_US);
            return rc<0 ? fail(w,rc) : VAU_OK;
        }
        int ready=vau_net_wait(&w->waiter,&w->listener,0,VAU_WORKER_WAIT_US);
        if (ready<0) return fail(w,ready);
        if (!ready) return VAU_OK;
        if(!live_grant(w->service,w->api->clock(w->api->context)))return fail(w,VAU_EXPIRED);
        if (vau_service_transport_poll(w->service)<0) {
            if(w->service->auth.stopped)return fail(w,VAU_DENIED);
            return VAU_OK;
        }
        int rc=vau_net_accept(&w->listener,&w->client);
        if (rc==1) return VAU_OK;
        if (rc<0) return fail(w,rc);
        now=w->api->clock(w->api->context);
        if (now<w->last_us || now>UINT64_MAX-VAU_WORKER_ADMISSION_US) return fail(w,VAU_DEVICE_ERROR);
        w->last_us=now; w->next_accept_us=now+VAU_WORKER_ADMISSION_US;
        if (vau_net_waiter_detach(&w->waiter)<0) return fail(w,VAU_DEVICE_ERROR);
        if (vau_tls_server_reset(w->server)<0) return fail(w,VAU_DEVICE_ERROR);
        mbedtls_ssl_set_bio(&w->server->channel,&w->client,vau_net_send,vau_net_recv,NULL);
        rc=vau_tls_driver_init(&w->driver,&w->server->channel,w->service,now);
        if (rc<0) return fail(w,rc);
        w->connected=1;
        return VAU_OK;
    }
    trace(w,!w->driver.active ? 2:w->driver.connection.state==VAU_CONNECTION_READING ? 3:4,0,0);
    if (w->driver.work==VAU_TLS_WAIT_READ || w->driver.work==VAU_TLS_WAIT_WRITE) {
        int ready=vau_net_wait(&w->waiter,&w->client,w->driver.work==VAU_TLS_WAIT_WRITE,VAU_WORKER_WAIT_US);
        if (ready<0) return fail(w,ready);
        now=w->api->clock(w->api->context);
        if (now<w->last_us) return fail(w,VAU_DEVICE_ERROR);
        w->last_us=now;
    }
    if(!live_grant(w->service,now))return fail(w,VAU_EXPIRED);
    if (vau_tls_driver_step(&w->driver,w->service,w->api,now)==VAU_TLS_CLOSED) {
        if (disconnect(w)<0) return fail(w,VAU_DEVICE_ERROR);
    }
    return VAU_OK;
}
