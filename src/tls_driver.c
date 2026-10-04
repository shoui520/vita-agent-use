/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "tls_driver.h"
#include <mbedtls/platform_util.h>
#include <string.h>

void vau_tls_driver_close(struct vau_tls_driver *d,int error)
{
    if (!d) return;
    vau_connection_close(&d->connection);
    mbedtls_platform_zeroize(d->input,sizeof(d->input));
    d->active=0;
    d->error=error;
    d->work=VAU_TLS_CLOSED;
}
int vau_tls_driver_init(struct vau_tls_driver *d,mbedtls_ssl_context *tls,
                         struct vau_service *s,uint64_t now)
{
    if (!d) return VAU_INVALID;
    memset(d,0,sizeof(*d));
    d->tls=tls;
    d->started_us=d->last_us=now;
    if (!tls || !s || mbedtls_ssl_is_handshake_over(tls) || vau_service_transport_poll(s)<0) {
        vau_tls_driver_close(d,VAU_DENIED);
        return VAU_DENIED;
    }
    d->generation=s->auth.stop_generation;
    return VAU_OK;
}
static enum vau_tls_work result(struct vau_tls_driver *d,int rc)
{
    if (rc==MBEDTLS_ERR_SSL_WANT_READ) d->work=VAU_TLS_WAIT_READ;
    else if (rc==MBEDTLS_ERR_SSL_WANT_WRITE) d->work=VAU_TLS_WAIT_WRITE;
    else if (rc<0) vau_tls_driver_close(d,rc);
    else d->work=VAU_TLS_RUN;
    return d->work;
}
enum vau_tls_work vau_tls_driver_step(struct vau_tls_driver *d,struct vau_service *s,
                                      const struct vau_native_api *api,uint64_t now)
{
    if (!d) return VAU_TLS_CLOSED;
    if (d->work==VAU_TLS_CLOSED) return d->work;
    if (!s || !api || !d->tls || now<d->last_us || vau_service_transport_poll(s)<0 ||
        d->generation!=s->auth.stop_generation) {
        vau_tls_driver_close(d,VAU_DENIED);
        return d->work;
    }
    d->last_us=now;
    if (!d->active) {
        if (now-d->started_us>=VAU_TLS_HANDSHAKE_US) {
            vau_tls_driver_close(d,VAU_DENIED);
            return d->work;
        }
        int rc=mbedtls_ssl_handshake_step(d->tls);
        if (rc!=0) return result(d,rc);
        if (mbedtls_ssl_is_handshake_over(d->tls)) {
            if (mbedtls_ssl_get_verify_result(d->tls)!=0 ||
                !mbedtls_ssl_get_peer_cert(d->tls) ||
                vau_connection_init(&d->connection,s,now)<0) {
                vau_tls_driver_close(d,VAU_DENIED);
                return d->work;
            }
            d->active=1;
        }
        return result(d,0);
    }
    if (vau_connection_poll(&d->connection,s,now)<0) {
        vau_tls_driver_close(d,VAU_DENIED);
        return d->work;
    }
    int rc;
    if(d->connection.state==VAU_CONNECTION_READING && vau_connection_push(&d->connection,s,api,now)<0) {
        vau_tls_driver_close(d,VAU_DEVICE_ERROR);return d->work;
    }
    if (d->connection.state==VAU_CONNECTION_READING) {
        rc=mbedtls_ssl_read(d->tls,d->input,sizeof(d->input));
        if (rc<0) return result(d,rc);
        if (!rc) {
            vau_tls_driver_close(d,0);
            return d->work;
        }
        rc=vau_connection_feed(&d->connection,s,api,now,d->input,(size_t)rc);
        mbedtls_platform_zeroize(d->input,sizeof(d->input));
    } else {
        /* Keep this exact pointer/length unchanged across WANT_READ/WRITE. */
        size_t size=0;
        const unsigned char *output=vau_connection_output(&d->connection,&size);
        if (!output || !size) { vau_tls_driver_close(d,VAU_DEVICE_ERROR); return d->work; }
        rc=mbedtls_ssl_write(d->tls,output,size);
        if (rc<0) return result(d,rc);
        if (!rc) {
            vau_tls_driver_close(d,VAU_DEVICE_ERROR);
            return d->work;
        }
        rc=vau_connection_written(&d->connection,s,now,(size_t)rc);
    }
    if (rc<0 || d->connection.state==VAU_CONNECTION_CLOSED) {
        vau_tls_driver_close(d,rc);
        return d->work;
    }
    return result(d,0);
}
