#ifndef MATTER_WIRE_FAULTS_H
#define MATTER_WIRE_FAULTS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
    size_t calls,failures,live,bytes,peak;
    unsigned ack_dropped,unacknowledged,ack_before_completion,ack_after_completion;
    unsigned wrong_role_acks,target_outcome,target_attempts;
} Wire_Stats;
extern Wire_Stats wire_stats;
extern bool wire_completion_pending;
void* wire_calloc(size_t,size_t);
void* wire_malloc(size_t);
void wire_free(void*);
void wire_fail_after(size_t);
/* 0=off, 1=all matching ACKs, 2=exactly one matching ACK. */
void wire_ack_fault(unsigned);
#endif
