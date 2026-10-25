#ifndef MATTER_COMPAT_H_INCLUDED
#define MATTER_COMPAT_H_INCLUDED 1

/* Explicit legacy SDK/CSA-test compatibility, not a conformance waiver.
 * Keep the Core 1.6.1 behavior by default. Define the umbrella to 1, or select
 * individual exceptions. All objects of one library must use the same values.
 * See doc/oss/csa75-compatibility.md for scope and original test identities. */
#ifndef MATTER_CSA_COMPAT
#define MATTER_CSA_COMPAT 0
#endif
#ifndef MATTER_CSA_COMPAT_PENDING_ROOT
#define MATTER_CSA_COMPAT_PENDING_ROOT MATTER_CSA_COMPAT
#endif
#ifndef MATTER_CSA_COMPAT_PROXY_VIEW
#define MATTER_CSA_COMPAT_PROXY_VIEW MATTER_CSA_COMPAT
#endif
#ifndef MATTER_CSA_COMPAT_REVOKE_REPLY
#define MATTER_CSA_COMPAT_REVOKE_REPLY MATTER_CSA_COMPAT
#endif
#ifndef MATTER_CSA_COMPAT_FAILSAFE_REARM
#define MATTER_CSA_COMPAT_FAILSAFE_REARM MATTER_CSA_COMPAT
#endif
#ifndef MATTER_CSA_COMPAT_FAILSAFE_SECONDS
#define MATTER_CSA_COMPAT_FAILSAFE_SECONDS 20
#endif
#if (MATTER_CSA_COMPAT != 0 && MATTER_CSA_COMPAT != 1) || \
    (MATTER_CSA_COMPAT_PENDING_ROOT != 0 && MATTER_CSA_COMPAT_PENDING_ROOT != 1) || \
    (MATTER_CSA_COMPAT_PROXY_VIEW != 0 && MATTER_CSA_COMPAT_PROXY_VIEW != 1) || \
    (MATTER_CSA_COMPAT_REVOKE_REPLY != 0 && MATTER_CSA_COMPAT_REVOKE_REPLY != 1) || \
    (MATTER_CSA_COMPAT_FAILSAFE_REARM != 0 && MATTER_CSA_COMPAT_FAILSAFE_REARM != 1)
#error Matter compatibility definitions must be 0 or 1
#endif
#if MATTER_CSA_COMPAT_FAILSAFE_SECONDS < 1 || MATTER_CSA_COMPAT_FAILSAFE_SECONDS > 65535
#error Matter compatibility fail-safe duration must be in 1..65535 seconds
#endif
#endif
