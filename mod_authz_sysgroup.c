/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This module was created by Nick Bartos using mod_authz_groupfile
 * from Apache 2.2.8 as a template */

/* This module is triggered by
 *
 *         require group <list-of-groups>
 * or
 *         require valid-system-user
 *
 * In an applicable limit/directory block for that method.
 *
 * If there are no 'require ' directives defined for
 * this request then we DECLINED.
 *
 * If there are no 'require ' directives valid for
 * this request method then we DECLINED.
 *
 * If there are any 'require group' blocks and we
 * are not in any group - we HTTP_UNAUTHORIZE
 * unless we are non-authoritative; in which
 * case we DECLINED.
 *
 * To support the 'AND'ing of groups, a user needs to be in all groups
 * specified on the 'Require group' line.  'OR'ing is supported by using
 * multiple 'Require group' lines.  For example:
 *
 * Require group ITAR chickens
 * Require group elves
 *
 * Would allow all elves to access the resource - AND -
 * allow chickens that are also a member of the ITAR group to access
 * the resource.
 *
 * Specifying 'Require valid-system-user' will only check to make sure
 * that the user is a valid system user, no group membership will be checked.
 * 
 */

#include <pwd.h>
#include <grp.h>

#include "apr_strings.h"
#include "apr_lib.h" /* apr_isspace */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"

typedef struct {
    char *ignore_suffix;
    int authoritative;
} authz_sysgroup_config_rec;

static void *create_authz_sysgroup_dir_config(apr_pool_t *p, char *d)
{
    authz_sysgroup_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->ignore_suffix = NULL;
    conf->authoritative = 1;
    return conf;
}

static const command_rec authz_sysgroup_cmds[] =
{
    AP_INIT_TAKE1("AuthzSysGroupIgnoreSuffix", ap_set_string_slot,
                  (void *)APR_OFFSETOF(authz_sysgroup_config_rec, ignore_suffix),
                  OR_AUTHCFG, "If a username ends in this text, ignore that part of "
                  "the username.  Intended for a realm, for example '@EXAMPLE.COM'."),
    AP_INIT_FLAG("AuthzSysGroupAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_sysgroup_config_rec, authoritative),
                 OR_AUTHCFG, "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the 'require group' fails. (default is On)."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_sysgroup_module;

/* Checking ID */

static int check_user_access(request_rec *r)
{
    authz_sysgroup_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_sysgroup_module);
    int m = r->method_number;
    int required_group = 0;
    register int x;
    const char *t, *w;
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int match_all_groups, has_a_match_this_time;
    int err;
    struct passwd *pwentptr;
    struct group *grentptr;
    char **group_members;

    /* Static buffers for thread-safe name/group functions. */
    struct passwd pwent_buf;
    struct group grent_buf;

    /* Buffer for thread-safe get passwd/group functions */
    char *buff;
    /* Start the buffer size at a resonable value.  This should be somewhat large due to
       the fact that there is no apr_prealloc (at least not as of 7/20/09) and we have to
       "throw away" allocated memory when we need more.  Note that the Linux man page for
       getpwent says you can use "sysconf (_SC_GETPW_R_SIZE_MAX)" to get the max possible,
       however this is was proven wrong by testing with a group with a large number of members. */
    size_t buff_size = 16 * 1024; /* 16KB */
    /* Max we will allow buff to grow before quitting.  This is just a safety
       check to make sure that getting too many ERANGEs from getpwnam_r/getgrnam_r
       won't completely bork the system. Probably not necessary but I don't like
       the idea of growing a memory buffer without bounds... */
    const size_t max_buff_size = 20 * 1024 * 1024; /* 20MB */

    /* Part of the username we care about. */
    char *user;

    size_t suffix_length, user_length;


    if (!reqs_arr) {
        return DECLINED;
    }

    /* If there's no user, it's a misconfiguration */
    if (!r->user) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - no user?!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }


    /* Get the part of the username we care about.  We allow stripping off a suffix
       to handle usernames which contain realms, which wouldn't be present in the
       system nss functions. */
    user = NULL;
    if (conf->ignore_suffix) {
        suffix_length = strlen (conf->ignore_suffix);
        user_length = strlen (r->user);

        if (user_length > suffix_length) {
            if (!strcmp (r->user + (user_length - suffix_length), conf->ignore_suffix)) {
                user = apr_pstrndup (r->pool, r->user, user_length - suffix_length);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "suffix '%s' stripped from username "
                              "'%s', using '%s' from now on.", conf->ignore_suffix, r->user, user);
            }
        }
    }

    if (!user) {
        user = r->user;
    }

    /* Allocate the initial size of the passwd/group buffer. */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "allocating %lu bytes from pool.",
                  (long unsigned) buff_size);
    buff = apr_palloc (r->pool, buff_size);
    if (!buff) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - crap - can't allocate "
                      "needed memory!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
 

    /* We need to get the gid of the user's primary group.  We don't actually care about
       any of the strings that are put into pwent_buf (we only want pw_gid), so we will
       use the same buffer later without saving anything in it.
       Since getpwnam_r can end up needing more memory, keep allocating if we get ERANGE. */
    while (1) {
        err = getpwnam_r(user, &pwent_buf, buff, buff_size, &pwentptr);

        /* This loop is only for the reallocation issue, if that's not a problem get out. */
        if (err != ERANGE) {
            break;
        }

        /* Do'h!  Not enough memory, get some more if possible. */
        buff_size = buff_size * 2;

        /* We should never come close to the maximum buffer size unless something is really wrong. */
        if (buff_size > max_buff_size) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - getpwnam_r asking for too "
                          "much memory - WTF?!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* No apr_prealloc means we can't reuse the smaller buffer we asked for earlier. */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "buff not big enough for getpwnam_r, allocating "
                      "%lu bytes from pool.", (long unsigned) buff_size);
        buff = apr_palloc (r->pool, buff_size);
        if (!buff) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - crap - can't allocate "
                          "needed memory!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

     /* If the lookup for the user fails, we can't do anything else constructive. */
     if (err || !pwentptr) {
        if (!conf->authoritative) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "mod_authz_sysgroup - getpwnam_r couldn't "
                          "find user '%s', declining since we are non-authorative.", user);
            return DECLINED;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - getpwnam_r couldn't "
                          "find user '%s', rejecting since we are authorative.", user);
            ap_note_auth_failure(r);
            return HTTP_UNAUTHORIZED;
        }
    }


    reqs = (require_line *)reqs_arr->elts;

    /* Loop through each require line. */
    for (x = 0; x < reqs_arr->nelts; x++) {

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        /* If all we wanted to do was verify that it is a valid system user, quit now. */
        if (!strcasecmp(w, "valid-system-user")) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "user '%s' is a valid system user and "
                          "'require valid-system-user' line detected, granting access.", user);
            return OK;
        }

        /* If it's not a 'Require group' line, we don't care about it. */
        if (strcasecmp(w, "group")) {
            continue;
        }
       
        /* Remember that we've had at least one. */ 
        required_group = 1;

        /* To support the 'AND'ing of groups, a user needs to be in all groups
           specified on this 'Require group' line.  'OR'ing is supported by using
           multiple 'Require group' lines. */
        match_all_groups = 0;
        while (t[0]) {
            w = ap_getword_conf(r->pool, &t);

            /* Get the gid for the group, and a list of members */
            while (1) {
                err = getgrnam_r(w, &grent_buf, buff, buff_size, &grentptr);

                /* This loop is only for the reallocation issue, if that's not a problem get out. */
                if (err != ERANGE) {
                    break;
                }

                /* Do'h!  Not enough memory, get some more if possible. */
                buff_size = buff_size * 2;

                /* We should never come close to the maximum buffer size unless something is really wrong. */
                if (buff_size > max_buff_size) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - getgrnam_r asking for "
                                  "too much memory - WTF?!");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                /* No apr_prealloc means we can't reuse the smaller buffer we asked for earlier */
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "buff not big enough for getgrnam_r, "
                              "allocating %lu bytes from pool.", (long unsigned) buff_size);
                buff = apr_palloc (r->pool, buff_size);
                if (!buff) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - crap - can't allocate "
                                  "more memory!");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            /* If we can't resolve the name for a group, log the error but keep going.  This can
               happen if someone specified an invalid group in the apache config file. */
            if (err || !grentptr) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - getgrnam_r couldn't find "
                              "group '%s'", w);
                match_all_groups = 0;
                break;
            }

            /* If this is the user's primary group, we're good on this one. */
            if (pwentptr->pw_gid == grentptr->gr_gid) {
                match_all_groups = 1;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "user '%s' is in required group '%s' "
                              "(user's primary group).", user, grentptr->gr_name);
                continue;
            }

            /* See if this user is listed amoung the members of the group */
            group_members = grentptr->gr_mem;

            has_a_match_this_time = 0;
            while (*group_members) {
                if (strcmp (*group_members, user) == 0) {
                    has_a_match_this_time = 1;
                    match_all_groups = 1;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "user '%s' is in required group '%s'.",
                                  user, grentptr->gr_name);
                    break;
                }

                group_members++;
            }

            if (!has_a_match_this_time) {
                match_all_groups = 0;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "user '%s' is NOT in required group '%s'.",
                              user, grentptr->gr_name);
                break;
            }
        }

        /* If the user is in all groups on the line, return success. */
        if (match_all_groups) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "user '%s' is in all groups on a "
                          "'require group' line, granting access.", user);
            return OK;
        }
    }

    /* No applicable "require group" for this method seen. */
    if (!required_group) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no applicable 'require group' line, declining.");
        return DECLINED;
    }
 
    if (!conf->authoritative) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "failed authorization for user '%s', but since "
                      "we are not authorative, we decline.", user);
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authz_sysgroup - authorization of user '%s' to access "
                  "'%s' failed, user is not part of the required group(s).", user, r->uri);

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[]={ "mod_authz_owner.c", NULL };

    ap_hook_auth_checker(check_user_access, aszPre, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authz_sysgroup_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_sysgroup_dir_config,/* dir config creater */
    NULL,                             /* dir merger -- default is to override */
    NULL,                             /* server config */
    NULL,                             /* merge server config */
    authz_sysgroup_cmds,             /* command apr_table_t */
    register_hooks                    /* register hooks */
};
