/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2014, 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "db-ctl-base.h"

#include "command-line.h"
#include "compiler.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "ovsdb-data.h"
#include "ovsdb-idl.h"
#include "openvswitch/poll-loop.h"
#include "process.h"
#include "stream.h"
#include "stream-ssl.h"
#include "svec.h"
#include "lib/ovsconf-idl.h"
#include "table.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(confctl);

struct conf_ctl_context;

/* --db: The database server to contact. */
static const char *db;

/* --oneline: Write each command's output as a single line? */
static bool oneline;

/* --dry-run: Do not commit any changes. */
static bool dry_run;

/* --timeout: Time to wait for a connection to 'db'. */
static unsigned int timeout;

/* Format for table output. */
static struct table_style table_style = TABLE_STYLE_DEFAULT;

/* The IDL we're using and the current transaction, if any.
 * This is for use by conf_ctl_exit() only, to allow it to clean up.
 * Other code should use its context arguments. */
static struct ovsdb_idl *the_idl;
static struct ovsdb_idl_txn *the_idl_txn;

OVS_NO_RETURN static void conf_ctl_exit(int status);
static void conf_ctl_cmd_init(void);
OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[], struct shash *local_options);
static void run_prerequisites(struct ctl_command[], size_t n_commands,
                              struct ovsdb_idl *);
static bool do_conf_ctl(const char *args, struct ctl_command *, size_t n,
                        struct ovsdb_idl *);

int
main(int argc, char *argv[])
{
    struct ovsdb_idl *idl;
    struct ctl_command *commands;
    struct shash local_options;
    unsigned int seqno;
    size_t n_commands;

    set_program_name(argv[0]);
    fatal_ignore_sigpipe();
    vlog_set_levels(NULL, VLF_CONSOLE, VLL_WARN);
    vlog_set_levels_from_string_assert("reconnect:warn");

    conf_ctl_cmd_init();

    /* Parse command line. */
    char *args = process_escape_args(argv);
    shash_init(&local_options);
    parse_options(argc, argv, &local_options);
    char *error = ctl_parse_commands(argc - optind, argv + optind,
                                     &local_options, &commands, &n_commands);
    if (error) {
        ctl_fatal("%s", error);
    }
    VLOG(ctl_might_write_to_db(commands, n_commands) ? VLL_INFO : VLL_DBG,
         "Called as %s", args);

    ctl_timeout_setup(timeout);

    /* Initialize IDL. */
    idl = the_idl = ovsdb_idl_create(db, &ovsconf_idl_class, false, false);
    run_prerequisites(commands, n_commands, idl);

    /* Execute the commands.
     *
     * 'seqno' is the database sequence number for which we last tried to
     * execute our transaction.  There's no point in trying to commit more than
     * once for any given sequence number, because if the transaction fails
     * it's because the database changed and we need to obtain an up-to-date
     * view of the database before we try the transaction again. */
    seqno = ovsdb_idl_get_seqno(idl);
    for (;;) {
        ovsdb_idl_run(idl);
        if (!ovsdb_idl_is_alive(idl)) {
            int retval = ovsdb_idl_get_last_error(idl);
            ctl_fatal("%s: database connection failed (%s)",
                        db, ovs_retval_to_string(retval));
        }

        if (seqno != ovsdb_idl_get_seqno(idl)) {
            seqno = ovsdb_idl_get_seqno(idl);
            if (do_conf_ctl(args, commands, n_commands, idl)) {
                free(args);
                exit(EXIT_SUCCESS);
            }
        }

        if (seqno == ovsdb_idl_get_seqno(idl)) {
            ovsdb_idl_wait(idl);
            poll_block();
        }
    }
}

static void
parse_options(int argc, char *argv[], struct shash *local_options)
{
    enum {
        OPT_DB = UCHAR_MAX + 1,
        OPT_ONELINE,
        OPT_NO_SYSLOG,
        OPT_DRY_RUN,
        OPT_PEER_CA_CERT,
        OPT_LOCAL,
        VLOG_OPTION_ENUMS,
        TABLE_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option global_long_options[] = {
        {"db", required_argument, NULL, OPT_DB},
        {"no-syslog", no_argument, NULL, OPT_NO_SYSLOG},
        {"dry-run", no_argument, NULL, OPT_DRY_RUN},
        {"oneline", no_argument, NULL, OPT_ONELINE},
        {"timeout", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        TABLE_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {NULL, 0, NULL, 0},
    };
    const int n_global_long_options = ARRAY_SIZE(global_long_options) - 1;
    char *tmp, *short_options;

    struct option *options;
    size_t allocated_options;
    size_t n_options;
    size_t i;

    tmp = ovs_cmdl_long_options_to_short_options(global_long_options);
    short_options = xasprintf("+%s", tmp);
    free(tmp);

    /* We want to parse both global and command-specific options here, but
     * getopt_long() isn't too convenient for the job.  We copy our global
     * options into a dynamic array, then append all of the command-specific
     * options. */
    options = xmemdup(global_long_options, sizeof global_long_options);
    allocated_options = ARRAY_SIZE(global_long_options);
    n_options = n_global_long_options;
    ctl_add_cmd_options(&options, &n_options, &allocated_options, OPT_LOCAL);

    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, options, &idx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DB:
            db = optarg;
            break;

        case OPT_ONELINE:
            oneline = true;
            break;

        case OPT_NO_SYSLOG:
            vlog_set_levels(&this_module, VLF_SYSLOG, VLL_WARN);
            break;

        case OPT_DRY_RUN:
            dry_run = true;
            break;

        case OPT_LOCAL:
            if (shash_find(local_options, options[idx].name)) {
                ctl_fatal("'%s' option specified multiple times",
                          options[idx].name);
            }
            shash_add_nocopy(local_options,
                             xasprintf("--%s", options[idx].name),
                             nullable_xstrdup(optarg));
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            printf("DB Schema %s\n", ovsconf_get_db_version());
            exit(EXIT_SUCCESS);

        case 't':
            if (!str_to_uint(optarg, 10, &timeout) || !timeout) {
                ctl_fatal("value %s on -t or --timeout is invalid", optarg);
            }
            break;

        VLOG_OPTION_HANDLERS
        TABLE_OPTION_HANDLERS(&table_style)

        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            ovs_abort(0, "Internal error when parsing option %d.", c);
        }
    }
    free(short_options);

    if (!db) {
        db = ctl_default_db();
    }

    for (i = n_global_long_options; options[i].name; i++) {
        free(CONST_CAST(char *, options[i].name));
    }
    free(options);
}

/* Frees the current transaction and the underlying IDL and then calls
 * exit(status).
 *
 * Freeing the transaction and the IDL is not strictly necessary, but it makes
 * for a clean memory leak report from valgrind in the normal case.  That makes
 * it easier to notice real memory leaks. */
static void
conf_ctl_exit(int status)
{
    if (the_idl_txn) {
        ovsdb_idl_txn_abort(the_idl_txn);
        ovsdb_idl_txn_destroy(the_idl_txn);
    }
    ovsdb_idl_destroy(the_idl);
    exit(status);
}

static void
usage(void)
{
    printf("\
%s: OVS local configuration utility\n\
usage: %s [OPTIONS] COMMAND [ARG...]\n\
\n\
Local_Config commands:\n\
  show                        print overview of database contents\n\
\n\
Connection commands:\n\
  get-connection             print the connections\n\
  del-connection             delete the connections\n\
  [--inactivity-probe=MSECS]\n\
  set-connection TARGET...   set the list of connections to TARGET...\n\
\n\
%s\
%s\
\n\
Options:\n\
  --db=DATABASE               connect to DATABASE\n\
                              (default: %s)\n\
  -t, --timeout=SECS          wait at most SECS seconds\n\
  --dry-run                   do not commit changes to database\n\
  --oneline                   print exactly one line of output per command\n",
           program_name, program_name, ctl_get_db_cmd_usage(),
           ctl_list_db_tables_usage(), ctl_default_db());
    table_usage();
    vlog_usage();
    printf("\
  --no-syslog                 equivalent to --verbose=conf_ctl:syslog:warn\n");
    stream_usage("database", true, true, false);
    printf("\n\
Other options:\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static struct cmd_show_table cmd_show_tables[] = {
    {&ovsconf_table_config,
     NULL,
     {&ovsconf_config_col_connections, NULL},
     {NULL, NULL, NULL}
    },

    {&ovsconf_table_connection,
     &ovsconf_connection_col_target,
     {&ovsconf_connection_col_is_connected,
      NULL,
      NULL},
     {NULL, NULL, NULL}
    },
    {NULL, NULL, {NULL, NULL, NULL}, {NULL, NULL, NULL}}
};

struct conf_ctl_context {
    struct ctl_context base;

    /* Modifiable state. */
    const struct ovsconf_config *conf_config;
};

/* Parameter commands. */
static const struct ctl_table_class tables[OVSCONF_N_TABLES] = {
    [OVSCONF_TABLE_CONNECTION].row_ids[0]
    = {&ovsconf_connection_col_target, NULL, NULL},
};


static void
conf_ctl_context_init_command(struct conf_ctl_context *confctl_ctx,
                              struct ctl_command *command)
{
    ctl_context_init_command(&confctl_ctx->base, command);

}

static void
conf_ctl_context_init(struct conf_ctl_context *confctl_ctx,
                      struct ctl_command *command,
                      struct ovsdb_idl *idl, struct ovsdb_idl_txn *txn,
                      const struct ovsconf_config *conf_config,
                      struct ovsdb_symbol_table *symtab)
{
    ctl_context_init(&confctl_ctx->base, command, idl, txn, symtab, NULL);
    confctl_ctx->conf_config = conf_config;
}

static void
conf_ctl_context_done_command(struct conf_ctl_context *confctl_ctx,
                              struct ctl_command *command)
{
    ctl_context_done_command(&confctl_ctx->base, command);
}

static void
conf_ctl_context_done(struct conf_ctl_context *confctl_ctx,
                      struct ctl_command *command)
{
    ctl_context_done(&confctl_ctx->base, command);
}

static void
run_prerequisites(struct ctl_command *commands, size_t n_commands,
                  struct ovsdb_idl *idl)
{
    struct ctl_command *c;

    ovsdb_idl_add_table(idl, &ovsconf_table_config);
    for (c = commands; c < &commands[n_commands]; c++) {
        if (c->syntax->prerequisites) {
            struct conf_ctl_context confctl_ctx;

            ds_init(&c->output);
            c->table = NULL;

            conf_ctl_context_init(&confctl_ctx, c, idl, NULL, NULL, NULL);
            (c->syntax->prerequisites)(&confctl_ctx.base);
            if (confctl_ctx.base.error) {
                ctl_fatal("%s", confctl_ctx.base.error);
            }
            conf_ctl_context_done(&confctl_ctx, c);

            ovs_assert(!c->output.string);
            ovs_assert(!c->table);
        }
    }
}

static void
verify_connections(struct ctl_context *ctx)
{
    const struct ovsconf_config *ovsconf_config =
        ovsconf_config_first(ctx->idl);
    const struct ovsconf_connection *conn;

    ovsconf_config_verify_connections(ovsconf_config);

    OVSCONF_CONNECTION_FOR_EACH (conn, ctx->idl) {
        ovsconf_connection_verify_target(conn);
    }
}

static void
pre_connection(struct ctl_context *ctx)
{
    ovsdb_idl_add_column(ctx->idl, &ovsconf_config_col_connections);
    ovsdb_idl_add_column(ctx->idl, &ovsconf_connection_col_target);
    ovsdb_idl_add_column(ctx->idl, &ovsconf_connection_col_inactivity_probe);
}

static void
cmd_get_connection(struct ctl_context *ctx)
{
    const struct ovsconf_connection *conn;
    struct svec targets;
    size_t i;

    verify_connections(ctx);

    /* Print the targets in sorted order for reproducibility. */
    svec_init(&targets);

    OVSCONF_CONNECTION_FOR_EACH (conn, ctx->idl) {
        svec_add(&targets, conn->target);
    }

    svec_sort_unique(&targets);
    for (i = 0; i < targets.n; i++) {
        ds_put_format(&ctx->output, "%s\n", targets.names[i]);
    }
    svec_destroy(&targets);
}

static void
delete_connections(struct ctl_context *ctx)
{
    const struct ovsconf_config *ovsconf_config =
        ovsconf_config_first(ctx->idl);
    const struct ovsconf_connection *conn;

    /* Delete Manager rows pointed to by 'connection_options' column. */
    OVSCONF_CONNECTION_FOR_EACH_SAFE (conn, ctx->idl) {
        ovsconf_connection_delete(conn);
    }

    /* Delete 'Manager' row refs in 'manager_options' column. */
    ovsconf_config_set_connections(ovsconf_config, NULL, 0);
}

static void
cmd_del_connection(struct ctl_context *ctx)
{
    verify_connections(ctx);
    delete_connections(ctx);
}

static void
insert_connections(struct ctl_context *ctx, char *targets[], size_t n)
{
    const struct ovsconf_config *ovsconf_config =
        ovsconf_config_first(ctx->idl);
    struct ovsconf_connection **connections;
    size_t i, conns = 0;
    const char *inactivity_probe = shash_find_data(&ctx->options,
                                                   "--inactivity-probe");

    /* Insert each connection in a new row in Connection table. */
    connections = xmalloc(n * sizeof *connections);
    for (i = 0; i < n; i++) {
        if (stream_verify_name(targets[i]) &&
                   pstream_verify_name(targets[i])) {
            VLOG_WARN("target type \"%s\" is possibly erroneous", targets[i]);
        }

        connections[conns] = ovsconf_connection_insert(ctx->txn);
        ovsconf_connection_set_target(connections[conns], targets[i]);
        if (inactivity_probe) {
            int64_t msecs = atoll(inactivity_probe);
            ovsconf_connection_set_inactivity_probe(connections[conns],
                                                  &msecs, 1);
        }
        conns++;
    }

    /* Store uuids of new connection rows in 'connection' column. */
    ovsconf_config_set_connections(ovsconf_config, connections, conns);
    free(connections);
}

static void
cmd_set_connection(struct ctl_context *ctx)
{
    const size_t n = ctx->argc - 1;

    verify_connections(ctx);
    delete_connections(ctx);
    insert_connections(ctx, &ctx->argv[1], n);
}


static bool
do_conf_ctl(const char *args, struct ctl_command *commands,
            size_t n_commands, struct ovsdb_idl *idl)
{
    struct ovsdb_idl_txn *txn;
    const struct ovsconf_config *conf_config;
    enum ovsdb_idl_txn_status status;
    struct ovsdb_symbol_table *symtab;
    struct conf_ctl_context confctl_ctx;
    struct ctl_command *c;
    struct shash_node *node;
    char *error = NULL;

    txn = the_idl_txn = ovsdb_idl_txn_create(idl);
    if (dry_run) {
        ovsdb_idl_txn_set_dry_run(txn);
    }

    ovsdb_idl_txn_add_comment(txn, "ovs-confctl: %s", args);

    conf_config = ovsconf_config_first(idl);
    if (!conf_config) {
        conf_config = ovsconf_config_insert(txn);
    }

    symtab = ovsdb_symbol_table_create();
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_init(&c->output);
        c->table = NULL;
    }
    conf_ctl_context_init(&confctl_ctx, NULL, idl, txn, conf_config, symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        conf_ctl_context_init_command(&confctl_ctx, c);
        if (c->syntax->run) {
            (c->syntax->run)(&confctl_ctx.base);
        }
        if (confctl_ctx.base.error) {
            ctl_fatal("%s", confctl_ctx.base.error);
        }
        conf_ctl_context_done_command(&confctl_ctx, c);

        if (confctl_ctx.base.try_again) {
            conf_ctl_context_done(&confctl_ctx, NULL);
            goto try_again;
        }
    }
    conf_ctl_context_done(&confctl_ctx, NULL);

    SHASH_FOR_EACH (node, &symtab->sh) {
        struct ovsdb_symbol *symbol = node->data;
        if (!symbol->created) {
            ctl_fatal("row id \"%s\" is referenced but never created "
                      "(e.g. with \"-- --id=%s create ...\")",
                      node->name, node->name);
        }
        if (!symbol->strong_ref) {
            if (!symbol->weak_ref) {
                VLOG_WARN("row id \"%s\" was created but no reference to it "
                          "was inserted, so it will not actually appear in "
                          "the database", node->name);
            } else {
                VLOG_WARN("row id \"%s\" was created but only a weak "
                          "reference to it was inserted, so it will not "
                          "actually appear in the database", node->name);
            }
        }
    }

    status = ovsdb_idl_txn_commit_block(txn);
    if (status == TXN_UNCHANGED || status == TXN_SUCCESS) {
        for (c = commands; c < &commands[n_commands]; c++) {
            if (c->syntax->postprocess) {
                conf_ctl_context_init(&confctl_ctx, c, idl, txn, conf_config,
                                      symtab);
                (c->syntax->postprocess)(&confctl_ctx.base);
                if (confctl_ctx.base.error) {
                    ctl_fatal("%s", confctl_ctx.base.error);
                }
                conf_ctl_context_done(&confctl_ctx, c);
            }
        }
    }
    error = xstrdup(ovsdb_idl_txn_get_error(txn));
    ovsdb_idl_txn_destroy(txn);
    txn = the_idl_txn = NULL;

    switch (status) {
    case TXN_UNCOMMITTED:
    case TXN_INCOMPLETE:
        OVS_NOT_REACHED();

    case TXN_ABORTED:
        /* Should not happen--we never call ovsdb_idl_txn_abort(). */
        ctl_fatal("transaction aborted");

    case TXN_UNCHANGED:
    case TXN_SUCCESS:
        break;

    case TXN_TRY_AGAIN:
        goto try_again;

    case TXN_ERROR:
        ctl_fatal("transaction error: %s", error);

    case TXN_NOT_LOCKED:
        /* Should not happen--we never call ovsdb_idl_set_lock(). */
        ctl_fatal("database not locked");

    default:
        OVS_NOT_REACHED();
    }
    free(error);

    ovsdb_symbol_table_destroy(symtab);

    for (c = commands; c < &commands[n_commands]; c++) {
        struct ds *ds = &c->output;

        if (c->table) {
            table_print(c->table, &table_style);
        } else if (oneline) {
            size_t j;

            ds_chomp(ds, '\n');
            for (j = 0; j < ds->length; j++) {
                int ch = ds->string[j];
                switch (ch) {
                case '\n':
                    fputs("\\n", stdout);
                    break;

                case '\\':
                    fputs("\\\\", stdout);
                    break;

                default:
                    putchar(ch);
                }
            }
            putchar('\n');
        } else {
            fputs(ds_cstr(ds), stdout);
        }
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);

        shash_destroy_free_data(&c->options);
    }
    free(commands);

    ovsdb_idl_destroy(idl);

    return true;

try_again:
    /* Our transaction needs to be rerun, or a prerequisite was not met.  Free
     * resources and return so that the caller can try again. */
    if (txn) {
        ovsdb_idl_txn_abort(txn);
        ovsdb_idl_txn_destroy(txn);
    }
    ovsdb_symbol_table_destroy(symtab);
    for (c = commands; c < &commands[n_commands]; c++) {
        ds_destroy(&c->output);
        table_destroy(c->table);
        free(c->table);
    }
    free(error);
    return false;
}

static const struct ctl_command_syntax conf_commands[] = {
    /* Connection commands. */
    {"get-connection", 0, 0, "", pre_connection, cmd_get_connection, NULL, "",
     RO},
    {"del-connection", 0, 0, "", pre_connection, cmd_del_connection, NULL, "",
     RW},
    {"set-connection", 1, INT_MAX, "TARGET...", pre_connection,
     cmd_set_connection, NULL, "--inactivity-probe=", RW},
    {NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, RO},
};

/* Registers vsctl and common db commands. */
static void
conf_ctl_cmd_init(void)
{
    ctl_init(&ovsconf_idl_class, ovsconf_table_classes, tables,
             cmd_show_tables, conf_ctl_exit);
    ctl_register_commands(conf_commands);
}
