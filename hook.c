#include "cache.h"
#include "hook.h"
#include "run-command.h"
#include "config.h"
#include "strmap.h"

static int identical_to_template_hook(const char *name, const char *path)
{
	const char *env = getenv("GIT_CLONE_TEMPLATE_DIR");
	const char *template_dir = get_template_dir(env && *env ? env : NULL);
	struct strbuf template_path = STRBUF_INIT;
	int found_template_hook, ret;

	strbuf_addf(&template_path, "%s/hooks/%s", template_dir, name);
	found_template_hook = access(template_path.buf, X_OK) >= 0;
#ifdef STRIP_EXTENSION
	if (!found_template_hook) {
		strbuf_addstr(&template_path, STRIP_EXTENSION);
		found_template_hook = access(template_path.buf, X_OK) >= 0;
	}
#endif
	if (!found_template_hook) {
		strbuf_release(&template_path);
		return 0;
	}

	ret = do_files_match(template_path.buf, path);

	strbuf_release(&template_path);
	return ret;
}

static struct strset safe_hook_sha256s = STRSET_INIT;
static int safe_hook_sha256s_initialized;

static int get_sha256_of_file_contents(const char *path, char *sha256)
{
	struct strbuf sb = STRBUF_INIT;
	int fd;
	ssize_t res;

	git_hash_ctx ctx;
	const struct git_hash_algo *algo = &hash_algos[GIT_HASH_SHA256];
	unsigned char hash[GIT_MAX_RAWSZ];

	if ((fd = open(path, O_RDONLY)) < 0)
		return -1;
	res = strbuf_read(&sb, fd, 400);
	close(fd);
	if (res < 0)
		return -1;

	algo->init_fn(&ctx);
	algo->update_fn(&ctx, sb.buf, sb.len);
	strbuf_release(&sb);
	algo->final_fn(hash, &ctx);

	hash_to_hex_algop_r(sha256, hash, algo);

	return 0;
}

static int safe_hook_cb(const char *key, const char *value, void *d)
{
	struct strset *set = d;

	if (value && !strcmp(key, "safe.hook.sha256"))
		strset_add(set, value);

	return 0;
}

static int is_hook_safe_during_clone(const char *name, const char *path, char *sha256)
{
	if (get_sha256_of_file_contents(path, sha256) < 0)
		return 0;

	if (!safe_hook_sha256s_initialized) {
		safe_hook_sha256s_initialized = 1;
		git_protected_config(safe_hook_cb, &safe_hook_sha256s);
	}

	return strset_contains(&safe_hook_sha256s, sha256);
}

const char *find_hook(const char *name)
{
	static struct strbuf path = STRBUF_INIT;

	int found_hook;
	char sha256[GIT_SHA256_HEXSZ + 1] = { '\0' };

	strbuf_reset(&path);
	strbuf_git_path(&path, "hooks/%s", name);
	found_hook = access(path.buf, X_OK) >= 0;
#ifdef STRIP_EXTENSION
	if (!found_hook) {
		int err = errno;

		strbuf_addstr(&path, STRIP_EXTENSION);
		found_hook = access(path.buf, X_OK) >= 0;
		if (!found_hook)
			errno = err;
	}
#endif

	if (!found_hook) {
		if (errno == EACCES && advice_enabled(ADVICE_IGNORED_HOOK)) {
			static struct string_list advise_given = STRING_LIST_INIT_DUP;

			if (!string_list_lookup(&advise_given, name)) {
				string_list_insert(&advise_given, name);
				advise(_("The '%s' hook was ignored because "
					 "it's not set as executable.\n"
					 "You can disable this warning with "
					 "`git config advice.ignoredHook false`."),
				       path.buf);
			}
		}
		return NULL;
	}
	if (!git_hooks_path && git_env_bool("GIT_CLONE_PROTECTION_ACTIVE", 0) &&
	    !identical_to_template_hook(name, path.buf) &&
	    !is_hook_safe_during_clone(name, path.buf, sha256))
		die(_("active `%s` hook found during `git clone`:\n\t%s\n"
		      "For security reasons, this is disallowed by default.\n"
		      "If this is intentional and the hook is safe to run, "
		      "please run the following command and try again:\n\n"
		      "  git config --global --add safe.hook.sha256 %s"),
		    name, path.buf, sha256);
	return path.buf;
}

int hook_exists(const char *name)
{
	return !!find_hook(name);
}

static int pick_next_hook(struct child_process *cp,
			  struct strbuf *out,
			  void *pp_cb,
			  void **pp_task_cb)
{
	struct hook_cb_data *hook_cb = pp_cb;
	const char *hook_path = hook_cb->hook_path;

	if (!hook_path)
		return 0;

	cp->no_stdin = 1;
	strvec_pushv(&cp->env, hook_cb->options->env.v);
	cp->stdout_to_stderr = 1;
	cp->trace2_hook_name = hook_cb->hook_name;
	cp->dir = hook_cb->options->dir;

	strvec_push(&cp->args, hook_path);
	strvec_pushv(&cp->args, hook_cb->options->args.v);

	/*
	 * This pick_next_hook() will be called again, we're only
	 * running one hook, so indicate that no more work will be
	 * done.
	 */
	hook_cb->hook_path = NULL;

	return 1;
}

static int notify_start_failure(struct strbuf *out,
				void *pp_cb,
				void *pp_task_cp)
{
	struct hook_cb_data *hook_cb = pp_cb;

	hook_cb->rc |= 1;

	return 1;
}

static int notify_hook_finished(int result,
				struct strbuf *out,
				void *pp_cb,
				void *pp_task_cb)
{
	struct hook_cb_data *hook_cb = pp_cb;
	struct run_hooks_opt *opt = hook_cb->options;

	hook_cb->rc |= result;

	if (opt->invoked_hook)
		*opt->invoked_hook = 1;

	return 0;
}

static void run_hooks_opt_clear(struct run_hooks_opt *options)
{
	strvec_clear(&options->env);
	strvec_clear(&options->args);
}

int run_hooks_opt(const char *hook_name, struct run_hooks_opt *options)
{
	struct strbuf abs_path = STRBUF_INIT;
	struct hook_cb_data cb_data = {
		.rc = 0,
		.hook_name = hook_name,
		.options = options,
	};
	const char *const hook_path = find_hook(hook_name);
	int ret = 0;
	const struct run_process_parallel_opts opts = {
		.tr2_category = "hook",
		.tr2_label = hook_name,

		.processes = 1,
		.ungroup = 1,

		.get_next_task = pick_next_hook,
		.start_failure = notify_start_failure,
		.task_finished = notify_hook_finished,

		.data = &cb_data,
	};

	if (!options)
		BUG("a struct run_hooks_opt must be provided to run_hooks");

	if (options->invoked_hook)
		*options->invoked_hook = 0;

	if (!hook_path && !options->error_if_missing)
		goto cleanup;

	if (!hook_path) {
		ret = error("cannot find a hook named %s", hook_name);
		goto cleanup;
	}

	cb_data.hook_path = hook_path;
	if (options->dir) {
		strbuf_add_absolute_path(&abs_path, hook_path);
		cb_data.hook_path = abs_path.buf;
	}

	run_processes_parallel(&opts);
	ret = cb_data.rc;
cleanup:
	strbuf_release(&abs_path);
	run_hooks_opt_clear(options);
	return ret;
}

int run_hooks(const char *hook_name)
{
	struct run_hooks_opt opt = RUN_HOOKS_OPT_INIT;

	return run_hooks_opt(hook_name, &opt);
}

int run_hooks_l(const char *hook_name, ...)
{
	struct run_hooks_opt opt = RUN_HOOKS_OPT_INIT;
	va_list ap;
	const char *arg;

	va_start(ap, hook_name);
	while ((arg = va_arg(ap, const char *)))
		strvec_push(&opt.args, arg);
	va_end(ap);

	return run_hooks_opt(hook_name, &opt);
}
