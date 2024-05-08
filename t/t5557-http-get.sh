#!/bin/sh

test_description='test downloading a file by URL'

TEST_PASSES_SANITIZE_LEAK=true

. ./test-lib.sh

. "$TEST_DIRECTORY"/lib-httpd.sh
start_httpd

test_expect_success 'get by URL: 404' '
	test_when_finished "rm -f file.temp" &&
	url="$HTTPD_URL/none.txt" &&
	cat >input <<-EOF &&
	capabilities
	get $url file1
	EOF

	test_must_fail git remote-http $url <input 2>err &&
	test_path_is_missing file1 &&
	grep "failed to download file at URL" err
'

test_expect_success 'get by URL: 200' '
	echo data >"$HTTPD_DOCUMENT_ROOT_PATH/exists.txt" &&

	url="$HTTPD_URL/exists.txt" &&
	cat >input <<-EOF &&
	capabilities
	get $url file2

	EOF

	git remote-http $url <input &&
	test_cmp "$HTTPD_DOCUMENT_ROOT_PATH/exists.txt" file2
'

test_expect_success 'get by URL with progress' '
	echo hello >"$HTTPD_DOCUMENT_ROOT_PATH/hello.txt" &&

	url="$HTTPD_URL/hello.txt" &&
	cat >input <<-EOF &&
	capabilities
	option progress true
	get $url file3

	EOF

	git remote-http $url <input 2>err &&
	test_grep "^Downloading via HTTP: 100%" err
'

test_done
