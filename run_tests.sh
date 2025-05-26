#!/usr/bin/env sh

export VALGRIND_OPTS="--leak-check=full --show-leak-kinds=all --track-fds=yes --error-exitcode=42"

abort() {
    echo "$@" >&2
    exit 1
}

TEST_ID=0

meh() {
    : $((TEST_ID += 1))
    dir="test_output/${TEST_ID}"
    mkdir -p -- "${dir}"
    timeout -s INT -k 5s 2s valgrind --xml=yes --xml-file="${dir}/valgrind.xml" --log-file="${dir}/valgrind.log" -- ./ft_ping "$@" >"${dir}/stdout.log" 2>"${dir}/stderr.log"
}

want_status() {
    echo "$@"
    want_status="$1"
    shift

    meh "$@"

    have_status=$?
    if [ "${have_status}" != "${want_status}" ]; then
        abort "test ${TEST_ID} '$*': expected status ${want_status}, got ${have_status}"
    fi
}

want_timeout() {
    want_status 124 "$@"
}

want_status 1 # no arguments
want_status 0 --help
want_status 0 127.0.0.1 -c 200 --help
want_timeout 127.0.0.1
want_timeout -i 0.2 127.0.0.1
want_status 0 -i 0.1 -w 1 127.0.0.1
want_timeout 127.0.0.1 -c 200
