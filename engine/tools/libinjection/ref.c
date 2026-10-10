/*
 * Reference driver for `make libinjection-diff`: one input per line on
 * stdin (a trailing '\n' removed), prints "<sqli fingerprint or ->
 * <xss 0/1>" per line, like engine/examples/injection-cli.rs.
 * Built against the original libinjection C sources, never shipped.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libinjection.h"

int main(void)
{
    char   *line = NULL;
    size_t  cap = 0;
    ssize_t n;
    char    fp[8];

    while ((n = getline(&line, &cap, stdin)) != -1) {
        if (n > 0 && line[n - 1] == '\n') {
            line[--n] = '\0';
        }
        if (libinjection_sqli(line, (size_t) n, fp)) {
            printf("%s ", fp);
        } else {
            printf("- ");
        }
        printf("%d\n", libinjection_xss(line, (size_t) n));
    }
    free(line);
    return 0;
}
