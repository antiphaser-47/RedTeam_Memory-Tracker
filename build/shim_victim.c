#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char *p, *q, *r;

    /* (1) 16-byte block, one byte written past the end -> redzone hit. */
    p = malloc(16);
    memset(p, 'A', 16);
    p[16] = 'X';
    free(p);

    /* (2) same pointer released twice -> double free. */
    q = calloc(4, 4);
    memset(q, 'B', 16);
    free(q);
    free(q);

    /* (3) perfectly well-behaved allocation -> must stay silent. */
    r = realloc(NULL, 32);
    memset(r, 'C', 32);
    r = realloc(r, 8);
    free(r);

    printf("victim done\n");
    return 0;
}
