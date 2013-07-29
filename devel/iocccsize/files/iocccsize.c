/*
 * iocccsize - IOCCC Source Secondary Size
 *
 *      Public Domain 1992, 2013 by Anthony Howe.  All rights released.
 *      With IOCCC mods in 2013 by chongo (Landon Curt Noll) /\oo/\
 *
 *      This IOCCC size tool source file is version 2013-07-26-v15.
 *
 * SYNOPSIS
 *
 *      ioccc [-ikrs] < input
 *
 *      -i      print official IOCCC size to standard out
 *                  NOTE: -i implies -r -s
 *      -k      keep comments
 *      -r      count C reserved words as 1 byte
 *      -s      silence; do not output source code, only final count
 *
 * DESCRIPION
 *
 *      Taking input from standard input, apply the IOCCC Source Size Rule
 *      for 2001.  The program's offical length is written to standard error.
 *      Also filter out C comment blocks (-k to keep) sending the modified
 *      source to standard output.
 *
 *      The 2001 Source Size Rule was:
 *
 *      Your entry must be <= 4096 bytes in length.  The number of octets
 *      excluding whitespace (tab, space, newline, formfeed, return), and
 *      excluding any ';', '{' or '}' followed by whitespace or end of file,
 *      must be <= 2048.
 *
 *  NOTE: The above descipion is NOT the official IOCCC size tool algorithm!
 */

/*
 * The official IOCCC rule 2 secondary limit on C code size
 *
 * The IOCCC size tool should be compiled as:
 *
 *      cc --pedantic -Wall -std=c99 iocccsize.c -o iocccsize
 *
 * This tool computes a 2nd size C code.  To check your program source
 * against the 2nd limit of rule 2, use the -i command line option.
 *
 * For example:
 *
 *      ./iocccsize -i < prog.c
 *
 * The IOCCC size tool, when using the -i option, may be summarized as:
 *
 *      The size tool counts C language keywords (primary, secondary, and
 *      selected preprocessor keywords) as 1.  The size tool counts all
 *      other octets as 1 excluding ASCII whitespace, and excluding any
 *      ';', '{' or '}' followed by ASCII whitespace, and excluding any
 *      ';', '{' or '}' octet immediately before the end of file.
 *
 * ASCII whitespace includes ASCII tab, ASCII space, ASCII newline,
 * ASCII formfeed, and ASCII carriage return.
 *
 * In cases where the above summary and the algorithm implemented by
 * the IOCCC size tool source code conflict, the algorithm implemented
 * by the IOCCC size tool source code is preferred by the judges.
 *
 * See the current IOCCC rules and guidelines for more information.
 * In particular, see the current IOCCC size rule for information about
 * the maximum value that this tool should print for an entry to be valid.
 */

/*
 * HINT: The algorithm implemented by this code may or not be obfuscated.
 *	 The algorithm may not or may appear to be obfucated.
 *
 * In particular:
 *
 *	We did not invent the algorithm.
 *	The algorithm consistently finds Obfuscation.
 *	The algorithm killed Obfuscation.
 *	The algorithm is banned in C.
 *	The algorithm is from Bell Labs in Jersey.
 *	The algorithm constantly finds Obfuscation.
 *	This is not the algorithm.
 *	This is close.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>

#define FLAG_SILENCE            1
#define FLAG_KEEP               2
#define FLAG_RESERVED           4
#define FLAG_IOCCC_SIZE         8

char usage[] =
"usage:  ioccc [-ikrs] < prog.c\n"
"\n"
"-i\t\tprint just the official secondary IOCCC size to stdout\n"
"\t\t    NOTE: -i implies -k -r -s\n"
"-k\t\tkeep comments\n"
"-r\t\tcount C reserved words as 1 byte\n"
"-s\t\tsilence; do not output source code, only final count\n";

#define STRLEN(s)               (sizeof (s)-1)

typedef struct {
	size_t length;
	const char *word;
} Word;

/*
 * C reserved words, plus a few #preprocessor tokens, that count as 1
 *
 * NOTE: For a good list of reserved words in C, see:
 *
 *	http://www.bezem.de/pdf/ReservedWordsInC.pdf
 *
 * by Johan Bezem of JB Enterprises:
 *
 *	See http://www.bezem.de/en/
 */
static Word cwords[] = {
	/* Yes Virginia, we left #define off the list on purpose! */
	{ STRLEN("#elif"), "#elif" },
	{ STRLEN("#else"), "#else" },
	{ STRLEN("#endif"), "#endif" },
	{ STRLEN("#error"), "#error" },
	{ STRLEN("#ident"), "#ident" },
	{ STRLEN("#if"), "#if" },
	{ STRLEN("#ifdef"), "#ifdef" },
	{ STRLEN("#include"), "#include" },
	{ STRLEN("#line"), "#line" },
	{ STRLEN("#pragma"), "#pragma" },
	{ STRLEN("#sccs"), "#sccs" },
	{ STRLEN("#warning"), "#warning" },
	/**/
	{ STRLEN("_Alignas"), "_Alignas" },
	{ STRLEN("_Alignof"), "_Alignof" },
	{ STRLEN("_Atomic"), "_Atomic" },
	{ STRLEN("_Bool"), "_Bool" },
	{ STRLEN("_Complex"), "_Complex" },
	{ STRLEN("_Generic"), "_Generic" },
	{ STRLEN("_Imaginary"), "_Imaginary" },
	{ STRLEN("_Noreturn"), "_Noreturn" },
	{ STRLEN("_Pragma"), "_Pragma" },
	{ STRLEN("_Static_assert"), "_Static_assert" },
	{ STRLEN("_Thread_local"), "_Thread_local" },
	/**/
	{ STRLEN("alignas"), "alignas" },
	{ STRLEN("alignof"), "alignof" },
	{ STRLEN("and"), "and" },
	{ STRLEN("and_eq"), "and_eq" },
	{ STRLEN("auto"), "auto" },
	{ STRLEN("bitand"), "bitand" },
	{ STRLEN("bitor"), "bitor" },
	{ STRLEN("bool"), "bool" },
	{ STRLEN("break"), "break" },
	{ STRLEN("case"), "case" },
	{ STRLEN("char"), "char" },
	{ STRLEN("compl"), "compl" },
	{ STRLEN("const"), "const" },
	{ STRLEN("continue"), "continue" },
	{ STRLEN("default"), "default" },
	{ STRLEN("do"), "do" },
	{ STRLEN("double"), "double" },
	{ STRLEN("else"), "else" },
	{ STRLEN("enum"), "enum" },
	{ STRLEN("extern"), "extern" },
	{ STRLEN("false"), "false" },
	{ STRLEN("float"), "float" },
	{ STRLEN("for"), "for" },
	{ STRLEN("goto"), "goto" },
	{ STRLEN("I"), "I" },
	{ STRLEN("if"), "if" },
	{ STRLEN("inline"), "inline" },
	{ STRLEN("int"), "int" },
	{ STRLEN("long"), "long" },
	{ STRLEN("noreturn"), "noreturn" },
	{ STRLEN("not"), "not" },
	{ STRLEN("not_eq"), "not_eq" },
	{ STRLEN("or"), "or" },
	{ STRLEN("or_eq"), "or_eq" },
	{ STRLEN("register"), "register" },
	{ STRLEN("restrict"), "restrict" },
	{ STRLEN("return"), "return" },
	{ STRLEN("short"), "short" },
	{ STRLEN("signed"), "signed" },
	{ STRLEN("sizeof"), "sizeof" },
	{ STRLEN("static"), "static" },
	{ STRLEN("static_assert"), "static_assert" },
	{ STRLEN("struct"), "struct" },
	{ STRLEN("switch"), "switch" },
	{ STRLEN("thread_local"), "thread_local" },
	{ STRLEN("true"), "true" },
	{ STRLEN("typedef"), "typedef" },
	{ STRLEN("union"), "union" },
	{ STRLEN("unsigned"), "unsigned" },
	{ STRLEN("void"), "void" },
	{ STRLEN("volatile"), "volatile" },
	{ STRLEN("while"), "while" },
	{ STRLEN("xor"), "xor" },
	{ STRLEN("xor_eq"), "xor_eq" },
	/**/
	{ 0, NULL }
};

Word *
find_member(Word *table, const char *string)
{
	Word *w;
	for (w = table; w->length != 0; w++) {
		if (strncmp(string, w->word, w->length) == 0
		&& !isalpha(string[w->length]) && string[w->length] != '_')
			return w;
	}
	return NULL;
}

/*
 * Count chacacters and strip comments.  The stripped input is
 * sent to standard output.  The count is sent to to standard error
 * unless -i is given in which case the IOCCC size rule count is
 * sent to standard out.
 *
 * Not withstanding -i, if silence is true, then do not print anything
 * to standard output.
 */
int
count(int flags)
{
	Word *w;
	int span;
	char *p, buf[256];
	int lcount, wcount, bcount;
	int is_comment, is_word, dquote;
	int count, keywords, saved, kw_saved;

	/* Start of buffer sentinel. */
	buf[0] = ' ';

	count = saved = 0;
	keywords = kw_saved = 0;
	lcount = wcount = bcount = 0;
	is_comment = is_word = dquote = 0;

	/*
	 * "no matter how well you may think you understand this code,
	 *  you don't, so don't mess with it." :-)
	 */
	for ( ; fgets(buf+1, sizeof (buf)-1, stdin) != NULL;) {
		/* Leading whitespace before comment block? */
		span = strspn(buf+1, "\t ");
		if (buf[1+span] == '/' && buf[2+span] == '*') {
			/* Strip leading whitespace before comment block. */
			is_comment = 1;
		}

		for (p = buf+1; *p != '\0'; p++) {
			/* Strip comment block? */
			if (is_comment) {
				/* End of comment? */
				if (*p == '*' && p[1] == '/') {
					is_comment = 0;

					/* Remove whitespace and newline
					 * trailing closing comment.
					 */
					p += 1 + strspn(p+2, " \t\r\n");
				}
				/* Skip octets in comment block. */
				continue;
			}

			/* Start of comment block to strip? */
			/* "You are not expected to understand this" */
			if (!(flags & FLAG_KEEP) && !dquote && *p == '/' && p[1] == '*') {
				/* Begin comment block. */
				is_comment = 1;
				p++;
				continue;
			}

			/* Toggle start/end of double-quote string. */
			if (*p == '"' && p[-1] != '\\' && p[-1] != '\'')
				dquote = !dquote;

			/* C reserved word? */
			if (!dquote && (w = find_member(cwords, p)) != NULL) {
				keywords++;
				if (flags & FLAG_RESERVED) {
					bcount += w->length;
					if (!is_word) {
						is_word = 1;
						wcount++;
					}

					if (!(flags & FLAG_SILENCE))
						fputs(w->word, stdout);

					/* Count reserved word as one. */
					kw_saved += w->length - 1;
					p += w->length - 1;
					count++;
					continue;
				}
			}

			/* Everything above here is stripped from the input. */
			if (!(flags & FLAG_SILENCE))
				fputc(*p, stdout);

			bcount++;
			if (*p == '\n')
				lcount++;

			/* Ignore all whitespace. */
			if (isspace(*p)) {
				is_word = 0;
				saved++;
				continue;
			} else if (!is_word) {
				is_word = 1;
				wcount++;
			}

			/* Ignore curly braces and semicolons when followed
			 * by any whitspace or EOF.
			 */
			if (strchr("{;}", *p) != NULL
			&& (isspace(p[1]) || p[1] == '\0')) {
				saved++;
				continue;
			}
			/* Count this octet. */
			count++;
		}
	}

	/* final count */
	if (flags & FLAG_IOCCC_SIZE) {
		/* output the official IOCCC size tool size to standard out */
		printf("%d\n", count);
	} else {
		fprintf(stderr, "%d %d %d %d %d %d %d\n",
			lcount, wcount, bcount, count, saved,
			keywords, kw_saved);
	}
	return count;
}

int
main(int argc, char **argv)
{
	int ch;
	int flags = 0;

	/* parse args */
	while ((ch = getopt(argc, argv, "ikrs")) != -1) {
		switch (ch) {
		case 'i':
			flags |= (FLAG_RESERVED | FLAG_SILENCE |
				  FLAG_IOCCC_SIZE);
			break;
		case 'k':
			flags |= FLAG_KEEP;
			break;
		case 'r':
			flags |= FLAG_RESERVED;
			break;
		case 's':
			flags |= FLAG_SILENCE;
			break;
		default:
			fprintf(stderr, "%s\n", usage);
			return 2;
		}
	}

	/* count as directed by flags */
	(void) count(flags);

	/* All Done!!! All Done!!! -- Jessical Noll, age 2 */
	return 0;
}
