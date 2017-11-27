#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

char* find_re (char* regex, char* text, int group)
{
  char * source = text;

  char * regexString = regex;
  size_t maxGroups = 3;
  char *result = 0;

  regex_t regexCompiled;
  regmatch_t groupArray[maxGroups];

  if (regcomp(&regexCompiled, regexString, REG_EXTENDED))
    {
      printf("Could not compile regular expression.\n");
      return NULL;
    };

  if (regexec(&regexCompiled, source, maxGroups, groupArray, 0) == 0)
    {
      if (groupArray[group].rm_so != (size_t)-1) {
          int length = groupArray[group].rm_eo - groupArray[group].rm_so;
          result = malloc(length + 1);
          strncpy(result, text + groupArray[group].rm_so, length);
          result[length] = '\0';
      }
    }

  regfree(&regexCompiled);

  return result;
}


char* read_file(char *filename) {
    char *source = NULL;
    FILE *fp = fopen(filename, "r");
    if (fp != NULL) {
        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            long bufsize = ftell(fp);
            if (bufsize == -1) { /* Error */ }

            /* Allocate our buffer to that size. */
            source = malloc(sizeof(char) * (bufsize + 1));

            /* Go back to the start of the file. */
            if (fseek(fp, 0L, SEEK_SET) != 0) { /* Error */ }

            /* Read the entire file into memory. */
            size_t newLen = fread(source, sizeof(char), bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                source[newLen++] = '\0'; /* Just to be safe. */
            }
        }
        fclose(fp);
    }
    return source;
}
