/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Check passwords against a list of pattern
 *
 * See \ref PWPOLICY_FILE_NAME for a syntax description of the pattern
 * file.
 */

#include "pwpolicy.h"

#include <errno.h> /* for errno */
#include <glib.h>  /* for g_strdup_printf, g_ascii_strcasecmp, g_free, ... */
#include <stdio.h> /* for fclose, fgets, fopen, FILE, ferror, EOF, getc */
#include <stdlib.h>
#include <string.h> /* for strstr, strlen, strncmp */

#ifndef DIM
#define DIM(v) (sizeof (v) / sizeof ((v)[0]))
#define DIMof(type, member) DIM (((type *) 0)->member)
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief The name of the pattern file
 *
 * This file contains pattern with bad passphrases.  The file is line
 * based with maximum length of 255 bytes per line and expected to be
 * in UTF-8 encoding.  Each line may either be a comment line, a
 * simple string, a regular expression or a processing instruction.
 * The lines are parsed sequentially.
 *
 * *Comments* are indicated by a hash mark ('#') as the first non
 * white-space character of a line followed immediately by a space or
 * end of line.  Such a comment line is completely ignored.
 *
 * *Simple strings* start after optional leading white-space.  They
 * are compared to the password under validation.  The comparison is
 * case insensitive for all ASCII characters.
 *
 * *Regular expressions* start after optional leading white-space with
 * either a single slash ('/') or an exclamation mark ('!') directly
 * followed by a slash.  They extend to the end of the line but may be
 * terminated with another slash which may then only be followed by
 * more white-space.  The regular expression are Perl Compatible
 * Regular Expressions (PCRE) and are by default case insensitive.  If
 * the regular expression line starts with the exclamation mark, the
 * match is reversed; i.e. an error is returned if the password does
 * not match.
 *
 * *Processing instructions* are special comments to control the
 * operation of the policy checking.  The start like a comment but the
 * hash mark is immediately followed by a plus ('+') signed, a
 * keyword, an optional colon (':') and an optional value string.  The
 * following processing instructions are supported:
 *
 *   #+desc[:] STRING
 *
 *     This is used to return a meaningful error message.  STRING is
 *     used a the description for all errors up to the next /desc/ or
 *     /nodesc/ processing instruction.
 *
 *   #+nodesc
 *
 *     This is syntactic sugar for /desc/ without a value.  It
 *     switches back to a default error description (pattern file name
 *     and line number).
 *
 *   #+username
 *
 *     This is used to perform checks on the name/password
 *     combination.  Currently this checks whether the password
 *     matches or is included in the password. It may eventually be
 *     extended to further tests.
 */
#define PWPOLICY_FILE_NAME GVM_SYSCONF_DIR "/pwpolicy.conf"

/**
 * @brief Flag indicating that passwords are not checked.
 */
static gboolean disable_password_policy;

/**
 * @return A malloced string to be returned on read and configuration
 * errors.
 */
static char *
policy_checking_failed (void)
{
  return g_strdup ("Password policy checking failed (internal error)");
}

/**
 * @brief Check whether a string starts with a keyword
 *
 * Note that the keyword may optionally be terminated by a colon.
 *
 * @param string   The string to check
 * @param keyword  The keyword
 *
 * @return NULL if the keyword is not found.  If found a pointer into
 *         \p string to the value of the keyword with removed leading
 *         spaces is returned.
 */
static char *
is_keyword (char *string, const char *keyword)
{
  int idx, slen;
  char *tmp;
  idx = strlen (keyword);
  slen = strlen (string);

  if (!strncmp (string, keyword, idx))
    {
      tmp = string + idx;
      if (tmp - string > slen)
        return NULL;
      // skip optional:
      if (*tmp == ':')
        tmp++;
      if (tmp - string > slen)
        return NULL;

      for (; tmp - string < slen && g_ascii_isspace (*tmp); tmp++)
        {
          // skip whitespace
        }
      return tmp;
    }
  return NULL;
}

/**
 * @brief Parse one line of a pettern file
 *
 * @param line     A null terminated buffer with the content of the line.
 *                 The line terminator has already been stripped. It may
 *                 be modified after return.
 * @param fname    The name of the pattern file for error reporting
 * @param lineno   The current line number for error reporting
 * @param descp    Pointer to a variable holding the current description
 *                 string or NULL for no description.
 * @param password The password to check.
 * @param username The username to check.
 *
 * @return NULL on success or a malloced string with an error
 *         description.
 */
static char *
parse_pattern_line (char *line, const char *fname, int lineno, char **descp,
                    const char *password, const char *username)
{
  char *ret = NULL;
  char *p;
  size_t n;

  /* Skip leading spaces.  */
  while (g_ascii_isspace (*line))
    line++;

  if (!*line) /* Empty line.  */
    {
      ret = NULL;
    }
  else if (*line == '#' && line[1] == '+') /* Processing instruction.  */
    {
      line += 2;
      p = is_keyword (line, "desc");
      if (p)
        {
          g_free (*descp);
          if (*p)
            *descp = g_strdup (p);
          else
            *descp = NULL;
        }
      else if ((is_keyword (line, "nodesc")))
        {
          g_free (*descp);
          *descp = NULL;
        }
      else if ((p = is_keyword (line, "search")))
        {
          g_warning ("unsupported password-policy search directive at line %d: %s",
                     lineno, p);
          ret = policy_checking_failed ();
        }
      else if (is_keyword (line, "username"))
        {
          /* Fixme: The include check is case sensitive and the strcmp
             does only work with ascii.  Changing this required a bit
             more more (g_utf8_casefold) and also requires checking
             for valid utf8 sequences in the password and all pattern.  */
          if (!username)
            ret = NULL;
          else if (!g_ascii_strcasecmp (password, username))
            ret = g_strdup_printf ("Weak password (%s)",
                                   "user name matches password");
          else if (strstr (password, username))
            ret = g_strdup_printf ("Weak password (%s)",
                                   "user name is part of the password");
          else if (strstr (username, password))
            ret = g_strdup_printf ("Weak password (%s)",
                                   "password is part of the user name");
          else
            ret = NULL;
        }
      else
        {
          g_warning ("error reading '%s', line %d: %s", fname, lineno,
                     "unknown processing instruction");
          ret = policy_checking_failed ();
        }
    }
  else if (*line == '#') /* Comment */
    {
      ret = NULL;
    }
  else if (*line == '/'
           || (*line == '!' && line[1] == '/')) /* Regular expression.  */
    {
      int rev = (*line == '!');
      if (rev)
        line++;
      line++;
      n = strlen (line);
      if (n && line[n - 1] == '/')
        line[n - 1] = 0;
      if (((!g_regex_match_simple (line, password, G_REGEX_CASELESS, 0)) ^ rev))
        ret = NULL;
      else if (*descp)
        ret = g_strdup_printf ("Weak password (%s)", *descp);
      else
        ret =
          g_strdup_printf ("Weak password (see '%s' line %d)", fname, lineno);
    }
  else /* Simple string.  */
    {
      if (g_ascii_strcasecmp (line, password))
        ret = NULL;
      else if (*descp)
        ret = g_strdup_printf ("Weak password (%s)", *descp);
      else
        ret =
          g_strdup_printf ("Weak password (see '%s' line %d)", fname, lineno);
    }

  return ret;
}

/**
 * @brief Validate a password against the pattern file
 *
 * @param[in] password  The password to check
 * @param[in] username  The user name or NULL.  This is used to check
 *                      the passphrase against the user name.
 *
 * @return NULL on success or a malloced string with an error
 *         description.
 */
char *
gvm_validate_password (const char *password, const char *username)
{
  const char *patternfile = PWPOLICY_FILE_NAME;
  char *ret;
  FILE *fp;
  int lineno;
  char line[256];
  char *desc = NULL;

  if (disable_password_policy)
    return NULL;

  if (!password || !*password)
    return g_strdup ("Empty password");

  fp = fopen (patternfile, "r");
  if (!fp)
    {
      g_warning ("error opening '%s': %s", patternfile, g_strerror (errno));
      return policy_checking_failed ();
    }
  lineno = 0;
  ret = NULL;
  while (fgets (line, DIM (line) - 1, fp))
    {
      size_t len;

      lineno++;
      len = strlen (line);
      if (!len || line[len - 1] != '\n')
        {
          g_warning ("error reading '%s', line %d: %s", patternfile, lineno,
                     len ? "line too long" : "line without a LF");
          ret = policy_checking_failed ();
          break;
        }
      line[--len] = 0; /* Chop the LF. */
      if (len && line[len - 1] == '\r')
        line[--len] = 0; /* Chop an optional CR. */
      ret = parse_pattern_line (line, patternfile, lineno, &desc, password,
                                username);
      if (ret)
        break;

      bzero (line, sizeof (line));
    }

  fclose (fp);
  g_free (desc);
  return ret;
}

/**
 * @brief Disable all password policy checking
 */
void
gvm_disable_password_policy (void)
{
  disable_password_policy = TRUE;
  g_warning ("Password policy checking has been disabled.");
}
