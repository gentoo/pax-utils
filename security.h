/* Various security related features.
 *
 * Copyright 2015 Gentoo Foundation
 * Distributed under the terms of the GNU General Public License v2
 *
 * Copyright 2015 Mike Frysinger  - <vapier@gentoo.org>
 */

#ifndef _PAX_SECURITY_H
#define _PAX_SECURITY_H

/* Whether to enable features that significantly impact speed. */
#ifdef SLOW_SECURITY
# define USE_SLOW_SECURITY 1
#else
# define USE_SLOW_SECURITY 0
#endif

#ifdef __linux__
/* Lock down the runtime; allow_forking controls whether to use a pidns. */
void security_init(bool allow_forking);
/* Disable forking; usable only when allow_forking above was true. */
void security_init_pid(void);
#else
static inline void security_init(bool allow_forking) {}
static inline void security_init_pid(void) {}
#endif

#endif
