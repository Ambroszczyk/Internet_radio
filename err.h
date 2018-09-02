#ifndef _ERR_
#define _ERR_

/* Wypisuje informację o błędnym zakończeniu funkcji systemowej
i kończy działanie programu. */
extern void syserr(const char *fmt, ...);

/* Wypisuje informacje o błędzie systemowym i NIE kończy działania programu */
extern void conterr(const char *fmt, ...);

/* Wypisuje informację o błędzie i kończy działanie programu. */
extern void fatal(const char *fmt, ...);

#endif