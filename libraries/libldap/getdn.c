/*
 *  Copyright (c) 1994 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getdn.c
 */

#include "portable.h"

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
extern char *strdup (const char *);
extern char *strtok (char *, const char *);

#include "ldap-int.h"

static char **explode_name( char *name, int notypes, int is_dn );

char *
ldap_get_dn( LDAP *ld, LDAPMessage *entry )
{
	char		*dn;
	BerElement	tmp;

	Debug( LDAP_DEBUG_TRACE, "ldap_get_dn\n", 0, 0, 0 );

	if ( entry == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return( NULL );
	}

	tmp = *entry->lm_ber;	/* struct copy */
	if ( ber_scanf( &tmp, "{a", &dn ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	return( dn );
}

char *
ldap_dn2ufn( char *dn )
{
	char	*p, *ufn, *r;
	int	state;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2ufn\n", 0, 0, 0 );

	if ( ldap_is_dns_dn( dn ) || ( p = strchr( dn, '=' )) == NULL )
		return( strdup( dn ));

	ufn = strdup( ++p );

#define INQUOTE		1
#define OUTQUOTE	2
	state = OUTQUOTE;
	for ( p = ufn, r = ufn; *p; p++ ) {
		switch ( *p ) {
		case '\\':
			if ( *++p == '\0' )
				p--;
			else {
				*r++ = '\\';
				*r++ = *p;
			}
			break;
		case '"':
			if ( state == INQUOTE )
				state = OUTQUOTE;
			else
				state = INQUOTE;
			*r++ = *p;
			break;
		case ';':
		case ',':
			if ( state == OUTQUOTE )
				*r++ = ',';
			else
				*r++ = *p;
			break;
		case '=':
			if ( state == INQUOTE )
				*r++ = *p;
			else {
				char	*rsave = r;

				*r-- = '\0';
				while ( !isspace( *r ) && *r != ';'
				    && *r != ',' && r > ufn )
					r--;
				r++;

				if ( strcasecmp( r, "c" )
				    && strcasecmp( r, "o" )
				    && strcasecmp( r, "ou" )
				    && strcasecmp( r, "st" )
				    && strcasecmp( r, "l" )
				    && strcasecmp( r, "cn" ) ) {
					r = rsave;
					*r++ = '=';
				}
			}
			break;
		default:
			*r++ = *p;
			break;
		}
	}
	*r = '\0';

	return( ufn );
}

char **
ldap_explode_dns( char *dn )
{
	int	ncomps, maxcomps;
	char	*s;
	char	**rdns;

	if ( (rdns = (char **) malloc( 8 * sizeof(char *) )) == NULL ) {
		return( NULL );
	}

	maxcomps = 8;
	ncomps = 0;
	for ( s = strtok( dn, "@." ); s != NULL; s = strtok( NULL, "@." ) ) {
		if ( ncomps == maxcomps ) {
			maxcomps *= 2;
			if ( (rdns = (char **) realloc( rdns, maxcomps *
			    sizeof(char *) )) == NULL ) {
				return( NULL );
			}
		}
		rdns[ncomps++] = strdup( s );
	}
	rdns[ncomps] = NULL;

	return( rdns );
}

char **
ldap_explode_dn( char *dn, int notypes )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_dn\n", 0, 0, 0 );

	if ( ldap_is_dns_dn( dn ) ) {
		return( ldap_explode_dns( dn ) );
	}
	return explode_name( dn, notypes, 1 );
}

char **
ldap_explode_rdn( char *rdn, int notypes )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_rdn\n", 0, 0, 0 );
	return explode_name( rdn, notypes, 0 );
}

static char **
explode_name( char *name, int notypes, int is_dn )
{
	char	*p, *q, **parts = NULL;
	int	state, count = 0, endquote, len;

	p = name-1;
	state = OUTQUOTE;

	do {

		++p;
		switch ( *p ) {
		case '\\':
			if ( *++p == '\0' )
				p--;
			break;
		case '"':
			if ( state == INQUOTE )
				state = OUTQUOTE;
			else
				state = INQUOTE;
			break;
		case '+':
			if (!is_dn)
				goto end_part;
			break;
		case ';':
		case ',':
			if (!is_dn)
				break;
			goto end_part;
		case '\0':
		end_part:
			if ( state == OUTQUOTE ) {
				++count;
				if ( parts == NULL ) {
					if (( parts = (char **)malloc( 8
						 * sizeof( char *))) == NULL )
						return( NULL );
				} else if ( count >= 8 ) {
					if (( parts = (char **)realloc( parts,
						(count+1) * sizeof( char *)))
						== NULL )
						return( NULL );
				}
				parts[ count ] = NULL;
				endquote = 0;
				if ( notypes ) {
					for ( q = name;
					    q < p && *q != '='; ++q ) {
						;
					}
					if ( q < p ) {
						name = ++q;
					}
					if ( *name == '"' ) {
						++name;
					}
					
					if ( *(p-1) == '"' ) {
						endquote = 1;
						--p;
					}
				}

				len = p - name;
				if (( parts[ count-1 ] = (char *)calloc( 1,
				    len + 1 )) != NULL ) {
				    	SAFEMEMCPY( parts[ count-1 ], name,
					    len );
					parts[ count-1 ][ len ] = '\0';
				}

				/*
				 *  Don't forget to increment 'p' back to where
				 *  it should be.  If we don't, then we will
				 *  never get past an "end quote."
				 */
				if ( endquote == 1 )
					p++;

				name = *p ? p + 1 : p;
				while ( isascii( *name ) && isspace( *name ) )
					++name;
			}
			break;
		}
	} while ( *p );

	return( parts );
}


int
ldap_is_dns_dn( char *dn )
{
	return( dn[ 0 ] != '\0' && strchr( dn, '=' ) == NULL &&
	    strchr( dn, ',' ) == NULL );
}

