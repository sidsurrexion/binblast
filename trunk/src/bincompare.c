/**************************************************
 * bincompare.c
 * Scott Miller
 * Performs a BLAST-type scoring on four-byte
 * packed binary data where the highest score (X1)
 * matches all bytes, the next score (X2) matches
 * the first two bytes, and the lowest score (X3)
 * matches the first byte, and no match results
 * in a penalty (X4)
 *************************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define OPT_THRESHOLD_DEFAULT	10
#define OPT_X1_DEFAULT	6
#define OPT_X2_DEFAULT	5
#define OPT_X3_DEFAULT	4
#define OPT_X4_DEFAULT	-4
int MATCH_X1 = OPT_X1_DEFAULT;
int MATCH_X2 = OPT_X2_DEFAULT;
int MATCH_X3 = OPT_X3_DEFAULT;
int MATCH_X4 = OPT_X4_DEFAULT;

#define WORD  unsigned char
#define DWORD unsigned short int
#define QWORD unsigned long int

/*****************************************************
 * dtime()
 * Returns the current time as a double in seconds
 *  since the epoch.
 ****************************************************/
double dtime() {
	struct timeval t;

	gettimeofday(&t, NULL);
	return(t.tv_sec + t.tv_usec/1000000.0);
}

/**************************************************
 * load_file(dat, filename, offset, len)
 * dat - a pointer to what will be a pointer to the
 *        allocated array
 * filename - the name of the dat file to load
 * offset - the offset within the file from which to
 *           start (in quadwords)
 * len - the length to load into memory (in quadwords)
 * Opens filename, allocates *dat, seeks to offset,
 *  and fills *dat with len quadwords
 * Returns 0 on success, -1 on failure
 ************************************************/
int load_file(void **dat, char *filename, unsigned long offset, unsigned long len)
{
	FILE *file;
	
	/*** Open filename ***/
	file = fopen(filename,"rb");
	if( file == 0 ) return(-1);
	
	/*** Allocate *dat ***/
	*dat = (void *)malloc(len * 4);
	if(*dat == 0) {
		fclose(file);
		return(-1);
	}

	/*** Seek file ***/
	if(fseek(file, offset * 4, SEEK_SET) != 0) {
		free(*dat);
		fclose(file);
		return(-1);
	}
	
	/*** Load *dat ***/
	if(fread(*dat, len * 4, 1, file)
	  != 1) {
		free(*dat);
		fclose(file);
		return(-1);
	}
	
	/*** All done ***/
	fclose(file);
	return(0);
}

/*****************************************************
 * score(a,aqwords,b,bqwords,
 *       threshold,mquadwords,boundary)
 * a, aqwords - a memory location and its length 
 *              (in quadwords)
 * b, bqwords - a memory location and its length
 *              (in quadwords)
 * threshold - after reaching a local max, the score
 *               terminates if that maximum is not
 *               exceded by the score of the next
 *               n more quadwords
 * mquadwords - the number of quadwords before the 
 *               maximum score
 * boundary - if the result may depend on an edge,
 *              0 = not on boundary
 *              1 = right boundary
 * score - the maximum score value 
 *
 * Computes a score pair (mlen,score) for the a
 *  and b data.  If mlen = a or mlen = b, the score
 *  is not complete.
 * Score calculations end when a zero quadword is
 *  encountered in a or b
 * A quadword match adds 3 to the score
 * A match of the first two words adds 2 to the score
 * The first two words being in the same group adds 1 to
 *  the score
 ***************************************************/
long score(void *a, long aqwords, 
	   void *b, long bqwords,
	   int threshold,
	   long *mquadwords,
	   int *boundary)
{
	long curscore=0;
	long maxscore=0;
	
	long i=0;
	long maxlen=0;
	long notexceeded=0;
	
	maxlen = aqwords > bqwords ? bqwords : aqwords;
	/*** Begin score ***/
	for(i=0;i<maxlen;i++) {
		/** If either a or b is zero, the match stops **/
		if( (*((QWORD *)a) == (QWORD)0) ||
		    (*((QWORD *)b) == (QWORD)0) )
			break;

		/** Exact match **/
		if       ( *((QWORD *)a) == *((QWORD *)b) ) {
			curscore += MATCH_X1;
		/** Partial match **/
		} else if( *((DWORD *)a) == *((DWORD *)b) ) {
			curscore += MATCH_X2;
		/** Class match **/
		} else if( *(( WORD *)a) == *(( WORD *)b) ) {
			curscore += MATCH_X3;
		/** No match **/
		} else {
			curscore += MATCH_X4;
		}
		
		/** Update maximum score or give up **/
		if(curscore > maxscore) {
			maxscore = curscore;
			notexceeded = 0;
		} else {
			if((notexceeded >= threshold) ||
			   (curscore < 0)) break; 
			notexceeded++;
		}
		
		/** Move to the next quadword **/
		a += sizeof(QWORD);
		b += sizeof(QWORD);
	}

	/*** Boundary check ***/
	if(i==maxlen) {
		/* NOTE: This may reduce the maximum
		 *  score if there is nothing on the
		 *  other edge of the match...       */
		*boundary = 1;
		maxscore = curscore;
		notexceeded = 0;
	} else {
		*boundary = 0;
	}
	
	/*** Return the score pair ***/
	*mquadwords = i - notexceeded;
	return(maxscore);
}

/*****************************************************
 * correlate(a,aqwords,b,bqwords,
 * 	     lresults, results, rresults,
 * 	     threshold)
 * a, aqwords - a memory location and its length 
 *              (in quadwords) - must be the
 *              smaller of a,b
 * b, bqwords - a memory location and its length
 *              (in quadwords) - must be the 
 *              larger of a,b
 *              
 * threshold  - after reaching a local max, the score
 *               terminates if that maximum is not
 *               exceded by the score of the next
 *               n more quadwords
 * Correlates the two to find maximum scores
 * 
 ***************************************************/
int correlate(void *a, long aqwords, 
	    void *b, long bqwords,
	    int threshold) 
{
	void *small, *large;
	long sqwords, lqwords;
	long i;
	small = a; sqwords = aqwords;
	large = b; lqwords = bqwords;

	/*** Consider all points of the larger ***/
	for(i=-sqwords;i<lqwords;i++) {
		long startj;
		long j;

		/** Determine where to start in the smaller **/
		if(i>0L) {
			startj = 0;
		} else {
			startj = -i;
		}
	
		/** Start matching at all points of the smaller **/
		for(j=startj;j<sqwords;j++) {
			long dlen;
			int boundary;
			long dscore;
			
			/* Get the score */
			dscore = score(small + (j*4),sqwords - j,
			         large + ((i + j) *4),lqwords - i - j,
			         threshold, &dlen, &boundary);

			/* If there was no significant score, go on.... */
			if((dscore < 13) || (dlen < 4)) continue;
			
			/* Add to the results */
			printf("%ld,%ld,%ld,%ld\n",
				j,
				j + i,
				dscore,
				dlen);

			/* The match may have consumed more than
			 *  the current token                    */
			j += dlen - 1;
		}
	}

	/* All done */
	return(0);
	
}

/*************************************************************
 * fileinfo typedef
 * A useful structure to keep track of the compare parameters
 * for a file
 ************************************************************/
typedef struct fileinfo_ {
	char *name;         /* The name of the file */
	unsigned long compareoffset; /* The offset (within the file, relative */
	                    /*  to the start of the file) from which */
			    /*  to begin the comparison */
	unsigned long comparelen;    /* The length to consider for a match */
} fileinfo;

/*************************************************************
 * options typedef
 * A useful encapsulation for the options that may be passed
 * to this program
 ************************************************************/
typedef struct options_ {
	fileinfo f[2];      /* The files to use for comparison */
	int threshold;	    /* The threshold parameter for  */
			    /*  MSP estimation	 */
	int x1,x2,x3,x4;    /* Scoring constants */
} options;

/************************************************************
 * unsigned long useful_strtoul(str)
 * str - a string to convert to an unsigned long
 * Uses strtoul base 0 for conversion, so can accept octal,
 *  decimal, and hexadecimal input
 * Returns the value if converted properly *or* the most
 *  positive long value on failure:
 *  overflow, 
 *  near overflow (th enumber decoded was the maximum 
 *    long value),
 *  not all of str was used for the conversion
 ***********************************************************/
#define NOT_THAT_USEFUL (long)(((unsigned long) (-1)) / 2)
long useful_strtol(char *str)
{
	unsigned long i;
	char *endptr;

	/* Attempt conversion */
	i = strtoul(str, &endptr, 0);

	/* Did we really consume everything to the end? */
	/* The longest possible string is: */
	/* 037777777777 */
	if(strnlen(str,13) != (int)(endptr - str) )
		return (NOT_THAT_USEFUL);

	/* The conversion was successful */
	return i;
}

/************************************************************
 * unsigned long useful_strtoul(str)
 * str - a string to convert to an unsigned long
 * Uses strtoul base 0 for conversion, so can accept octal,
 *  decimal, and hexadecimal input
 * Returns the value if converted properly *or* the maximum 
 * long value on failure:
 *  overflow, 
 *  near overflow (th enumber decoded was the maximum 
 *    long value),
 *  not all of str was used for the conversion
 ***********************************************************/
#define UNOT_THAT_USEFUL ((unsigned long) (-1))
unsigned long useful_strtoul(char *str)
{
	unsigned long i;
	char *endptr;

	/* Attempt conversion */
	i = strtoul(str, &endptr, 0);

	/* Did we really consume everything to the end? */
	/* The longest possible string is: */
	/* 037777777777 */
	if(strnlen(str,13) != (int)(endptr - str) )
		return (UNOT_THAT_USEFUL);

	/* The conversion was successful */
	return i;
}

/************************************************************
 * print_usage(name)
 * name - the name of this reported, i.e. as in argv[0]
 * Prints the command line usage
 ***********************************************************/
void print_usage(char *name)
{
	printf("Usage: %s [options] fileA [offset [len]] fileB [offset [len]]\n", name);
	printf("Options:\n");
	printf("  -h Print this help\n");
	printf("  -t=N: Set the threshold parameter to N, default is %d\n",
			OPT_THRESHOLD_DEFAULT);
	printf("  -x1=N: Set scoring parameter x1 to N, default is %d\n", 
			OPT_X1_DEFAULT);
	printf("  -x2=N: Set scoring parameter x2 to N, default is %d\n", 
			OPT_X2_DEFAULT);
	printf("  -x3=N: Set scoring parameter x3 to N, default is %d\n", 
			OPT_X3_DEFAULT);
	printf("  -x4=N: Set scoring parameter x4 to N, default is %d\n", 
			OPT_X4_DEFAULT);
printf("Files:\n");
	printf("  name - The name of the comparison file, i.e. name.dat\n");
	printf("  offset - The start offset in quadwords\n");
	printf("           Relative to the start of the file\n");
	printf("           Defaults to 0\n");
	printf("  len - The length for comparison in quadwords\n");
	printf("           Defaults to the name's byte length / 4\n");
	printf(" The fileA length must be smaller (or the same size)\n");
	printf("  as fileB length.\n");
	exit(-1);
}	

/************************************************************
 * void parse_args(argc, argv, opts)
 * argc - the number of arguments to parse
 * argv - an array of the arguments to parse
 * opts - An options structure into which to store the 
 *         results
 * Parses the command line arguments and populates the 
 *  options structure
 ***********************************************************/
void parse_args(int argc, char **argv, options *opts) 
{
	int argcur = 1; /* Something to keep track of which */
	                /*  argument to be processed */
	struct stat filestats; /* Needed to capture file stats */
	int i; /* A counter */

	/* Before getting started, the minimum number of */
	/*  arguments to this is 2, the two binary files */
	if(argc < 3) {
		print_usage(argv[0]);
	}

	/* Set some of the defaults */
	opts->threshold = OPT_THRESHOLD_DEFAULT;
	opts->x1 = OPT_X1_DEFAULT;
	opts->x2 = OPT_X2_DEFAULT;
	opts->x3 = OPT_X3_DEFAULT;
	opts->x4 = OPT_X4_DEFAULT;
	
	/* Options */
	while(argv[argcur][1] == '-' && argcur < argc) {
		/* Usage */
		if (strncmp(argv[argcur],"-h",3) == 0) {
			print_usage(argv[0]);
		}

		/* Threshold  */
		if (strncmp(argv[argcur],"-t=",3) == 0) {
			opts->threshold = useful_strtoul(&argv[argcur][3]);
			if(opts->threshold == UNOT_THAT_USEFUL) 
				print_usage(argv[0]);
		}

		/* x1  */
		if (strncmp(argv[argcur],"-x1=",4) == 0) {
			opts->x1 = useful_strtol(&argv[argcur][4]);
			if(opts->x1 == NOT_THAT_USEFUL) 
				print_usage(argv[0]);
		}
		
		/* x2  */
		if (strncmp(argv[argcur],"-x2=",4) == 0) {
			opts->x2 = useful_strtol(&argv[argcur][4]);
			if(opts->x2 == NOT_THAT_USEFUL) 
				print_usage(argv[0]);
		}
		/* x3  */
		if (strncmp(argv[argcur],"-x3=",4) == 0) {
			opts->x3 = useful_strtol(&argv[argcur][4]);
			if(opts->x3 == NOT_THAT_USEFUL) 
				print_usage(argv[0]);
		}
		
		/* x4  */
		if (strncmp(argv[argcur],"-x4=",4) == 0) {
			opts->x4 = useful_strtol(&argv[argcur][4]);
			if(opts->x4 == NOT_THAT_USEFUL) 
				print_usage(argv[0]);
		}
	
	}

	/* Files */
	for(i=0;i<2;i++) {
		/* File name */
		if(argcur >= argc) print_usage(argv[0]);
		opts->f[i].name = argv[argcur];
		argcur++;
		
		/* Offset */
		if( (argcur < argc) && 
		    (useful_strtoul(argv[argcur]) != UNOT_THAT_USEFUL) ) {
			opts->f[i].compareoffset = useful_strtoul(argv[argcur]);
			argcur++;
		} else {
			opts->f[i].compareoffset = 0L;
		}
		
		/* Len */
		if( (argcur < argc) &&
		    (useful_strtoul(argv[argcur]) != UNOT_THAT_USEFUL ) ) {
			opts->f[i].comparelen = useful_strtoul(argv[argcur]);
		 	argcur++;

		} else {
			if(stat(opts->f[i].name,&filestats) == 0) {
				opts->f[i].comparelen = filestats.st_size / 4;
				opts->f[i].comparelen -= opts->f[i].compareoffset;
			} else {
				fprintf(stderr,"Unable to stat %s\n",
						opts->f[i].name);
				exit(-2);
			}
		}
		
		/* Offset + len cannot excede the file */
		if(stat(opts->f[i].name,&filestats) == 0) {
			if ((opts->f[i].compareoffset + opts->f[i].comparelen) >
			    (filestats.st_size / 4)) {
				fprintf(stderr,"Offset + len execedes size of %s\n", opts->f[i].name);
				exit(-3);
			}
		} else {
			fprintf(stderr,"Unable to stat %s\n",
					opts->f[i].name);
			exit(-2);
		}

		/* Sanity check: offset + len cannot overflow */
		if(opts->f[i].compareoffset + opts->f[i].comparelen <
			opts->f[i].compareoffset) {
			fprintf(stderr,"Offset + len overflows for %s\n", opts->f[i].name);
			exit(-4);
		}
		
		printf("File %s, offset %ld, len %ld\n",
			opts->f[i].name,
			opts->f[i].compareoffset,
			opts->f[i].comparelen);
	}
}

/************************************************************
 * int perform_bincompare(opts)
 * opts - a fully populated, validated options structure
 * Performs the comparison specified by opts and returns 0
 *  on success
 ***********************************************************/
int perform_bincompare(options *opts)
{
	void *datA, *datB; /* The memory locations of the */
			   /* comparison data */
	double tic, toc;   /* Timing storage */

	/* Set the match constants */
	MATCH_X1 = opts->x1;
	MATCH_X2 = opts->x2;
	MATCH_X3 = opts->x3;
	MATCH_X4 = opts->x4;

	/* Load the files */
	if(
	(load_file(&datA,opts->f[0].name,
		         opts->f[0].compareoffset,
			 opts->f[0].comparelen) != 0) ||
	(load_file(&datB,opts->f[1].name,
		         opts->f[1].compareoffset,
			 opts->f[1].comparelen) != 0)
	) {
		fprintf(stderr,"Unable to load dat files\n");
		return(-1);
	}
	
	/* Perform the correlation */
	tic = dtime();
	correlate(datA,opts->f[0].comparelen,
	  	  datB,opts->f[1].comparelen,
		  opts->threshold);
	toc = dtime();
	printf("Comparison took %g seconds.\n",toc-tic);

	/* Free memory */
	free(datA); free(datB);

	return(0);
}

int main(int argc, char **argv)
{
	options opts;
	
	parse_args(argc,argv,&opts);

	return(perform_bincompare(&opts));
	
}


