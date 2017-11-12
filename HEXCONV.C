#include <stdio.h>

main(int argc, char **argv)
{
  FILE    *infile,*outfile;
  char    s[80];
  int     i,length;
  int     firsttime = TRUE;
  unsigned int address;
  unsigned int load_address;
  long    offset = 0L;
  int     rectype;
  char    datastr[80];
  char    s1[20],s2[20],s3[20];
  char    c;
  char    *tmpfile = "zztmpzz.hex";

  if (argc < 2)
  {
    puts("\nUsage: hexconv file\n");
    puts("The HEX file will be read. The first address encountered");
    puts("is the load address. The user can give another load address");
    puts("");
    return(0);
  }

  infile = fopen(argv[1],"r");
  if (!infile)
  {
    printf("ERROR opening file %s",*(argv[1]));
    return(-1);
  }

  outfile = fopen(tmpfile,"w");
  if (!outfile)
  {
    puts("Error in creating temporary file");
    return(-2);
  }

  while (!feof(infile))
  {
    s[0] = '\0';
    fgets(s,80,infile);                /* Get input line                 */
    if (s[0] != ':') break;          /* End of file reached            */
    sscanf(s,"%c%2s%4s%2s%s",&c,s1,s2,s3,datastr);
    if (c!=':') return(-1);
    sscanf(s1,"%x",&length);
    sscanf(s2,"%X",&address);
    sscanf(s3,"%x",&rectype);
    if (firsttime && rectype == 0)    /* First datarecord */
    {
      printf("Load address: <%0X> ",address);
      gets(s);
      if (s)
        sscanf(s,"%x",&load_address);
      offset = address - load_address;
      firsttime = FALSE;
    }
    if (rectype == 0)     /* Only adjust data records */
      address -= offset;
    fprintf(outfile,"%c%2s%04X%2s%s\n",c,s1,address,s3,datastr);
  }

  fclose(infile);
  fclose(outfile);

  remove(argv[1]);
  i = rename(tmpfile,argv[1]);
  if (i)
  {
    printf("ERROR: coudn't rename tmpfile in %s\n",argv[1]);
    return(-1);
  }

  return(0);

}



