/************************************************
*
*    6502 disassembler
*    Disassebles INTEL-HEX16 code
*
*    V0.1 901212    H.v.A.
*
*************************************************/

char *idstr = "\n6502-disassembler V1.0     (C)H.B.J. van Asselt\n";

#define DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ADDRESS long
#define BYTE unsigned char
#define WORD unsigned int

/*----------------------
| Define error codes
----------------------*/
#define OPEN_ERR  -1
#define DUP_ERR   -2
#define ALLOC_ERR -3
#define OVERFLOW  -4

/*---------------
| Define sizes
---------------*/
#define OBJ_SIZE   0x8000         /* 32 KB Size of object code buffer */
#define STRLEN     80             /*       Size of a string           */
#define MAX_LABELS 500             /* max. no. labels to process       */

/*--------------------------
| Define instruction types
---------------------------*/
#define ABSOLUTE   0x0001  /* A */
#define JUMP       0x0004  /* J */
#define BRANCH     0x0008  /* B */
#define ZEROPAGE   0x0080  /* Z */
#define VAR2       0x0100  /* 2 */
#define CMOSCODE   0x0200  /* C */

/*--------------------------
| Definitions for data type
----------------------------*/
#define UNKNOWN    0x0000
#define DATA       0x0001
#define CODE       0x0002

/*--------------------------
| Definitions for file type
----------------------------*/
#define HEX        0x0001
#define BIN        0x0002
#define OBJ        0x0004

/*------------
| Prototypes
-------------*/
int  build_mnemonictable(void);
void clear_mnemonictable(void);
void clear_labeltabel(void);
int  read_labelfile(void);
int  load_objfile(void);
int  load_hexfile(void);
int  get_datatype(ADDRESS address);
int  pass1(void);
int  pass2(void);
void usage(void);

/*---------------------
| Definition of tables
----------------------*/
typedef struct
{
  char mnemonic[20];
  int  no_bytes;
  int  type;
}
MNEMONIC_TABLE;
MNEMONIC_TABLE table[256];

typedef struct
{
  ADDRESS address;
  char label[15];
  int  type;          /* CODE or DATA */
}
LABEL_TABLE;
LABEL_TABLE labeltabel[MAX_LABELS];

/*-------------------
| Global variables
-------------------*/
char basename[30];         /* Base file name (without extension) */
int  filetype = 0;
int  cmos = FALSE;
int  asm_output = FALSE;
int  datatype = CODE;
char hexstr[STRLEN];
char instr_str[STRLEN];
char comment[STRLEN];
char paramstr[STRLEN];

BYTE    *obj_code = NULL;      /* Pointer to object code in memory  */
ADDRESS offset = 0xF800;       /* Offset to object code             */
ADDRESS start_address = 0;     /* Start address of disassmbly       */
ADDRESS stop_address = 0;      /* Stop address of disassembly       */
ADDRESS load_address = 0;      /* Start address of objectcode       */
ADDRESS end_address = 0;       /* Endaddress of objectcode          */

/*-------------------------------------------------------------------
|   FUNCTION: get_mnemonic(int index)
|    PURPOSE: get pointer to mnemonic from mnemonic table
| DESRIPTION: -
|    RETURNS: Pointer to mnemonic
|    VERSION: 901213 V0.1
---------------------------------------------------------------------*/
char *get_mnemonic(int index)
{
  return(table[index].mnemonic);
}

/*-------------------------------------------------------------------
|   FUNCTION: get_instrlen(int index)
|    PURPOSE: get instruction length
| DESRIPTION: -
|    RETURNS: Number of bytes of the instruction
|    VERSION: 901213 V0.1
---------------------------------------------------------------------*/
int get_instrlen(int index)
{
  if (table[index].mnemonic[0] != '-')     /* if mnemonic exists */
    return((int) table[index].no_bytes);
  else
    return(1);
}

/*-------------------------------------------------------------------
|   FUNCTION: decode_byte(char *s)
|    PURPOSE: decode a byte from character stream s
| DESRIPTION: Takes the first two digits and convert them to a BYTE
|    RETURNS: The value decoded
|    VERSION: 901213 V0.1
---------------------------------------------------------------------*/
BYTE decode_byte(char *s)
{
  char t[3];
  BYTE i;

  t[0] = s[0];
  t[1] = s[1];
  t[2] = '\0';
  sscanf(t,"%2x",&i);
  return((BYTE)i);
}

/*-------------------------------------------------------------------
|   FUNCTION: decode_hexline(...)
|    PURPOSE: decode INTEL HEX-16 line
| DESRIPTION: -
|    RETURNS: 0=success, <0=failure
|    VERSION: 901213 V0.1
---------------------------------------------------------------------*/
int decode_hexline(char *s, int *length, ADDRESS *address, int *rectype, char *datastr)
{
  char s1[20],s2[20],s3[20];
  char c;

  sscanf(s,"%c%2s%4s%2s%s",&c,s1,s2,s3,datastr);
  if (c!=':') return(-1);
  sscanf(s1,"%x",length);
  sscanf(s2,"%X",address);
  sscanf(s3,"%x",rectype);
  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: clear_mnemonictable()
|    PURPOSE: -
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901215 V0.1
---------------------------------------------------------------------*/
void clear_mnemonictable()
{
  int i;

  for (i=0 ; i<256 ; i++)
  {
    table[i].mnemonic[0] = '\0';
    table[i].no_bytes  = 0;
    table[i].type      = 0;
  }
}

/*-------------------------------------------------------------------
|   FUNCTION: clear_labeltabel()
|    PURPOSE: -
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901215 V0.1
---------------------------------------------------------------------*/
void clear_labeltabel()
{
  int i;

  for (i=0 ; i<MAX_LABELS ; i++)
  {
    labeltabel[i].address = 0;
    labeltabel[i].label[0] = '\0';
    labeltabel[i].type = UNKNOWN;
  }
}

/*-------------------------------------------------------------------
|   FUNCTION: build_mnemonictable()
|    PURPOSE: Build internal mnemonic table
| DESRIPTION: Opens inputfile, reads the table (ASCII) and builds
|             our own table (ordered by operand value).
|    RETURNS: 0        = succesfull
|             OPEN_ERR = file open error
|    VERSION: 901212 V0.1
---------------------------------------------------------------------*/
int build_mnemonictable()
{
  FILE *infile;
  char s[STRLEN],
       mnemonic[20],
       typestr[10],
       c;
  BYTE index;
  int  i,
       no_bytes,
       type;

  infile = fopen("6502dis.tbl","r");
  if (!infile)
  {
    printf("ERROR: couldn't open 6502 table\n");
    exit(OPEN_ERR);
  }

  clear_mnemonictable();

  /*----------------------
  | Build MNEMONIC table
  -----------------------*/
  while (!feof(infile))
  {
    /*--------------------------
    | Read input and get tokens
    ----------------------------*/
    s[0] = '\0';                /* Clear input string             */
    fgets(s,STRLEN,infile);     /* Read entry                     */
    if (!s[0]) break;           /* No input, end of table reached */

    /*----------------------------------------
    | A record of data consists of:
    | 2 char: hex code of opcode
    | 1 space
    | 11 char: mnemonic
    | 1 space
    | 1 digit: #bytes of instruction
    | 5 chars: instruction type
    ----------------------------------------*/
    typestr[0] = '\0';
    sscanf(s,"%2x %11s %1d %5s\n",
      &index,mnemonic,&no_bytes,typestr);
    table[index].no_bytes = no_bytes;
    type = 0;
    i = 0;
    while (typestr[i])
    {
      c = toupper(typestr[i++]);
      switch (c)
      {
        case 'A': type |= ABSOLUTE;  break;
        case 'B': type |= BRANCH;    break;
        case 'C': type |= CMOSCODE;  break;
        case 'J': type |= JUMP;      break;
        case 'Z': type |= ZEROPAGE;  break;
        case '2': type |= VAR2;      break;
      }
    }

    /*---------------------------------------------------------
    | If table entry already occupied, continue with next line
    -----------------------------------------------------------*/
    if (table[index].mnemonic[0])
    {
      printf("ERROR: entry %3d of mnemonic table already occupied\n",index);
      continue;
    }

    /*----------------------------------------------------------
    | If CMOS code, but not wanted then continue with next line
    -----------------------------------------------------------*/
    if ((type & CMOSCODE) && !cmos)
      continue;

    /*------------------------------
    | Store data in mnemonic table
    --------------------------------*/
    strcpy(table[index].mnemonic,mnemonic);
    table[index].no_bytes = no_bytes;
    table[index].type = type;
  }

  fclose(infile);  /* Close table file        */
  return(0);       /* Return successfull      */

}

/*-------------------------------------------------------------------
|   FUNCTION: decode_hexdata(ADDRESS address, ADDRESS length, char *hex_data)
|    PURPOSE: Decode hexadecimal data to objectcode in memory
| DESRIPTION: Decode the data and place it in object-code memory
|             Start at the load loadaddress.
|             The data consists of 'length' bytes in hex-representation
|    RETURNS: 0=success  negative=error
|    VERSION: 901215 V0.1
---------------------------------------------------------------------*/
int decode_hexdata(ADDRESS address, ADDRESS length, char *hex_data)
{
  BYTE code;
  int  i=0;

  do
  {
    if (obj_code[(WORD)address] != '\0')
    {
      printf("ERROR: address %lx already occupied\n",address);
      return(-1);
    }
    code = decode_byte(hex_data+i);
    i += 2;
    obj_code[(WORD)address++] = code;
    length--;
  }
  while (length);

  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: load_objfile()
|    PURPOSE: Read object file (.BIN) from disk
| DESRIPTION: -
|    RETURNS: 0=success, -1=failure
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
load_objfile()
{
  FILE *infile;
  char filename[30];
  long file_length;

  /*--------------------------------------------
  | Allocate memory for object code (only once)
  --------------------------------------------*/
  if (obj_code == NULL)
  {
    obj_code = calloc(OBJ_SIZE,sizeof(BYTE));
    if (!obj_code)
    {
      puts("ERROR: failure in memory allocation for object code");
      exit(ALLOC_ERR);
    }
  }

  /*---------------------------
  | Open BIN file for reading
  ----------------------------*/
  strcpy(filename,basename);
  if (filetype == OBJ)
    strcat(filename,".obj");
  if (filetype == BIN)
    strcat(filename,".bin");

  infile = fopen(filename,"rb");
  if (!infile)
  {
    printf("ERROR: couldn't open file '%s'\n",filename);
    exit(OPEN_ERR);
  }

  fseek(infile,0,SEEK_END);      /* Pointer to end of file   */
  file_length = ftell(infile);   /* Read file pointer        */
  fseek(infile,0,SEEK_SET);      /* Pointer to start of file */
  end_address = fread(obj_code,1,(size_t)file_length,infile);
  load_address += offset;
  end_address += offset;

  fclose(infile);
  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: load_hexfile()
|    PURPOSE: Load hexfile and convert to object code
| DESRIPTION: INTEL-16 HEX (?) file consists of a number of lines:
|             ':NNAAAATTDDDD...DDCC' in which:
|             ':'        = start of line
|             'NN'       = number of databytes
|             'AAAAAA'   = loadaddress of data
|             'TT'       = record type
|             'DDDD..DD' = data
|             'CC'       = 1 byte checksum
|    RETURNS: 0=succes  negative=failure
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
load_hexfile()
{
  FILE *infile;
  char s[80];
  int  length = 0;
  int  rectype;
  char data_str[40];
  char hexfile[30];
  ADDRESS address = 0;

  /*--------------------------------------------
  | Allocate memory for object code (only once)
  --------------------------------------------*/
  if (obj_code == NULL)
  {
    obj_code = calloc(OBJ_SIZE,sizeof(BYTE));
    if (!obj_code)
    {
      puts("ERROR: failure in memory allocation for object code");
      exit(ALLOC_ERR);
    }
  }

  /*---------------------------
  | Open hex file for reading
  ----------------------------*/
  strcpy(hexfile,basename);
  strcat(hexfile,".hex");
  infile = fopen(hexfile,"r");
  if (!infile)
  {
    printf("ERROR: couldn't open file '%s'\n",hexfile);
    exit(OPEN_ERR);
  }

  address = 0;
  while (!feof(infile))
  {
    s[0] = '\0';                     /* Clear string                   */
    fgets(s,STRLEN,infile);          /* Get input line                 */
    if (s[0] != ':') break;          /* End of file reached            */

    decode_hexline(s,&length,&address,&rectype,data_str);
    load_address = min(load_address,address);
    if (address >= OBJ_SIZE)
      offset = OBJ_SIZE;
    if ( (address+length) > end_address)
      end_address = address + length;
    if (rectype != 1)                /* EOF record  */
      decode_hexdata(address-offset,length,data_str);
  }

  fclose(infile);
  return(0);   /* success */
}

/*-------------------------------------------------------------------
|   FUNCTION: add_labeltable(ADDRESS address)
|    PURPOSE: Add 'address' to labeltabel
| DESRIPTION: Finds an empty entry in the labeltabel, puts the label
|             in it and creates a lable (Laddress) in this table.
|             If assembler output is wanted, we number the labels to
|             avoid confusion with addresses.
|    RETURNS: offset in table,
|             -1 if entry already occupied
|             OVERFLOW if table full.
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
int add_labeltable(ADDRESS address)
{
  int i = 0;
  static int label_nr = 1;

  while (i < MAX_LABELS)
  {
    if (labeltabel[i].address == address)  /* Address already in table */
      return(-1);
    if (!labeltabel[i].address)            /* empty record found */
    {
      /*---------------------------------
      | Address not found in table.
      | Generate a label and add
      | address and label to the table
      ---------------------------------*/
      labeltabel[i].address = address;     /* Add address to table */
      if (asm_output)
      {
        sprintf(labeltabel[i].label,"L_%02d",label_nr);
        label_nr++;
      }
      else
        sprintf(labeltabel[i].label,"L%04X",(WORD)address);
      return(0);
    }
    else
     i++;
  }

  printf("ERROR: labeltabel full\n");
  return(OVERFLOW);
}

/*-------------------------------------------------------------------
|   FUNCTION: find_label(ADDRESS address)
|    PURPOSE: Find an address in the labeltabel
| DESRIPTION: -
|    RETURNS: Pointer to the label in the table; if none found it
|             returns pointer to a null-string;
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
char *find_label(ADDRESS address)
{
  int i = 0;
  char *null_str = "";

  while (i < MAX_LABELS)
  {
    if (!labeltabel[i].label[0])
      return(null_str);
    if (address == labeltabel[i].address)
      return(labeltabel[i].label);
    else
      i++;
  }
  return(null_str);
}

/*-------------------------------------------------------------------
|   FUNCTION: get_datatype(ADDRESS address)
|    PURPOSE: -
| DESRIPTION: -
|    RETURNS: datatype (CODE or DATA)
|    VERSION: -
---------------------------------------------------------------------*/
int get_datatype(ADDRESS address)
{
  int i,t;

  i = 0;
  while (i < MAX_LABELS)
  {
    if (!labeltabel[i].label[0])
      return(datatype);
    if (address == labeltabel[i].address)
    {
      t = labeltabel[i].type;
      if (t & (DATA|CODE))
      {
        datatype = t;
        return(datatype);
      }
    }
    i++;
  }
  return(datatype);   /* Return old value if address not found */
}

/*-------------------------------------------------------------------
|   FUNCTION: print_labels(FILE *outfile)
|    PURPOSE: print labels on screen and in disassembly file
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void print_labels(FILE *outfile)
{
  int  i = 0;
  char s[STRLEN];
  char tmpstr[STRLEN];

  /*-------------------
  | Print header line
  --------------------*/
  sprintf(s,"\n\nLABEL TABLE\n");
  printf("%s",s);
  fprintf(outfile,"%s",s);

  /*---------------
  | Print labels
  ---------------*/
  i = 0;
  s[0] = '\0';
  while (TRUE)
  {
    if (i%3 == 0)            /* Force output after 3 labels */
    {
      printf("%s\n",s);
      fprintf(outfile,"%s\n",s);
      s[0] = '\0';                     /* 'Clear' string s  */
    }
    if (labeltabel[i].label[0])         /* Record occupied ? */
    {
      sprintf(tmpstr,"%10s: %04XH  ",
        labeltabel[i].label,(WORD)labeltabel[i].address);
      strcat(s,tmpstr);
      i++;
    }
    else                               /* Empty record      */
    {
      printf("%s\n",s);                /* Force output      */
      fprintf(outfile,"%s\n",s);
      break;                           /* Break from loop   */
    }
  }
}

/*-------------------------------------------------------------------
|   FUNCTION: print_equations()
|    PURPOSE: print user defined labels as equations in outputfile
| DESRIPTION: Labels, generated by this programm will not be equated
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void print_equations(FILE *outfile)
{
  char s[STRLEN];
  char tmpstr[STRLEN];
  int  i=0;

  /*---------------
  | Print labels
  ---------------*/
  while (TRUE)
  {
    if (labeltabel[i].label[0])         /* Record occupied ? */
    {
      strcpy(tmpstr,labeltabel[i].label);
      if (!(asm_output && tmpstr[0] == 'L' && tmpstr[1] == '_'))
      {
        strcat(tmpstr,":");
        sprintf(s,"%-15s  EQU  0%04XH",
          tmpstr,(WORD)labeltabel[i].address & 0xFFFF);
        printf("%s\n",s);
        fprintf(outfile,"%s\n",s);
      }
      i++;
    }
    else                               /* Empty record      */
    {
      printf("\n");
      fprintf(outfile,"\n");
      break;                           /* Break from loop   */
    }
  }
}


/*-------------------------------------------------------------------
|   FUNCTION: build_hexstr(BYTE *code, int n, char *s)
|    PURPOSE: Build hex representation of an array of bytes
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void build_hexstr(BYTE *code, int n)
{
  int  i = 0;
  char t[6];

  hexstr[0] = '\0';
  for (i=0 ; i<n ; i++)
  {
    sprintf(t,"%02X",code[i]);
    strcat(hexstr,t);
  }
}

/*-------------------------------------------------------------------
|   FUNCTION: build_comment(BYTE *code)
|    PURPOSE: Build comment string
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void build_comment(BYTE *code)
{
  int type;
  char *s = "";

  strcpy(comment,";");

  type = table[code[0]].type;
  if (type & ZEROPAGE)              /* Deal with zero page */
    strcat(comment,"ZP ");
  if (type & JUMP)
    strcat(comment,"JUMP ");

  switch (code[0])
  {
    case 0x60: s = "Return SUB ";        break;
    case 0x40: s = "Return Interrupt ";  break;
    case 0x58: s = "Enable IRQ ";        break;
    case 0x78: s = "Disable IRQ ";       break;
    default:   s = "";
  }
  strcat(comment,s);
}

/*-------------------------------------------------------------------
|   FUNCTION: calc_target(ADDRESS load_address)
|    PURPOSE: Calculate target address of JUMP or BRANCH instruction
| DESRIPTION: -
|    RETURNS: Calculated target address
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
ADDRESS calc_target(ADDRESS opcode_address)
{
  int type;
  int instr_len;
  signed char branch_offset;
  ADDRESS target = 0;
  WORD addr;
  BYTE opcode;

  addr = (WORD)(opcode_address - offset);
  opcode = obj_code[(WORD)addr];
  type = table[opcode].type;

  if (type & BRANCH)
  {
    if (type & VAR2)
      branch_offset = obj_code[addr+2];
    else
      branch_offset = obj_code[addr+1];
    instr_len = get_instrlen(opcode);
    target = opcode_address + instr_len + branch_offset;
    return(target&0xFFFF);
  }
  else if (type & JUMP)
  {
    target = obj_code[addr+2]*256+obj_code[addr+1];
    return(target&0xFFFF);
  }
  else
    return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: build_paramstr(ADDRESS opcode_address)
|    PURPOSE: Build parameter string for disassembled instruction
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void build_paramstr(ADDRESS opcode_address)
{
  int  type = 0;         /* instruction type                             */
  char *label;
  int  instr_len = 0;
  char tmpstr[10];
  ADDRESS zp_addr = 0;   /* zero-page address                            */
  ADDRESS target = 0;    /* target address of JUMP or BRANCH instruction */
  BYTE opcode;
  WORD addr;

  addr = (WORD) (opcode_address-offset);
  opcode = obj_code[(WORD)addr];
  type = table[opcode].type;
  instr_len = get_instrlen(opcode);

  /*--------------------------------------------------------
  | Build the parameter string.
  | If the operand consists of 2 bytes, and the
  | addressing mode is ABSOLUTE, then reverse the swap the
  | 2 bytes (of the hexadecimal representation) because the
  | objectcode is in LSB/MSB notation
  ---------------------------------------------------------*/
  sprintf(paramstr,"0%sH",hexstr+2);
  if ( (instr_len == 3) && (type & ABSOLUTE) )
  {
    strcpy(tmpstr,paramstr);
    paramstr[1] = tmpstr[3];
    paramstr[2] = tmpstr[4];
    paramstr[3] = tmpstr[1];
    paramstr[4] = tmpstr[2];
  }

  /*--------------------------------------
  | Deal labeling of zero page addresses.
  -----------------------------------------*/
  if (type & ZEROPAGE)
  {
    zp_addr = obj_code[addr+1];
    label = find_label(zp_addr);
    if (*label)
      strcpy(paramstr,label);
  }

  /*-----------------------------------------------
  | Substitute parameter string by target address
  | in case of BRANCH of JUMP instructions
  ------------------------------------------------*/
  if (type & (BRANCH|JUMP))
  {
    target = calc_target(opcode_address);
    label = find_label(target);
    if (*label)
      strcpy(paramstr,label);     /* Copy label to paramstr */
    else
      sprintf(paramstr,"0%04XH",target);
  }

  /*-----------------------------------------
  | Substitute paramstr by label in case of
  | Absolute, 2 bytes addressing
  ------------------------------------------*/
  if ( (type & ABSOLUTE) && (instr_len == 3) )
  {
    target = obj_code[addr+2]*256+obj_code[addr+1];
    label = find_label(target);
    if (*label)
      strcpy(paramstr,label);
  }

  /*--------------------------------------------------------------
  | Special case: BBRx and BBSx instructions have 2 parameters:
  | parameter 1 : zero-page address
  | parameter 2 : branch offset
  ---------------------------------------------------------------*/
  if (type & VAR2)
  {
    label = find_label(opcode_address); /* Label for 0-page address available ? */
    if (*label)
      sprintf(paramstr,"%s,",label);
    else
      sprintf(paramstr,"0%02XH,");

    target = calc_target(opcode_address);
    label = find_label(target);
    if (*label)
      strcat(paramstr,label);
    else
    {
      sprintf(tmpstr,"0%2X",(signed char)obj_code[addr+2]);
      strcat(paramstr,tmpstr);
    }
  }
}

/*-------------------------------------------------------------------
|   FUNCTION: build_instruction(BYTE opcode)
|    PURPOSE: build instruction from mnemonic and parameter string
| DESRIPTION: Substitute '|' in mnemonic by a space to seperate
|             opcode and variables.
|             Substitute '_' in mnemonic by appropiate parameter string
|    RETURNS: nothing
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
void build_instruction(BYTE opcode)
{
  char tmpstr[STRLEN];
  char mnemonic[STRLEN];
  char *m;

  m = get_mnemonic(opcode);
  strcpy(mnemonic,m);

  memset(tmpstr,'\0',20);
  m = strpbrk(mnemonic,"|");      /* replace '|' by a space */
  if (m)
    *m = ' ';

  m = strpbrk(mnemonic,"_");      /* Replace '_' by parameter string */
  if (m)
  {
    strncpy(tmpstr,mnemonic,(size_t)(m-mnemonic));
    strcat(tmpstr,paramstr);
    strcat(tmpstr,m+1);
    strcpy(instr_str,tmpstr);
  }
  else
    strcpy(instr_str,mnemonic);
}

/*-------------------------------------------------------------------
|   FUNCTION: process_instruction(address);
|    PURPOSE: -
| DESRIPTION: Will only be called during pass 2.
|    RETURNS: next address;
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
ADDRESS process_instruction(ADDRESS opcode_address)
{
  BYTE opcode,
       instr_code[5];
  int  j,
       instr_len;
  ADDRESS addr;

  /*----------------------
  | Get instruction code
  -----------------------*/
  addr = opcode_address - offset;
  datatype = get_datatype(opcode_address);
  if (datatype & CODE)
  {
    opcode = obj_code[(WORD)addr++];
    instr_len = get_instrlen(opcode);
    instr_code[0] = opcode;
    j = 1;
    while (--instr_len > 0)
      instr_code[j++] = obj_code[(WORD)addr++];
    instr_len = j;

    build_hexstr(instr_code,instr_len);
    build_paramstr(opcode_address);
    build_comment(instr_code);
    build_instruction(opcode);

  }
  else   /* datatype = DATA */
  {
    instr_len = 1;
    instr_code[0] = obj_code[(WORD)addr];
    instr_code[1] = '\0';
  }

  return(opcode_address+instr_len);
}

/*-------------------------------------------------------------------
|   FUNCTION: get_addresses(ADDRESS *offset,ADDRESS *start, ADDRESS *stop)
|    PURPOSE: Get start en stop-address of disassembly from user
| DESRIPTION: -
|    RETURNS: Nothing
|    VERSION: 901217 V0.1
---------------------------------------------------------------------*/
void get_addresses(ADDRESS *offset, ADDRESS *start, ADDRESS *stop)
{
  char tmpstr[20];

  if (!offset)
  {
    printf("Offset = <%05lX> ",offset);
    gets(tmpstr);
    if (*tmpstr)
      sscanf(tmpstr,"%X",&offset);
  }

  *start = load_address;
  printf("Start  = <%05lX> ",*start);
  gets(tmpstr);
  if (*tmpstr)
    sscanf(tmpstr,"%X",start);

  *stop = end_address;
  printf("End    = <%05lX> ",*stop);
  gets(tmpstr);
  if (*tmpstr)
    sscanf(tmpstr,"%X",stop);

  *stop = min(*stop,end_address);
  *stop = max(*stop,*start);
}

/*-------------------------------------------------------------------
|   FUNCTION: pass1()
|    PURPOSE: pass 1 of disassembly object code in memory
| DESRIPTION: Main purpose it to get the target_addresses of
|             JUMP and BRANCH instructions.
|    RETURNS: 0=successfull, <0=failure
|    VERSION: 901212 V0.1
---------------------------------------------------------------------*/
int pass1()
{
  ADDRESS address,
          target;
  BYTE    *opcode;
  int     instr_len;

  puts("PASS 1");

  datatype = CODE;                 /* Reset datatype */

  address = start_address;
  while (address < stop_address)
  {
    /*------------------
    | Show we are busy
    -------------------*/
    printf("%05X\b\b\b\b\b",address);   /* CR */

    /*---------------------
    | Process instruction
    ----------------------*/
    datatype = get_datatype(address);
    if (datatype & CODE)
    {
      opcode = obj_code+(WORD)address-(WORD)offset;
      target = calc_target(address);
      if (target)
        add_labeltable(target);
      instr_len = get_instrlen(*opcode);
      address += instr_len;
    }
    else
      address++;
  }
  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: pass2()
|    PURPOSE: pass 2 of disassembling object code in memory
| DESRIPTION: Main function is the output of the disassembled code
|    RETURNS: 0=successfull, <0=failure
|    VERSION: 901217 V0.2
---------------------------------------------------------------------*/
int pass2()
{
  FILE *outfile;
  char filename[30],
       outstr[STRLEN],
       tmpstr[20],
       *label,                     /* Ptr to label in jump table */
       labelstr[20];               /* Copy of label              */
  ADDRESS address = 0,
          opcode_address;
  int  i = 0,
       len = 0;

  puts("PASS 2");

  datatype = CODE;                 /* Reset datatype */

  /*----------------------
  | Open file for output
  -----------------------*/
  strcpy(filename,basename);
  if (asm_output)
    strcat(filename,".asm");
  else
    strcat(filename,".dis");
  outfile = fopen(filename,"w");
  if (!outfile)
  {
    printf("ERROR: couldn't open output '%s'\n",filename);
    exit(OPEN_ERR);
  }

  /*-----------------------------
  | Write ouput header to file
  ------------------------------*/
  if (asm_output)
  {
    fprintf(outfile,"  CPU \"6502.tbl\"\n");
    fprintf(outfile,"  HOF \"INT16\"\n");
    fprintf(outfile,"  ORG 0%04XH\n\n",(WORD)offset);
    print_equations(outfile);
  }
  else
  {
    fprintf(outfile,idstr);
    fprintf(outfile,"\n%6s %-6s %-10s %-20s %-10s\n\n",
      "ADDR","DATA","LABEL","CODE","COMMENT");
  }

  address = start_address;
  while (address < stop_address)
  {
    datatype = get_datatype(address);
    label = find_label(address);
    labelstr[0] = '\0';
    if (*label)
    {
      strcpy(labelstr,label);
      strcat(labelstr,":");
      strcpy(instr_str,"DFB ");     /* Reset instruction string */
      strcpy(hexstr,"");            /* Clear hexstr             */
      i = 0;
    }

    if (datatype & CODE)
    {
      /*---------------------
      | Process instruction
      ----------------------*/
      opcode_address = address;
      address = process_instruction(opcode_address);
    }

    else if (datatype & DATA)
    {
      /*------------------------------------------------------------
      | Build hex_str until
      | (1) 10 bytes processed
      | (2) or datatype becomes CODE again
      | (3) or a new label is encounterd.
      | (4) or address >= stop_address
      -------------------------------------------------------------*/
      while ( (datatype & DATA) && i<8 && address<stop_address)
      {
        if (i == 0)
        {
          opcode_address = address;
          strcpy(instr_str,"DFB ");     /* Reset instruction string */
          strcpy(hexstr,"");            /* Clear hexstr             */
          strcpy(comment,"; ");         /* Reset comment string     */
        }
        sprintf(tmpstr,"0%02XH,",obj_code[(WORD)(address-offset)]);
        strcat(instr_str,tmpstr);
        datatype = get_datatype(address);
        address++;
        i++;
        label = find_label(address);      /* New label ?      */
        if (*label)
          break;                          /*   then exit loop */
      }
      i = 0;
    }

    /*---------------------------------------
    |  Remove last ',' of instruction string
    ----------------------------------------*/
    len = strlen(instr_str);
    if (instr_str[len-1] == ',')
      instr_str[len-1] = '\0';

    /*----------------------------
    | Output of disassembled line
    -----------------------------*/
    if (asm_output)
    {

      sprintf(outstr,"%-10s %-20s %-10s\n",
        labelstr,instr_str,comment);
    }
    else
    {
      sprintf(outstr,"%6lX %-6s %-10s %-20s %-10s\n",
        opcode_address,hexstr,labelstr,instr_str,comment);
    }
    printf(outstr);
    fprintf(outfile,outstr);

  }

  if (!asm_output)
    print_labels(outfile);

  fclose(outfile);
  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: read_labelfile()
|    PURPOSE: Read labelfile and store pre-defined labels in jump table
| DESRIPTION: A record of the label file consists of 3 fields:
|             field 1: label name, closed with a colon (':');
|             field 2: Hexadecimal character representation of address
|             field 3: Label type : CODE or DATA
|             DATA should not be interpreteted.
|             CODE starts interpretation again.
|    RETURNS: 0        = success
|             OPEN_ERR = no file found
|             OVERFLOW = table full
|    VERSION: 901216 V0.1
---------------------------------------------------------------------*/
int read_labelfile()
{
  FILE *infile;
  char filename[30];
  char s[STRLEN];
  char label[15];
  ADDRESS address;
  char typestr[10];
  char *m;
  int  i = 0;

  /*-----------------
  | Open label file
  ------------------*/
  strcpy(filename,basename);
  strcat(filename,".lbl");
  infile = fopen(filename,"r");
  if (!infile)
    return(-1);          /* No label file. Pitty... but no big deal */

  /*----------------------
  | Process label file
  -----------------------*/
  while (!feof(infile))
  {
    s[0] = '\0';                /* Clear input string             */
    fgets(s,STRLEN,infile);     /* Read entry                     */
    if (!s[0]) break;           /* No input, end of table reached */

    typestr[0] = '\0';
    sscanf(s,"%15s %4X %4s\n",label,&address,typestr);
    m = strpbrk(label,":");   /* Replace ':' by a NILL */
    if (m)
      *m = '\0';

    if (i < MAX_LABELS)
    {
      labeltabel[i].address = address;
      strcpy(labeltabel[i].label,label);
      strupr(typestr);
      if (strstr(typestr,"DATA"))
        labeltabel[i].type = DATA;
      if (strstr(typestr,"CODE"))
        labeltabel[i].type = CODE;
      i++;
    }
    else
      return(-2);
  }
  return(0);
}

/*-------------------------------------------------------------------
|   FUNCTION: usage()
|    PURPOSE: print usage of command line and short explenation
| DESRIPTION: -
|    RETURNS: nothing
|    VERSION: 901218 V0.1
---------------------------------------------------------------------*/
void usage()
{
  puts("usage: 6502dis [-ac] file");
  puts("");
  puts("Options:");
  puts(" -a  Output of .asm file (for C16 cross-compiler)");
  puts(" -c  Allow code for 65C02");
  puts("");
  puts("Inputfile can be a binary or an Intel HEX16 file");
  puts("Outputfile of dissambled code: 'basename.dis'");
  puts("Outputfile of assembler code: 'basename.asm'\n");
}

/*------------------------------------------------------------------
|   FUNCTION: main()
|    PURPOSE: main function of this disassembler
| DESRIPTION: -
|    RETURNS: 0=successfull, negative=failure.
|    VERSION: 901212 V0.1
---------------------------------------------------------------------*/
main(int argc, char **argv)
{
  char filename[30];
  char *token;
  char *temp;

  puts(idstr);         /* Print header line */

  /*-------------------------------------------------
  | Check for minimum number of command line options
  ---------------------------------------------------*/
  if (argc < 2)
  {
    usage();
    exit(-1);
  }

  /*---------------------
  | Parse command line
  ----------------------*/
  while (--argc && (*++argv)[0] == '-')
    for (temp=argv[0]+1 ; *temp != '\0' ; temp++)
      switch(toupper(*temp))
      {
        case 'A': asm_output = TRUE; break;
        case 'C': cmos = TRUE; break;
        default : usage(); exit(-1);
      }
  /*--------------------
  | Get inputfile name
  ---------------------*/
  strcpy(filename,*argv);
  strupr(filename);
  if (strstr(filename,".HEX"))
    filetype = HEX;
  else if (strstr(filename,".OBJ"))
    filetype = OBJ;
  else if (strstr(filename,".BIN"))
    filetype = BIN;
  else
  {
    printf("ERROR: wrong file extension: %s\n",argv[1]);
    exit(-1);
  }
  token = strtok(filename,".");
  if (token)
    strcpy(basename,token);

  clear_labeltabel();
  read_labelfile();
  build_mnemonictable();

  /*----------------
  | Load data file
  -----------------*/
  if (filetype == HEX)
    load_hexfile();
  else if (filetype == BIN)
    load_objfile();

  get_addresses(&offset,&start_address,&stop_address);

  /*----------------------------
  | Perform 2-pass disassembly
  -----------------------------*/
  pass1();
  pass2();

  return(0);      /* Successfull end of programm */
}