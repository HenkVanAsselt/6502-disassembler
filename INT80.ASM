






         ;------------------------------------------------;
         ;                                                ;
         ;  Disassembled Interface 80 serial I/O EPROM    ;
         ;  with test on NMEA-0183 identifier             ;
         ;                                                ;
         ;  Disassembled by H.B.J. van Asselt             ;
         ;                  24-12-1990                    ;
         ;                                                ;
         ;------------------------------------------------;






          ;--------------------------------
          ; C16 Crosscompiler instructions
          ;--------------------------------

          CPU  "6502.tbl"
          HOF  "INT16"
          TITL "Interface 80       NMEA-0183 Serial I/O EPROM code"
          PAGE  72

PAGE
;--------------------------------------------------------------------------
; 6551 Communications Interface Adapter (CIA) data       Clock = 1.8432 MHz
;--------------------------------------------------------------------------
; STATUS REGISTER
;
; Bit 7: 1 = Interrupt request given
; Bit 6: 0 = !DSR is low (i.e. Data Set is Ready)
; Bit 5: 0 = !DCD is low (i.e. Data Carrier has been detected)
; Bit 4: 1 = Transmitter Data Register is empty
; Bit 3: 1 = Receiver Data Register is full
; Bit 2: 1 = Overrun Error has occured
; Bit 1: 1 = Framing Error Detected
; Bit 0: 1 = Parity Error Detected
;--------------------------------------------------------------------------
; CONTROL REGISTER
;
; Bit 7:     0 = 1 stopbit;
;            1 = 2 stop bits or
;                1 stop bit if 8 databits + parity (9 bits) or
;                1.5 stop bits if 5 databits and no parity
; Bit 6..5: Word length.  00=8  01=7  10=6  11=5
; Bit 4   : Receiver clock source: 0 = external, 1 = baud rate generator
; Bit 3..0: Baud rate generator
;           0000 = 16x external clock  1000 = 1200
;           0001 = 50                  1001 = 1800
;           0010 = 75                  1010 = 2400
;           0011 = 108.92              1011 = 3600
;           0100 = 134.58              1100 = 4800
;           0101 = 150                 1101 = 7200
;           0110 = 300                 1110 = 9600
;           0111 = 600                 1111 = 19200
;--------------------------------------------------------------------------
; COMMAND REGISTER
;
; Bit 7..5: Parity Check Controls
;           xx0 = Parity Disabled
;           001 = Odd parity tx and rx
;           011 = Even parity tx and rx
;           101 = Mark parity transmitted, no parity check
;           111 = Space parity transmitted, no parity check
; Bit 4:    Normal/Echo mode for receiver
;           0 = normal, 1 = echo (Bits 2 and 3 must be '0')
; Bit 3..2:       Tx IRQ    CTS Level  Transmitter
;           00 =  Disabled  High       Off
;           01 =  Enabled   Low        On
;           10 =  Disabled  Low        On
;           11 =  Disabled  Low        Transmit BRK
; Bit 1:    Receiver Interrupt Enable
;           0 = !IRQ Interrupt enabled from bit 3 of Status Register
;           1 = !IRQ Interrupt disabled
; Bit 0:    Data Terminal Ready
;           0 = Disable receiver and all interrupts (!DTR high)
;           1 = Enable receiver and all interrupts (!DTR low)
;---------------------------------------------------------------------------

PAGE
;---------------------------
; 6551 UART ADDRESSES
;---------------------------
UART_data:       EQU  00800H
UART_status:     EQU  00801H
UART_cmd:        EQU  00802H
UART_cntrl:      EQU  00803H

;---------------------------
; ZERO PAGE ADDRESSES
;---------------------------
switch3:         EQU  01H    ; Switch 3 settings
switch2:         EQU  02H    ; Switch 2 settings
outterm_flag:    EQU  03H    ; Terminator found while copying output buffer
outptr:          EQU  04H    ; Pointer to ??? output buffer
modinbuf_ptr:    EQU  05H    ; Pointer to module's input buffer
term_count:      EQU  06H    ; Terminating count value
term_char:       EQU  07H    ; Terminating character
term_mode:       EQU  08H    ; Terminating mode
ms_cntr_H:       EQU  0BH    ; millisecond counter
ms_cntr_L:       EQU  0CH    ; "
interm_flag:     EQU  0DH    ; Input terminator flag
tmout_cntr_H:    EQU  0EH    ; time out counter
tmout_cntr_L:    EQU  0FH    ; "
tmout_5char_H:   EQU  10H    ; 5 char timeout value
tmout_5char_L:   EQU  11H    ; "
ms_val_L:        EQU  12H    ; Millisecond value
ms_val_H:        EQU  13H    ; "
sec99_flag:      EQU  15H    ; 99 seconds past last input flag.
time_ptr:        EQU  16H    ; Points past last char of datastring (for time insertion)
tmp1:            EQU  17H    ; Temporary data
id_ptr:          EQU  20H    ; Pointer to identifier string
match_flag:      EQU  21H    ; Identifier match flag

;----------------------------
; BUFFER ADDRESSES
;----------------------------
modin_buf:       EQU  200H   ; Module input buffer         (module only)
modout_buf:      EQU  280H   ; Module output buffer        (module only)
cntrl_inbuf:     EQU  300H   ; Shared memory input buffer  (module --> CNTRL)
cntrl_outbuf:    EQU  380H   ; Shared memory output buffer (CNTRL --> module)

;---------------------------
; 6522 VIA ADDRESSES
;---------------------------
VIA_IORB:        EQU  00400H
VIA_IORA:        EQU  00401H
VIA_DDRB:        EQU  00402H
VIA_DDRA:        EQU  00403H
VIA_T1_CL:       EQU  00404H
VIA_T1_CH:       EQU  00405H
VIA_T1_LL:       EQU  00406H
VIA_T1_LH:       EQU  00407H
VIA_T2_CL:       EQU  00408H
VIA_T2_CH:       EQU  00409H
VIA_SR:          EQU  0040AH
VIA_ACR:         EQU  0040BH
VIA_PCR:         EQU  0040CH
VIA_IFR:         EQU  0040DH
VIA_IER:         EQU  0040EH
VIA_IORA2:       EQU  0040FH

;---------------------------
; VECTOR ADDRESSES
;---------------------------
NMI_addr:        EQU  0FFFAH    ; Non Maskeble Interrupt vector
RES_addr:        EQU  0FFFCH    ; Reset Vector
IRQ_addr:        EQU  0FFFEH    ; IRQ Vector

;---------------------------
; CONSTANTS
;---------------------------
CR:              EQU  0DH       ; Carriage Return
LF:              EQU  0AH       ; Line Feed
MAX_CHAR:        EQU  7AH       ; 7Fh characters in buffer, minus "mmmm*"


PAGE

           ;**************************************
           ;
           ;   START OF PROGRAM
           ;
           ;**************************************

           ORG 0F800H

start:     CLD                  ;Clear Decimal Flag
           LDX #0FFH            ;X = FFh
           TXS                  ;X-->Stackpointer
           SEI                  ;Disable IRQ

           ;--------------------------
           ; Get switch settings
           ;--------------------------
           LDA #0               ;A = 0
           STA VIA_DDRA         ;VIA Port A is input
           LDA #0               ;A = 0
           STA VIA_DDRB         ;VIA Port B is input
           LDA VIA_IORA         ;Determine switch 2 settings
           STA Switch2          ;Store switch 2 settings
           LDA VIA_IORB         ;Determine switch 3 settings
           STA Switch3          ;Store switch 3 setting
           LDA UART_status      ;Get UART status
           STA 000H             ;Store UART status

           ;---------------------------------
           ; Interpretate the switch settings
           ;----------------------------------
restart:   LDA Switch2          ;Load switch 2 settings
           AND #08FH            ;Mask bit 7 (no_stopbits) and 3..0 (baudrate)
           ORA #010H            ;Set bit 4
           TAX                  ;Save A in X
           LDA Switch3          ;Load copy of switch 3 settings
           AND #040H            ;Mask bit 6 (word length)
           BEQ L_01             ;Bit 6 == 0 ? (8 databits ?) Yes --> goto L_01
           TXA                  ;Restore A from X
           ORA #020H            ;Set bit 5 of A
           TAX                  ;Save A in X
L_01:      STX UART_cntrl       ;Load UART control register with X
           STX 009H             ;Save copy in $09h (is never used again)
           LDA Switch2          ;Load switch 2 settings
           AND #070H            ;Mask bit 6..4 (parity mode)
           ASLA                 ;A *= 2
           ORA #00BH            ;Set bit 7, 5 and 4
           STA UART_cmd         ;Load UART command register with A
           STA 00AH             ;RAM[0Ah] = UART command register

           ;-------------------------------------------------
           ; Initialize input termination condition
           ;-------------------------------------------------
           LDA #0FFH            ;Preset terminating character
           STA term_char        ; to FFh
           LDA #MAX_CHAR        ;Preset terminating character counter
           STA term_count       ; to 122.
           LDA Switch3          ;Load copy of switch 3 settings.
           TAX                  ;X = A
           AND #080H            ;Mask Terminating mode
           STA term_mode        ;Store mode in term_mode
           TXA                  ;A = X
           AND #03FH            ;Mask upper 6 bits of count/char
           ASLA                 ;Shift to left (to get bit 0 later on)
           TAX                  ;X = A
           LDA 000H             ;Load copy of UART status register
           AND #040H            ;Mask lower bit of count/char (DSR of UART)
           BEQ L_02             ;Bit 6 == 0 ? Yes --> goto L_02
           TXA                  ;A = X (count/char)
           ORA #1               ;Set bit 1 of count/char
           TAX                  ;X = A
L_02:      LDA term_mode        ;Get terminating mode
           BEQ L_03             ;Term mode = 0 (term. char) ? --> goto L03
           CPX #MAX_CHAR        ;X < MAX_CHAR ?
           BCC L_04             ;  Yes --> goto L_04
           LDX #MAX_CHAR        ;No, X = MAX_CHAR
L_04:      STX term_count       ;Terminating counter = X
           JMP init_var         ;Skip next instruction
L_03:      STX term_char        ;Terminating character = X

PAGE
           ;------------------------------------------------
           ; Initialize several memory locations on page 0
           ;------------------------------------------------
init_var:  LDA #0               ;A = 0
           STA outterm_flag     ;outterm_flag = 0
           STA interm_flag      ;interm_flag = 0
           STA ms_cntr_L        ;Millisecond counter = 0
           STA ms_cntr_H        ;"
           STA ms_val_L         ;Millisecond value = 0
           STA ms_val_H         ;"
           STA 014H             ;
           STA sec99_flag       ;sec99_flag = 0
           STA time_ptr         ;
           STA tmout_cntr_H     ;
           STA tmout_cntr_L     ;
           LDA #1               ;A = 1
           STA outptr           ;outptr = 1
           STA modinbuf_ptr     ;modinbuf_ptr = 1

           ;------------------------------------
           ; Disable all interrupts of VIA chip
           ;------------------------------------
           LDA #07FH            ;
           STA VIA_IER          ;

           ;------------------------------------------------
           ; Set Aid Control Register of VIA chip
           ; ACR = 01000000b
           ; i.e.  bit 0..1 No latch on port A and B
           ;       bit 2..4 Shift register disabled
           ;       bit 5    T2 timer interrupts continously
           ;       bit 6..7 T1 timer interrupts continously
           ;------------------------------------------------
           LDA #040H            ;
           STA VIA_ACR          ;

           ;----------------------------------------------------
           ; Initialize clock 1 on VIA chip  with 03E8h = 1000d
           ; Clock input is 1 MHz, so timer will set each
           ; 1000 x 1 us = 1 ms it's interrupt flag.
           ; Each interrupt will increment a counter to provide
           ; for the 10 sec overall time-out to write '!'
           ; instead of data.
           ;----------------------------------------------------
           LDA #0E8H            ; Load T1 counter with 1000d
           STA VIA_T1_CL        ;
           LDA #003H            ;
           STA VIA_T1_CH        ;

           ;--------------------------------------------------
           ; Get baudrate code from UART control register,
           ; convert it to a WORD offset, and get 2-byte
           ; counter value from table0.
           ; This will create a 5 character timeout to detect
           ; a gap between data blocks and provide initial
           ; synchronisation when timer is set to the
           ; character count mode.
           ;--------------------------------------------------
           LDA UART_cntrl       ;Get UART control register
           AND #00FH            ;Mask baudate code
           ASLA                 ;A = A * 2 (make WORD offset)
           TAX                  ;X = A
           LDA table0,X         ;Get 5-char timeout value from table0
           STA tmout_5char_H    ;"
           INX                  ;"
           LDA table0,X         ;"
           STA tmout_5char_L    ;"

           PAGE
           ;----------------------------------------
           ;
           ;----------------------------------------
           LDA term_count       ;A = terminating count value
           CMP #MAX_CHAR        ;A == MAX_CHAR ?
           BNE L_06             ; No, goto L_06
           LDA #0FFH            ;tmout_5char_H = -1
           STA tmout_5char_H    ;"
L_06:      LDA term_count       ;A = terminating count value
           LDX #MAX_CHAR        ;X = MAX_CHAR
           CMP #MAX_CHAR        ;A == MAX_CHAR ?
           BEQ L_07             ;  Yes --> goto L_07
           TAX                  ;X = A

           ;--------------------------------------
           ; Write "-!!!!*" to cntrl_inbuf string
           ; (buffer from module to controller)
           ;--------------------------------------
L_07:      LDA #02DH            ;*cntrl_inbuf = '-' (Stale data)
           STA cntrl_inbuf      ;"
           LDA #021H            ;A = '!'
           LDY #1               ;Y = 1
           INX                  ;pointer X += 4
           INX                  ;"
           INX                  ;"
           INX                  ;"
L_09:      STA cntrl_inbuf,Y    ;*(cntrl_inbuf+Y) = '!'
           INY                  ;Y++
           DEX                  ;X--
           BEQ L_08             ;X = 0 ? Yes --> goto L_08 (end of loop)
           JMP L_09             ;No --> loop


L_08:      LDA #02AH            ;A = '*'
           STA cntrl_inbuf,Y    ;*(cntrl_inbuf+Y) = '*' (write terminator)
L_34:      LDA #02AH            ;Last char of cntrl_inbuf becomes '*'
           STA cntrl_inbuf+7FH  ;"
           LDA term_count       ;A = terminating count value
           CMP #MAX_CHAR        ;A == MAX_CHAR ?
           BNE test_T1          ; No, test timer 1
           LDA #0               ;Reset time out counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"
           STA interm_flag      ;interm_flag = 0

           ;--------------------------------------------------------
           ; Test VIA Timer 1 and increment 2-byte time-out counter
           ; if another millisecond has passed
           ; Also increment RAM[14h]
           ;--------------------------------------------------------
test_T1:   LDA VIA_IFR          ;Get VIA Interrupt Flag Register
           STA VIA_IFR          ;  and write data back in IFR
           AND #040H            ;Mask bit 6 (Time out T1)
           BEQ L_11             ;Bit 6 was 0 --> no time out --> goto L_11
           LDA tmout_cntr_L     ;Increment 2-byte time out counter.
           CLC                  ;"
           ADC #1               ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #0               ;"
           STA tmout_cntr_H     ;"
           INC 014H             ;RAM[14h]++

           CMP tmout_5char_H    ;tmout_5char_H = tmout_cntr_H ?
           BNE L_11             ;  No --> goto L_11
           LDA tmout_cntr_L     ;Get LSB of time out counter
           CMP tmout_5char_L    ;tmout_cntr_L == tmout_5char_L ?
           BNE L_11             ; No --> goto L_11
           LDA #1               ;modinbuf_ptr = 1
           STA modinbuf_ptr     ;"
           LDA #0               ;Reset 2-byte time out counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"

L_11:      LDA 014H             ;A = RAM[14h]
           CMP #00AH            ;A < 10 ?
           BCC L_12             ;Yes, goto L_12
           SBC #00AH            ;A = A - 10 - 1
           STA 014H             ;RAM[14h] = A

           PAGE
           ;----------------------------------------------------
           ; Increment 2-byte (0Bh,0Ch) counter in decimal mode
           ;----------------------------------------------------
           LDA ms_cntr_L        ;
           SED                  ;Decimal mode
           CLC                  ;Clear Carry
           ADC #1               ;Increment ms_cntr_L
           STA ms_cntr_L        ;"
           LDA ms_cntr_H        ;and increment ms_cntr_H if Carry set
           ADC #0               ;"
           STA ms_cntr_H        ;"

           ;----------------------------------------------------------
           ; Increment 2-byte BCD millisecond value in decimal mode
           ;----------------------------------------------------------
           LDA ms_val_L         ;ms_val_L++
           CLC                  ;"
           ADC #1               ;"
           STA ms_val_L         ;"
           LDA ms_val_H         ;If Carry set then ms_val_H++
           ADC #0               ;"
           STA ms_val_H         ;"
           CLD                  ;Leave decimal mode

           ;-----------------------------------
           ;
           ;-----------------------------------
           LDX sec99_flag       ;Sec99_flag != 0 ?
           BNE L_12             ; Yes, goto L_12
           LDX time_ptr         ; No, X = time_ptr
           BEQ L_12             ;X = 0 ? Yes, goto L_12
           CMP #099H            ;A == 99h ?
           BNE L_13             ; No, goto L_13
           JMP L_14             ;Yes, goto L_14
L_13:      CPX #07CH            ;X > 124d
           BCS L_12             ;  Yes, goto L_12
           JMP ms_char2         ;  No, Convert BCD milliseconds to char's
L_12:      JMP L_16             ;goto L_16

           PAGE
           ;----------------------------------------------------
           ; Convert 2-byte BCD millisecond value to 4 characters
           ; Place these characters in cntrl_inbuf string
           ; Accu contains value of ms_val_H
           ;-----------------------------------------------------
ms_char2:  TAY                  ;Y = A (save value in Y)
           AND #0F0H            ;Mask 1st nibble
           LSR A                ;Shift 1st nibble to 2nd nibble
           LSR A                ;"
           LSR A                ;"
           LSR A                ;"
           ORA #030H            ;Convert value to character
           STA cntrl_inbuf,X    ;Place it in the string
           JSR sub1             ;Wait some time to make access
           JSR sub1             ;  to shared memory possible
           JSR sub1
           JSR sub1
           NOP
           NOP
           NOP
           NOP
           INX                  ;X++  increment string pointer
           TYA                  ;A = Y (restore value from Y)
           AND #00FH            ;mask 2nd nibble
           ORA #030H            ;Convert value to character
           STA cntrl_inbuf,X    ;Place character in string
           JSR sub1             ;Wait some time to make access
           JSR sub1             ;  to shared memory possible
           JSR sub1
           NOP
           NOP
           NOP
           JMP L_17             ;goto L_17
L_17:      INX                  ;X++; increment string pointer
           LDA ms_val_L         ;A = ms_val_L
           TAY                  ;Y = A (save value in Y)
           AND #0F0H            ;Mask 1st nibble
           LSR A                ;Shift 1st nibble to 2nd nibble
           LSR A                ;"
           LSR A                ;"
           LSR A                ;"
           ORA #030H            ;Convert value to character
           STA cntrl_inbuf,X    ;Place character in string
           JSR sub1             ;Wait some time to make access to
           JSR sub1             ;  shared memory possible
           JSR sub1
           JSR sub1
           NOP
           NOP
           NOP
           NOP
           INX                  ;X++
           TYA                  ;A = Y (restore value from Y)
           AND #00FH            ;Mask 2nd nibble
           ORA #030H            ;Convert value to character
           STA cntrl_inbuf,X    ;Place character in string
           JSR sub1             ;Wait some time to make access to
           JSR sub1             ;  shared memory possible.
           JSR sub1
           JSR sub1
           JSR sub1
           INX                  ;X++ ; increment pointer
           LDA #02AH            ;A = '*'
           STA cntrl_inbuf,X    ;*(cntrl_inbuf+X) = '*'
           JMP L_16             ;Goto L_16

           ;-----------------------------------------
           ; Add 4 '!' to end of cntrl_inbuf string
           ; This indicates that detection of the first
           ; character in the message was more than
           ; 99.00 sec ago.
           ; Set flag to indicate this.
           ;-----------------------------------------
L_14:      LDA #021H            ;A = '!'
           STA sec99_flag       ;Set sec99_flag
           LDY #0               ;Y = 0
           LDX time_ptr         ;X = time_ptr
L_19:      STA cntrl_inbuf,X    ;*(cntrl_inbuf+X) = A
           INX                  ;X++
           JSR sub1             ;Wait some time to make access to
           JSR sub1             ;  shared memory possible.
           JSR sub1
           JSR sub1
           NOP
           NOP
           JMP L_18             ;Goto L_18
L_18:      INY                  ;Y++
           CPY #004H            ;Y == 4 ?
           BNE L_19             ;  No --> goto L_19

           ;----------------------------------
           ;
           ;----------------------------------
L_16:      LDA outterm_flag     ;Outterm_flag set ?
           BNE L_20             ; Yes, goto L_20
           JMP test_rx2         ;No, get and test character from UART

           ;----------------------------------
           ;
           ;----------------------------------
L_20:      LDA outptr           ;A = outptr
           TAX                  ;X = A
           TAY                  ;Y = A
           INY                  ;Y++
           LDA modout_buf,X     ;A = *(modout_buf+X)
           CMP #02AH            ;A == '*' ?
           BNE L_22             ;  No --> goto L_22:
           JMP reset_outvars    ; Yes, reset output variables
L_22:      LDA UART_status      ;Get actual status from UART
           AND #010H            ;Mask Transmitter Data Register Empty flag
           BNE L_24             ;TX Data Register empty? Yes, goto L_24
           JMP test_rx2         ;No, goto test_rx2:

           ;--------------------------------------
           ; Check if output message contains '<^'
           ; If so, replace these by CR and LF
           ;--------------------------------------
L_24:      LDA modout_buf,X     ;A = *(modout_buf+Y)
           CMP #03CH            ;A == '<' ?
           BNE test_override    ;  No, test if override command
           LDA modout_buf,Y     ;A = *(modout_buf+X)
           CMP #05EH            ;A == '^' ?
           BNE test_override    ;  No, test if override command
           LDA #CR              ;Yes, A = CR
           STA modout_buf,X     ;*(modout_buf+X) = CR
           LDA #LF              ;A = LF
           STA modout_buf,Y     ;  *(modout_buf+Y) = LF

           PAGE
           ;-----------------------------------------------------
           ; Test outputstring on Override Command '^^'
           ; This command data has format "Dn+^^JKLMN", Where:
           ;   n = module select code (1-8) as set by switch S1
           ;   JKLMN are override values for switches S2 and S3
           ;   J (0..1) Overrides SW3 position 9
           ;   K (0..F) Overrides SW3 positions 8..5
           ;   L (0..F) Overrides SW3 positions 4..1
           ;   M (0..F) Overrides SW2 positions 8..5
           ;   N (0..F) Overrides SW2 positions 4..1
           ;-----------------------------------------------------
test_override:
           CPX #1               ;X == 1 ?
           BNE char_out         ;  No, send char to UART
           CMP #05EH            ;A == '^' ?
           BNE char_out         ;  No, send char to UART
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           CMP #05EH            ;A == '^' ?
           BNE char_out         ;  No, end char to UART

           ;---------------------------------
           ; Get J and perform override SW3/9
           ;----------------------------------
           INY                  ;Y++
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           ASLA                 ;Shift bit in correct position
           ASLA                 ;"
           ASLA                 ;"
           ASLA                 ;"
           ASLA                 ;"
           ASLA                 ;"
           STA 000H             ;RAM[00h] = A

           ;-------------------------------------
           ; Get K and perform override SW3/8..5
           ;-------------------------------------
           CLD                  ;Clear Decimal Flag
           INY                  ;Y++
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           SEC                  ;Set Decimal Flag
           SBC #030H            ;A = A - '0' (Now in range 0...15)
           TAX                  ;X = A
           LDA table2,X         ;Get data from table2
           STA tmp1             ;Save data in tmp1

           ;------------------------------------
           ; Get L and perform override SW3/4..1
           ;-------------------------------------
           INY                  ;Y++
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           SEC                  ;Set Decimal Flag
           SBC #030H            ;A = A - '0' (Now in range 0...15)
           TAX                  ;X = A
           LDA table1,X         ;Get data from table1
           ORA tmp1             ;A |= tmp1
           STA Switch3          ;Switch3 = A

           ;------------------------------------
           ; Get M and perform override SW2/8..5
           ;-------------------------------------
           INY                  ;Y++
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           SEC                  ;Set Decimal Flag
           SBC #030H            ;A = A - '0' (Now in range 0...15)
           TAX                  ;X = A
           LDA table2,X         ;Get data from table2
           STA tmp1             ;Save data in tmp1

           ;-------------------------------------
           ; Get N and perform override SW2/4..1
           ;-------------------------------------
           INY                  ;Y++
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           SEC                  ;Set Decimal Flag
           SBC #030H            ;A = A - '0' (Now in range 0...15)
           TAX                  ;X = A
           LDA table1,X         ;Get data from table1
           ORA tmp1             ;A |= tmp1
           STA Switch2          ;Switch2 = A
           JMP restart          ;Restart program with override values

           ;-------------------------------------------
           ; Send character from output string to UART
           ;-------------------------------------------
char_out:  LDA modout_buf,X     ;A = *(modout_buf+X)
           STA UART_data        ;Send data to UART for output
           INC outptr           ;outptr++
           JMP test_rx2         ;Goto test_rx2

           ;----------------------------------------
           ; Reset output variables
           ;----------------------------------------
reset_outvars:
           LDA #0               ;outterm_flag = 0
           STA outterm_flag     ;"
           LDA #1               ;outptr = 1
           STA outptr           ;"

           PAGE
           ;------------------------------------
           ; Test if UART has data available
           ;------------------------------------
test_rx2:  LDA UART_status      ;Get UART status
           AND #008H            ;Receiver Data Register Full ?
           BNE L_28             ;  Yes --> goto L_28
           JMP no_char1         ;  No --> goto no_char1

           ;-------------------------
           ; UART has received data
           ;-------------------------
L_28:      JMP getchar1         ;Get char and test ID match (if needed)
got_char1: NOP                  ;
           CMP #CR              ;A == CR ?
           BEQ L_30             ;  Yes, goto L_30
           CMP #LF              ;A == LF ?
           BNE L_31             ;  No, goto L_31
L_30:      LDA #027H            ;Replace CR or LF by '\''
L_31:      TAX                  ;X = A (store char)
           LDA #0               ;Reset 2-byte timeout counter
           STA tmout_cntr_H     ;"
           STA tmout_cntr_L     ;"
           STA sec99_flag       ;sec99_flag = 0
           LDA modinbuf_ptr     ;modinbuf_ptr == 1 ?
           CMP #1               ;"
           BNE L_32             ;  No, goto L_32
           LDA #0               ;  Yes, reset variables:
           STA ms_cntr_L        ;ms_cntr_L = 0
           STA ms_cntr_H        ;ms_cntr_H = 0
           STA 014H             ;RAM[14h] = 0

L_32:      TXA                  ;A = X (restore char)
           LDX modinbuf_ptr     ;X = pointer to module's input buffer
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++
           STX modinbuf_ptr     ;modinbuf_ptr = X
           LDA #02AH            ;Place a '*'
           STA modin_buf,X      ;  behind last character of input_str
           DEX                  ;X--
           CPX term_count       ;X == terminating count value ?
           BEQ eos2             ; Yes, goto eos2
           CPY term_char        ;Y == terminating character ?
           BEQ eos2             ; Yes, goto eos2
           JMP L_34             ;No termination condition, goto L_34

           ;------------------------------------------------------
           ; String terminator has been found:
           ; 1) Terminating character or
           ; 2) Specified number of characters read.
           ; Actions:
           ; 1) Reset millisecond value to start of THIS message
           ; 2) Set time_ptr on char after last message byte
           ;------------------------------------------------------
eos2:      LDA ms_cntr_L        ;ms_val_L = ms_cntr_L
           STA ms_val_l         ;"
           LDA ms_cntr_H        ;ms_val_H = ms_cntr_H
           STA ms_val_H         ;"
           LDX modinbuf_ptr     ;time_ptr = modinbuf_ptr
           STX time_ptr         ;"

           PAGE
           ;------------------------------------------------------
           ; Convert 2-byte BCD millisecond value to 4 characters
           ; and place these characters in modin_buf string
           ;------------------------------------------------------
ms_char1:  LDX time_ptr         ;Get time_ptr
           LDA ms_val_H         ;Get data
           TAY                  ;Y = A (save data in Y)
           AND #0F0H            ;Mask 1st nibble
           LSR A                ;Shift 1st nibble to 2nd nibble
           LSR A                ;"
           LSR A                ;"
           LSR A                ;"
           ORA #030H            ;Convert value to character
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++
           TYA                  ;A = Y (restore data from Y)
           AND #00FH            ;Mask 2nd nibble
           ORA #030H            ;Convert value to character
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++
           LDA ms_val_L         ;A = ms_val_L
           TAY                  ;Y = A (save data in Y)
           AND #0F0H            ;Mask 1st nibble
           LSR A                ;Shift 1st nibble to 2nd nibble
           LSR A                ;"
           LSR A                ;"
           LSR A                ;"
           ORA #030H            ;Convert value to character
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++
           TYA                  ;A = Y (restore data from Y)
           AND #00FH            ;Mask 2nd nibble
           ORA #030H            ;Convert value to character
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++


           ;---------------------------
           ;
           ;---------------------------
           LDA #02AH            ;A = '*'
           STA modin_buf,X      ;*(modin_buf+X) = '*'
           LDA #1               ;modinbuf_ptr = 1
           STA modinbuf_ptr     ;"
           LDA #02BH            ;*modin_buf = '+' (Indicate 'FRESH data')
           STA modin_buf        ;"
           LDX #0               ;X = 0

           ;----------------------------------------------
           ; Copy character from module's input buffer
           ; to input buffer TO controller
           ;----------------------------------------------
L_39:      LDA modin_buf,X      ;A = *(modin_buf+X)
           TAY                  ;Y = A
           STA cntrl_inbuf,X    ;*(cntrl_inbuf+X) = A

           ;--------------------------------------------------------
           ; Test VIA Timer 1 and increment 2-byte time-out counter
           ; if another millisecond has passed
           ; Also increment RAM[14h]
           ;--------------------------------------------------------
           LDA VIA_IFR          ;Get VIA interrupt flag register
           STA VIA_IFR          ;  and write data back to IFR
           AND #040H            ;Mask timeout T1 flag
           BEQ L_35             ;If flag not set then goto L_35 else
           LDA tmout_cntr_L     ;Increment 2-byte timeout counter
           CLC                  ;"
           ADC #1               ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #0               ;"
           STA tmout_cntr_H     ;"
           INC 014H             ;RAM[14h]++
           JMP L_36             ;Goto L_36

           ;---------------------------------------
           ; Some code which seems purposeless...
           ;---------------------------------------
L_35:      JSR sub1             ;sub1()
           NOP                  ;
           NOP                  ;
           NOP                  ;
           NOP                  ;
           NOP                  ;
           JMP L_36             ;goto L_36
L_36:      JMP L_37             ;goto L_37
L_37:      NOP                  ;
           NOP                  ;
           NOP                  ;
           INX                  ;X++
           CPX #07FH            ;X == 7Fh ? (max buf ptr)
           BEQ L_38             ;  Yes, goto L_38
           CPY #02AH            ;Y == '*' ?
           BNE L_39             ;  No, goto L_39
L_38:      LDY interm_flag      ;interm_flag = 0 ?
           BEQ L_40             ; Yes, goto L_40 (fresh data from controller)
           LDA #0               ; No, reset interm_flag to 0
           STA interm_flag      ; "
           LDA cntrl_outbuf     ;Get 1st char from buffer FROM controller
           CMP #02DH            ;char == '-' ?  (Stale data ?)
           BNE L_40             ; No, goto L_40
           JMP L_41             ; Yes, goto L_41
L_40:      JMP L_34             ;Goto L_34

           ;------------------------------------------------------
           ; We got no message character from UART.
           ; Test if FRESH datastring from controller has arrived
           ;------------------------------------------------------
no_char1:  LDA cntrl_outbuf     ;char = *cntrl_outbuf (buffer FROM controller)
           CMP #02BH            ;char == '+' ? (Fresh data ?)
           BEQ L_42             ; Yes, goto L_42
           JMP L_34             ; No, goto L_34

           ;-------------------------------------------------
           ; FRESH data has been arrived from the controller
           ; Change '+' flag at beginning of string to '-'
           ;-------------------------------------------------
L_42:      LDA #02DH            ;*cntrl_outbuf = '-' (Stale data)
           STA cntrl_outbuf     ;"
           LDY #0               ;Y = 0   Point to start of controller string

L_51:      INY                  ;Y++

           ;--------------------------------------------------------
           ; Test VIA Timer 1 and increment 2-byte time-out counter
           ; if another millisecond has passed
           ; Also increment RAM[14h]
           ;--------------------------------------------------------
           LDA VIA_IFR          ;Get VIA Interrupt Flag Register
           STA VIA_IFR          ;  and write data back to it.
           AND #040H            ;Mask bit 6 (Time out T1)
           BEQ test_rx1         ;T1 Time out ? Yes, goto test_rx1
           LDA tmout_cntr_L     ;No, increment 2-bytes timeout counter
           CLC                  ;"
           ADC #1               ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #0               ;"
           STA tmout_cntr_H     ;"
           INC 014H             ;RAM[14h]++

           CMP tmout_5char_H    ;tmout_5char_H = tmout_cntr_H ?
           BNE test_rx1         ; No, test if UART has a char available
           LDA tmout_cntr_L     ;Get LSB of timeout counter
           CMP tmout_5char_L    ;tmout_5char_L == tmout_cntr_L ?
           BNE test_rx1         ;  No, test if UART has a char available

           ;--------------------------------------
           ; We have had a 5 character data gap.
           ; Reset buffer input pointer to 1
           ; Reset timeout counter
           ;--------------------------------------
           LDA #1               ;modinbuf_ptr = 1
           STA modinbuf_ptr     ;"
           LDA #0               ;Reset 2-byte timeout counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"

           PAGE
           ;-----------------------------
           ; Test if UART received data.
           ;-----------------------------
test_rx1:  LDA UART_status      ;Get UART status
           AND #008H            ;Receiver Data Register Full ?
           BEQ no_char2         ;  No, goto no_char2

           ;-------------------------------
           ; UART has data available
           ;-------------------------------
           JMP getchar2         ;Get char and perform test on identifier
got_char2: NOP                  ;NOP (char in A and in Y)
           CMP #CR              ;A == CR ?
           BEQ L_45             ; Yes, goto L_45
           CMP #LF              ;A == LF ?
           BNE L_46             ; No, goto L_46
L_45:      LDA #027H            ;Replace CR or LF by '\''
L_46:      STA tmp1             ;Save char in tmp1
           LDA #0               ;Reset 2-byte timeout counter
           STA tmout_cntr_H     ;"
           STA tmout_cntr_L     ;"
           STA sec99_flag       ;sec99_flag = 0
           LDX modinbuf_ptr     ;X = modinbuf_ptr
           CPX #1               ;modinbuf_ptr == 1 ?
           BNE L_47             ; No, goto L_47
           LDX #0               ;Reset 2-byte value
           STX ms_cntr_L        ;"
           STX ms_cntr_H        ;"
L_47:      LDX modinbuf_ptr     ;X = modinbuf_ptr
           LDA tmp1             ;Retrieve char from tmp1
           STA modin_buf,X      ;*(modin_buf+X) = char
           INC modinbuf_ptr     ;modinbuf_ptr++
           CPX term_count       ;X == terminating counter value ?
           BEQ eos1             ; Yes, goto eos1
           CPY term_char        ;Y == terminating character ?
           BEQ eos1             ; Yes, goto eos1
           JMP no_char2         ;No termination condition, goto no_char2

           ;------------------------------------------------------
           ; String terminator has been found:
           ; 1) Terminating character or
           ; 2) Specified number of characters read.
           ; Actions:
           ; 1) Reset millisecond value to start of THIS message
           ; 2) Set time_ptr on char after last message byte
           ; 3) Reset module's input pointer to 1.
           ; 4) Set interm_flag by copying char from UART to it
           ;------------------------------------------------------
eos1:      LDA modinbuf_ptr     ;time_ptr = modinbuf_ptr
           STA time_ptr         ;"
           LDA #1               ;modinbuf_ptr = 1
           STA modinbuf_ptr     ;"
           LDA ms_cntr_L        ;ms_val_L = ms_cntr_L
           STA ms_val_L         ;"
           LDA ms_cntr_H        ;ms_val_H = ms_cntr_H
           STA ms_val_H         ;"
           STY interm_flag      ;interm_flag = Y (= char from UART)
           JMP ms_char1         ;Convert BCD milliseconds to 4 char's.

           ;----------------------------------------------------
           ; We got no message character from UART.
           ; 1) Get and copy char from buffer FROM controller
           ;    to module's output buffer,
           ; 2) Test on terminating '*'.
           ;----------------------------------------------------
no_char2:  JSR sub1             ;sub1() (useless)
L_41:      LDA cntrl_outbuf,Y   ;Get char from buffer from controller
           STA modout_buf,Y     ;Store char in module output buffer
           CMP #02AH            ;char == '*' ?
           BEQ L_50             ;  Yes, goto L_50
           JMP L_51             ;  No, goto L_51

           ;----------------------------------------------
           ; A terminating '*' was found during copying
           ; buffer FROM controller to module's output
           ; buffer.
           ;-----------------------------------------------
L_50:      LDA #1               ;Set outterm_flag to 1
           STA outterm_flag     ;"
           JMP L_34             ;goto L_34

           ;-------------------------------------------
           ; SUB1()
           ; The subroutine in which nothing is done
           ;-------------------------------------------
sub1:      RTS                  ;Return SUB

           PAGE
           ;------------------------------------------
           ; Table 0
           ; This table contains the values for the
           ; 5 character timeout counter to detect a
           ; datagap. This value is depents on the
           ; current baudrate.
           ;------------------------------------------
           ORG 0FC2Dh

table0:    DFB 000H,000H,003H,0E8H,002H,09BH,001H,0C7H ;
           DFB 001H,074H,001H,04DH,000H,0A7H,000H,053H ;
           DFB 000H,02AH,000H,01CH,000H,015H,000H,00EH ;
           DFB 000H,00AH,000H,007H,000H,005H,000H,003H ;

           ;------------------------------------------
           ; Table 1
           ;------------------------------------------
           ORG 0FC4DH

table1:    DFB 000H,001H,002H,003H,004H,005H,006H,007H ;
           DFB 008H,009H,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,00AH,00BH,00CH,00DH,00EH,00FH      ;

           ;------------------------------------------
           ; Table 2
           ;------------------------------------------
           ORG 0FC64H

table2:    DFB 000H,010H,020H,030H,040H,050H,060H,070H ;
           DFB 080H,090H                               ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH      ;
           DFB 0A0H,0B0H,0C0H,0D0H,0E0H,0F0H,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH   ;

           PAGE
           ;-----------------------------------------------------------
           ; Test if input character matches identifier string (id_str)
           ; Each time a LF is found, we set the match_flag to 1 (assume
           ;  match) and the pointer to the identifier in ROM to 0.
           ; If id_ptr < 7 we will test if the character matches its
           ;  corresponding position in the ROM identifier. If not, we
           ; reset the match_flag to 0.
           ; If id_ptr >= 7 we are past the identifier of the message.
           ;  If the match_flag is set then, we sent the character back
           ;  to the UART up and including the terminating LF
           ; If id_ptr >=7 and the matchflag is not set, we wait till
           ; we receive a LF and reset id_ptr and set the match_flag
           ;------------------------------------------------------------
getchar1:  LDA UART_data        ;Get char from UART
           TAY                  ;Save char in Y
           INC id_ptr           ;id_ptr++
           LDX id_ptr           ;X = id_ptr
           CPX #007H            ;id_ptr >= 7 ?
           BCS L_52             ;  Yes, goto L_52
           CMP 0FE00H,X         ;char == *(id_str+id_ptr) ?
           BEQ L_53             ;  Yes, goto L_53
           LDX #0               ;match_flag = 0
           STX match_flag       ;"
L_53:      CMP #00AH            ;A == LF ?
           BNE L_54             ;  No, goto L_54
           LDX #0               ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;match_flag = 1
           STX match_flag       ;"
L_54:      JMP no_char1         ;Data is not part of message --> no_char1
           NOP                  ;NOP
L_52:      LDX match_flag       ;Get match_flag
           CPX #0               ;match_flag = 0 ?
           BEQ L_53             ;  Yes, goto L_53
           CMP #00AH            ;A = LF ?
           BNE L_55             ;  No, goto L_55
           LDX #0               ;id_ptr = 0
           STX id_ptr           ;"
           INX                  ;match_flag = 1
           STX match_flag       ;"
L_55:      NOP                  ;NOP
           NOP                  ;NOP
           STA UART_data        ;Send char to UART (Send Register)
           JMP got_char1        ;Data is part of message --> got_char1

           ;---------------------
           ; Data table 3
           ;---------------------
data3:     DFB 0FFH,0FFH,0FFH   ;

           PAGE
           ;-----------------------------------------------------------
           ; Test if input character matches identifier string (id_str)
           ; See for description getchar1()
           ; We perform the same function, but are called from somewhere
           ; else in the code.
           ;------------------------------------------------------------
getchar2:  LDA UART_data        ;Get character from UART
           TAY                  ;Save character in Y
           INC id_ptr           ;id_ptr++
           LDX id_ptr           ;X = id_ptr
           CPX #007H            ;id_ptr >= 7 ?
           BCS L_57             ;  Yes, goto L_57
           CMP 0FE00H,X         ;char == *(id_str+id_ptr) ?
           BEQ L_58             ;  Yes, goto L_58
           LDX #0               ;Match_flag = 0
           STX match_flag       ;"
L_58:      CMP #00AH            ;char == LF ?
           BNE L_59             ;  No, goto L_59
           LDX #0               ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;Match_flag = 1
           STX match_flag       ;"
L_59:      JMP no_char2         ;Data is not part of message --> no_char2
           NOP                  ;
L_57:      LDX match_flag       ;Get match_flag
           CPX #0               ;match_flag == 0 ?
           BEQ L_58             ;  Yes, goto L_58
           CMP #00AH            ;char == LF ?
           BNE L_60             ;  No, goto L_60
           LDX #0               ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;Match_flag = 1
           STX match_flag       ;"
L_60:      NOP                  ;
           NOP                  ;
           STA UART_data        ;
           JMP got_char2        ;Data is part of message --> got_char2

           PAGE
           ;------------------------------------------
           ; Data ???
           ;------------------------------------------
data2:     DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH   ;

           ;------------------------------------------
           ; Identifier string
           ;------------------------------------------
string:    DFB 000H,024H,049H,049H,047H,047H,04CH,000H ; "/0$IIGGL/0"

           ;--------------------------------------------
           ; Data ???
           ;--------------------------------------------
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;
           DFB 0FFH,0FFH        ;

           ;-------------------------------------------
           ; Vectors
           ;-------------------------------------------
NMI_addr:  DFB 0FFH,0FFH        ;
RES_addr:  DFB 000H,0F8H        ;
IRQ_addr:  DFB 0FFH,0FFH        ;
