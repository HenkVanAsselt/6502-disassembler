
         ;------------------------------------------------;
         ;                                                ;
         ;  Interface 80 serial I/O EPROM                 ;
         ;  with test on NMEA-0183 identifier             ;
         ;  but without test on talker address            ;
         ;                                                ;
         ;  '$xxGGL'                                      ;
         ;                                                ;
         ;  H.B.J. van Asselt                             ;
         ;  V1.0            19-12-1990                    ;
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
term_count:      EQU  06H    ; Terminating count value
term_char:       EQU  07H    ; Terminating character
term_mode:       EQU  08H    ; Terminating mode
tmout_5char_L:   EQU  11H    ; 5 char timeout value
tmout_5char_H:   EQU  10H    ; "
tmout_cntr_L:    EQU  0FH    ; time out counter
tmout_cntr_H:    EQU  0EH    ;
id_ptr:          EQU  20H    ; Pointer to identifier string
tmp1:            EQU  17H    ; Temporary data
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
; Some character constants
;---------------------------
CR:              EQU  0DH       ; Carriage Return
LF:              EQU  0AH       ; Line Feed


PAGE
           ORG 0F800H

           CLD                  ;Clear Decimal Flag
           LDX #0FFH            ;X = FFh
           TXS                  ;X-->Stackpointer
           SEI                  ;Disable IRQ
           LDA #000H            ;A = 0
           STA VIA_DDRA         ;VIA Port A is input
           LDA #000H            ;A = 0
           STA VIA_DDRB         ;VIA Port B is input
           LDA VIA_IORA         ;Determine switch 2 settings
           STA Switch2          ;Store switch 2 settings
           LDA VIA_IORB         ;Determine switch 3 settings
           STA Switch3          ;Store switch 3 setting
           LDA UART_status      ;Get UART status
           STA 000H             ;Store UART status
L_27:      LDA Switch2          ;Load switch 2 settings
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
           STX 009H             ;Save copy in RAM[09h]
           LDA Switch2          ;Load switch 2 settings from ZP
           AND #070H            ;Mask bit 6..4 (parity mode)
           ASLA                 ;A *= 2
           ORA #00BH            ;Set bit 7, 5 and 4
           STA UART_cmd         ;Load UART command register with A
           STA 00AH             ;Save copy in ZP-0Ah

           ;-------------------------------------------------
           ; Initialize input termination condition
           ;-------------------------------------------------
           LDA #0FFH            ;Preset terminating character
           STA term_char        ; to FFh
           LDA #07AH            ;Preset terminating character counter
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
           ORA #001H            ;Set bit 1 of count/char
           TAX                  ;X = A
L_02:      LDA term_mode        ;Get terminating mode
           BEQ L_03             ;Term mode = 0 (term. char) ? --> goto L03
           CPX #07AH            ;X < 122 ?
           BCC L_04             ;  Yes --> goto L_04
           LDX #07AH            ;No, X = 122
L_04:      STX term_count       ;Terminating counter = X
           JMP L_05             ;Skip next instruction
L_03:      STX term_char        ;Terminating character = X

PAGE
           ;------------------------------------------------
           ; Initialize several memory locations on page 0
           ;------------------------------------------------
L_05:      LDA #000H            ;A = 0
           STA 003H             ;
           STA 00DH             ;
           STA 00CH             ;
           STA 00BH             ;
           STA 012H             ;
           STA 013H             ;
           STA 014H             ;
           STA 015H             ;
           STA 016H             ;
           STA tmout_cntr_H     ;
           STA tmout_cntr_L     ;
           LDA #001H            ;A = 1
           STA 004H             ;
           STA 005H             ;

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
           CMP #07AH            ;A == 122 ?
           BNE L_06             ; No, goto L_06
           LDA #0FFH            ;RAM[10h] = -1
           STA tmout_5char_H    ;"
L_06:      LDA term_count       ;A = terminating count value
           LDX #07AH            ;X = 122
           CMP #07AH            ;A = 7Ah/122/'z' ?
           BEQ L_07             ;  Yes --> goto L_07
           TAX                  ;X = A
L_07:      LDA #02DH            ;A = '-'
           STA cntrl_inbuf      ;*(cntrl_inbuf) = '-'
           LDA #021H            ;A = '!'
           LDY #001H            ;Y = 1
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
           STA cntrl_inbuf,Y    ;*(cntrl_inbuf+Y) = '*'
L_34:      LDA #02AH            ;A = '*'
           STA 0037FH           ;RAM(37Fh] = '*'
           LDA term_count       ;A = terminating count value
           CMP #07AH            ;A == 122 ?
           BNE L_10             ; No, goto L_10
           LDA #000H            ;Reset time out counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"
           STA 00DH             ;RAM[0dh] = 0
L_10:      LDA VIA_IFR          ;Get VIA Interrupt Flag Register
           STA VIA_IFR          ;  and write data back in IFR
           AND #040H            ;Mask bit 6 (Time out T1)
           BEQ L_11             ;Bit 6 was 0 --> no time out --> goto L_11
           LDA tmout_cntr_L     ;Increment 2-byte time out counter.
           CLC                  ;"
           ADC #001H            ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #000H            ;"
           STA tmout_cntr_H     ;"
           INC 014H             ;Increment ZP-14h
           CMP tmout_5char_H    ;RAM[10h] = RAM[0Eh] ?
           BNE L_11             ;  No --> goto L_11
           LDA tmout_cntr_L     ;Get LSB of time out counter
           CMP tmout_5char_L    ;RAM[0Fh] == RAM[11h] ?
           BNE L_11             ; No --> goto L_11
           LDA #001H            ;Yes,
           STA 005H             ;RAM[05h] = 1
           LDA #000H            ;Reset 2-byte time out counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"

L_11:      LDA 014H             ;A = RAM[14h]
           CMP #00AH            ;A < 10 ?
           BCC L_12             ;Yes, goto L_12
           SBC #00AH            ;A = A - 10
           STA 014H             ;RAM[14h] = A

           PAGE
           ;----------------------------------------------------
           ; Increment 2-byte (0Bh,0Ch) counter in decimal mode
           ;----------------------------------------------------
           LDA 00CH             ;Get ZP-0Ch
           SED                  ;Set Decimal Flag (calculate decimal)
           CLC                  ;Clear Carry Flag
           ADC #001H            ;Increment value (decimal)
           STA 00CH             ;Write result in ZP-0Ch
           LDA 00BH             ;Get ZP-0Ch
           ADC #000H            ;If Carry, increment value
           STA 00BH             ;Write result in ZP-0Ch

           ;----------------------------------------------------
           ; Increment 2-byte (13h,12h) counter in decimal mode
           ;----------------------------------------------------
           LDA 012H             ;Increment ZP-12h
           CLC                  ;"
           ADC #001H            ;"
           STA 012H             ;"
           LDA 013H             ;and increment ZP-13h if Carry set
           ADC #000H            ;"
           STA 013H             ;"
           CLD                  ;Clear Decimal Flag

           ;-----------------------------------
           ;
           ;-----------------------------------
           LDX 015H             ;ZP
           BNE L_12             ;
           LDX 016H             ;ZP
           BEQ L_12             ;
           CMP #099H            ;
           BNE L_13             ;
           JMP L_14             ;JUMP
L_13:      CPX #07CH            ;
           BCS L_12             ;
           JMP L_15             ;JUMP
L_12:      JMP L_16             ;JUMP

           PAGE
           ;----------------------------------------------------
           ; Convert 2-byte counter (12h,13h) to 4 characters
           ; Place these characters in string, starting at 0300h
           ; A contains value of RAM[13h]
           ;-----------------------------------------------------
           ;
           ;  Convert first byte RAM[13h]
           ;
L_15:      TAY                  ;Y = A (save value in Y)
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
           ;
           ; Convert second byte RAM[12h]
           ;
L_17:      INX                  ;X++; increment string pointer
           LDA 012H             ;A = RAM[12h]
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

           ;---------------------------------------
           ;
           ;---------------------------------------
L_14:      LDA #021H            ;A = '!'
           STA 015H             ;RAM[15h] = '!'
           LDY #000H            ;Y = 0
           LDX 016H             ;RAM[16h] = 0
L_19:      STA cntrl_inbuf,X    ;*(cntrl_inbuf+X) = A
           INX                  ;X++
           JSR sub1             ;Wait some time to make access to
           JSR sub1             ;  shared memory possible.
           JSR sub1
           JSR sub1
           NOP
           NOP
           JMP L_18             ;Goto L_18

           ;-----------------------------------
           ;
           ;-----------------------------------
L_18:      INY                  ;Y++
           CPY #004H            ;Y == 4 ?
           BNE L_19             ;  No --> goto L_19
L_16:      LDA 003H             ;ZP
           BNE L_20             ;
           JMP test_rx2         ;JUMP
L_20:      LDA 004H             ;A = RAM[04h]
           TAX                  ;X = A
           TAY                  ;Y = A
           INY                  ;Y++
           LDA modout_buf,X     ;A = *(modout_buf+X)
           CMP #02AH            ;A == '*' ?
           BNE L_22             ;  No --> goto L_22:
           JMP L_23             ; Yes --> goto L_23:
L_22:      LDA UART_status      ;Get actual status from UART
           AND #010H            ;Mask Transmitter Data Register Empty flag
           BNE L_24             ;Data Register empty? Yes, goto L_24
           JMP test_rx2         ;No, goto test_rx2:

           ;--------------------------------------
           ; Check if output message contains '<^'
           ; If so, replace these by CR and LF
           ;--------------------------------------
L_24:      LDA modout_buf,X     ;A = *(modout_buf+Y)
           CMP #03CH            ;A == '<' ?
           BNE L_25             ;  No, goto L_25:
           LDA modout_buf,Y     ;A = *(modout_buf+X)
           CMP #05EH            ;A == '^' ?
           BNE L_25             ;  No, goto L_25:
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
L_25:      CPX #001H            ;X == 1 ?
           BNE L_26             ;  No, goto L_26
           CMP #05EH            ;A == '^' ?
           BNE L_26             ;  No (no override command), goto L_26
           LDA modout_buf,Y     ;A = *(modout_buf+Y)
           CMP #05EH            ;A == '^' ?
           BNE L_26             ;  No (no override command), goto L_26

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
           JMP L_27             ;Goto L_27: Restart program with override values

           ;---------------------------------
           ; No override command detected
           ;---------------------------------
L_26:      LDA modout_buf,X     ;A = *(modout_buf+X)
           STA UART_data        ;Send data to UART for output
           INC 004H             ;Increment output_ptr
           JMP test_rx2         ;Goto test_rx2

           ;----------------------------------------
           ; Reset output string (outstr) pointers
           ;----------------------------------------
L_23:      LDA #000H            ;RAM[03h] = 0
           STA 003H             ;"
           LDA #001H            ;RAM[04h] = 0
           STA 004H             ;"

           PAGE
           ;------------------------------------
           ; Test if UART has data available
           ;------------------------------------
test_rx2:  LDA UART_status      ;Get UART status
           AND #008H            ;Receiver Data Register Full ?
           BNE L_28             ;  Yes --> goto L_28
           JMP L_29             ;  No --> goto L_29

           ;-------------------------
           ; UART has received data
           ;-------------------------
L_28:      JMP testchar1        ;Test if char matches identifier string
L_56:      NOP                  ;
           CMP #CR              ;A == CR ?
           BEQ L_30             ;  Yes, goto L_30
           CMP #LF              ;A == LF ?
           BNE L_31             ;  No, goto L_31
L_30:      LDA #027H            ;Replace CR or LF by '\''
L_31:      TAX                  ;X = A (store char)
           LDA #000H            ;Reset 2-byte timeout counter
           STA tmout_cntr_H     ;"
           STA tmout_cntr_L     ;"
           STA 015H             ;RAM[15h] = 0
           LDA 005H             ;A = RAM[05h]
           CMP #001H            ;A == 1 ?
           BNE L_32             ;  No, goto L_32
           LDA #000H            ;  Yes, reset ZP locations:
           STA 00CH             ;RAM[0Ch] = 0
           STA 00BH             ;RAM[0Bh] = 0
           STA 014H             ;RAM[14h] = 0

L_32:      TXA                  ;A = X (restore char)
           LDX 005H             ;X = pointer
           STA modin_buf,X      ;*(modin_buf+X) = char
           INX                  ;X++
           STX 005H             ;RAM[05h] = X
           LDA #02AH            ;Place a '*'
           STA modin_buf,X      ;  behind last character of input_str
           DEX                  ;X--
           CPX term_count       ;X == terminating count value ?
           BEQ L_33             ; Yes, goto L_33
           CPY term_char        ;Y == terminating character ?
           BEQ L_33             ; Yes, goto L_33
           JMP L_34             ;No termination condition, goto L_34

           ;-------------------------------------------
           ; String terminator has been found:
           ; 1) Terminating character or
           ; 2) Specified number of characters read.
           ;-------------------------------------------
L_33:      LDA 00CH             ;ZP
           STA 012H             ;ZP
           LDA 00BH             ;ZP
           STA 013H             ;ZP
           LDX 005H             ;ZP
           STX 016H             ;ZP

           PAGE
           ;------------------------------------------------
           ; Convert 2-byte value (12h,13h) to 4 characters
           ; and place these characters in modin_buf string
           ;------------------------------------------------
L_49:      LDX 016H             ;Get pointer
           LDA 013H             ;Get data
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
           LDA 012H             ;A = data
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
           LDA #02AH            ;
           STA modin_buf,X      ;
           LDA #001H            ;
           STA 005H             ;
           LDA #02BH            ;
           STA modin_buf        ;
           LDX #000H            ;
L_39:      LDA modin_buf,X      ;
           TAY                  ;
           STA cntrl_inbuf,X    ;
           LDA VIA_IFR          ;Get VIA interrupt flag register
           STA VIA_IFR          ;  and write data back to IFR
           AND #040H            ;Mask timeout T1 flag
           BEQ L_35             ;If flag not set then goto L_35 else
           LDA tmout_cntr_L     ;Increment 2-byte timeout counter
           CLC                  ;"
           ADC #001H            ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #000H            ;"
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
           CPX #07FH            ;X == 7Fh ?
           BEQ L_38             ;  Yes, goto L_38
           CPY #02AH            ;Y == 2Ah/42/'*' ?
           BNE L_39             ;  No, goto L_39
L_38:      LDY 00DH             ;ZP
           BEQ L_40             ;
           LDA #000H            ;
           STA 00DH             ;ZP
           LDA cntrl_outbuf     ;
           CMP #02DH            ;
           BNE L_40             ;
           JMP L_41             ;JUMP
L_40:      JMP L_34             ;JUMP
L_29:      LDA cntrl_outbuf     ;
           CMP #02BH            ;
           BEQ L_42             ;
           JMP L_34             ;JUMP
L_42:      LDA #02DH            ;
           STA cntrl_outbuf     ;
           LDY #000H            ;
L_51:      INY                  ;
           LDA VIA_IFR          ;Get VIA Interrupt Flag Register
           STA VIA_IFR          ;  and write data back to it.
           AND #040H            ;Mask bit 6 (Time out T1)
           BEQ test_rx1         ;T1 Time out ? Yes, goto test_rx1
           LDA tmout_cntr_L     ;No, increment 2-bytes timeout counter
           CLC                  ;"
           ADC #001H            ;"
           STA tmout_cntr_L     ;"
           LDA tmout_cntr_H     ;"
           ADC #000H            ;"
           STA tmout_cntr_H     ;"
           INC 014H             ;RAM[14h]++
           CMP tmout_5char_H    ;ZP
           BNE test_rx1         ;
           LDA tmout_cntr_L     ;Get LSB of timeout counter
           CMP tmout_5char_L    ;RAM[11h] == LSB ?
           BNE test_rx1         ;  No, goto test_rx1
           LDA #001H            ;RAM[05h] = 1
           STA 005H             ;"
           LDA #000H            ;Reset 2-byte timeout counter
           STA tmout_cntr_L     ;"
           STA tmout_cntr_H     ;"

           PAGE
           ;-----------------------------
           ; Test if UART received data.
           ;-----------------------------
test_rx1:  LDA UART_status      ;Get UART status
           AND #008H            ;Receiver Data Register Full ?
           BEQ L_44             ;  No, goto L_44

           ;-------------------------------
           ; UART has data available
           ;-------------------------------
           JMP testchar2        ;Get char and perform test on identifier
L_61:      NOP                  ;NOP (char in A and in Y)
           CMP #CR              ;A == CR ?
           BEQ L_45             ; Yes, goto L_45
           CMP #LF              ;A == LF ?
           BNE L_46             ; No, goto L_46
L_45:      LDA #027H            ;Replace CR or LF by '\''
L_46:      STA tmp1             ;Save char in tmp1
           LDA #000H            ;Reset 2-byte timeout counter
           STA tmout_cntr_H     ;"
           STA tmout_cntr_L     ;"
           STA 015H             ;RAM[15h] = 0
           LDX 005H             ;X = RAM[05h]
           CPX #001H            ;RAM[05h] == 1 ?
           BNE L_47             ; No, goto L_47
           LDX #000H            ;Reset 2-byte value
           STX 00CH             ;"
           STX 00BH             ;"
L_47:      LDX 005H             ;X = RAM[05h]
           LDA tmp1             ;Retrieve char from tmp1
           STA modin_buf,X      ;*(modin_buf+X) = char
           INC 005H             ;RAM[05h]++
           CPX term_count       ;X == terminating counter value ?
           BEQ L_48             ; Yes, goto L_48
           CPY term_char        ;Y == terminating character ?
           BEQ L_48             ; Yes, goto L_48
           JMP L_44             ;No termination condition, goto L_44

           ;-------------------------------------------
           ; String terminator has been found:
           ; 1) Terminating character or
           ; 2) Specified number of characters read.
           ;-------------------------------------------
L_48:      LDA 005H             ;ZP
           STA 016H             ;ZP
           LDA #001H            ;
           STA 005H             ;ZP
           LDA 00CH             ;ZP
           STA 012H             ;ZP
           LDA 00BH             ;ZP
           STA 013H             ;ZP
           STY 00DH             ;ZP
           JMP L_49             ;JUMP

           ;--------------------------------------
           ;
           ;--------------------------------------
L_44:      JSR sub1             ;sub1() (useless)
L_41:      LDA cntrl_outbuf,Y   ;
           STA modout_buf,Y     ;
           CMP #02AH            ;
           BEQ L_50             ;
           JMP L_51             ;JUMP
L_50:      LDA #001H            ;
           STA 003H             ;ZP
           JMP L_34             ;JUMP
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

testchar1: LDA UART_data        ;Get char from UART
           TAY                  ;Save char in Y
           INC id_ptr           ;id_ptr++
           LDX id_ptr           ;X = id_ptr
           CPX #007H            ;id_ptr >= 7 ?
           BCS L_52             ;  Yes, goto L_52
           CPX #2               ;id_ptr == 2 ?
           BEQ L_53             ;  Yes, skip testing Talker address
           CPX #3               ;id_ptr == 3 ?
           BEQ L_53             ;  Yes, skip testing Talker address
           CMP 0FE00H,X         ;char == *(id_str+id_ptr) ?
           BEQ L_53             ;  Yes, goto L_53
           LDX #000H            ;match_flag = 0
           STX match_flag       ;"
L_53:      CMP #00AH            ;A == LF ?
           BNE L_54             ;  No, goto L_54
           LDX #000H            ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;match_flag = 1
           STX match_flag       ;"
L_54:      JMP L_29             ;goto L_29 (get out of this 'subroutine')
           NOP                  ;NOP
L_52:      LDX match_flag       ;Get match_flag
           CPX #000H            ;match_flag = 0 ?
           BEQ L_53             ;  Yes, goto L_53
           CMP #00AH            ;A = LF ?
           BNE L_55             ;  No, goto L_55
           LDX #000H            ;id_ptr = 0
           STX id_ptr           ;"
           INX                  ;match_flag = 1
           STX match_flag       ;"
L_55:      NOP                  ;NOP
           NOP                  ;NOP
           STA UART_data        ;Send char to UART (Send Register)
           JMP L_56             ;goto L_56 (get out of this 'subroutine')

           ;---------------------
           ; Data table 3
           ;---------------------
data3:     DFB 0FFH,0FFH,0FFH   ;

           PAGE
           ;-----------------------------------------------------------
           ; Test if input character matches identifier string (id_str)
           ; See for description testchar1()
           ; We perform the same function, but are called from somewhere
           ; else in the code.
           ;------------------------------------------------------------

testchar2: LDA UART_data        ;Get character from UART
           TAY                  ;Save character in Y
           INC id_ptr           ;id_ptr++
           LDX id_ptr           ;X = id_ptr
           CPX #007H            ;id_ptr >= 7 ?
           BCS L_57             ;  Yes, goto L_57
           CMP 0FE00H,X         ;char == *(id_str+id_ptr) ?
           BEQ L_58             ;  Yes, goto L_58
           LDX #000H            ;Match_flag = 0
           STX match_flag       ;"
L_58:      CMP #00AH            ;char == LF ?
           BNE L_59             ;  No, goto L_59
           LDX #000H            ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;Match_flag = 1
           STX match_flag       ;"
L_59:      JMP L_44             ;goto L_44 (get out of this 'subroutine')
           NOP                  ;
L_57:      LDX match_flag       ;Get match_flag
           CPX #000H            ;match_flag == 0 ?
           BEQ L_58             ;  Yes, goto L_58
           CMP #00AH            ;char == LF ?
           BNE L_60             ;  No, goto L_60
           LDX #000H            ;Yes, id_ptr = 0
           STX id_ptr           ;"
           INX                  ;Match_flag = 1
           STX match_flag       ;"
L_60:      NOP                  ;
           NOP                  ;
           STA UART_data        ;
           JMP L_61             ;goto L_61 (get out of this 'subroutine')

           ;------------------------------------------
           ; Identifier string
           ;------------------------------------------
string:    DFB 000H,024H,049H,049H,047H,047H,04CH,000H ; "/0$xxGGL/0"

           ;-------------------------------------------
           ; Vectors
           ;-------------------------------------------
           ORG 0FFFAH

NMI_addr:  DFB 0FFH,0FFH        ; Non Maskeble Interrupt vector
RES_addr:  DFB 000H,0F8H        ; Reset vector
IRQ_addr:  DFB 0FFH,0FFH        ; Interrupt Request vector
