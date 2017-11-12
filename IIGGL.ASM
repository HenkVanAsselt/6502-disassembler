  CPU "6502.tbl"
  HOF "INT16"
  ORG 0F800H

UART_data:       EQU  00800H
UART_status:     EQU  00801H
UART_cmd:        EQU  00802H
UART_cntrl:      EQU  00803H
UART_cntrl:      EQU  00803H
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
VIA_IORA2:       EQU  0040FH
NMI_addr:        EQU  0FFFAH
RES_addr:        EQU  0FFFCH
IRQ_addr:        EQU  0FFFEH
IRQ_addr:        EQU  0FFFEH
sub1:            EQU  0FC2CH
testchar2:       EQU  0FCD0H
testchar1:       EQU  0FC90H
testchar1:       EQU  0FC90H
string:          EQU  0FE00H
table:           EQU  0FC4DH
data1:           EQU  0FC2DH
data2:           EQU  0FD0DH
data3:           EQU  0FCCDH

           CLD                  ;         
           LDX #0FFH            ;         
           TXS                  ;         
           SEI                  ;Disable IRQ 
           LDA #000H            ;         
           STA VIA_DDRA         ;         
           LDA #000H            ;         
           STA VIA_DDRB         ;         
           LDA VIA_IORA         ;         
           STA 002H             ;ZP       
           LDA VIA_IORB         ;         
           STA 001H             ;ZP       
           LDA UART_status      ;         
           STA 000H             ;ZP       
L_27:      LDA 002H             ;ZP       
           AND #08FH            ;         
           ORA #010H            ;         
           TAX                  ;         
           LDA 001H             ;ZP       
           AND #040H            ;         
           BEQ L_01             ;         
           TXA                  ;         
           ORA #020H            ;         
           TAX                  ;         
L_01:      STX UART_cntrl       ;         
           STX 009H             ;ZP       
           LDA 002H             ;ZP       
           AND #070H            ;         
           ASLA                 ;         
           ORA #00BH            ;         
           STA UART_cmd         ;         
           STA 00AH             ;ZP       
           LDA #0FFH            ;         
           STA 007H             ;ZP       
           LDA #07AH            ;         
           STA 006H             ;ZP       
           LDA 001H             ;ZP       
           TAX                  ;         
           AND #080H            ;         
           STA 008H             ;ZP       
           TXA                  ;         
           AND #03FH            ;         
           ASLA                 ;         
           TAX                  ;         
           LDA 000H             ;ZP       
           AND #040H            ;         
           BEQ L_02             ;         
           TXA                  ;         
           ORA #001H            ;         
           TAX                  ;         
L_02:      LDA 008H             ;ZP       
           BEQ L_03             ;         
           CPX #07AH            ;         
           BCC L_04             ;         
           LDX #07AH            ;         
L_04:      STX 006H             ;ZP       
           JMP L_05             ;JUMP     
L_03:      STX 007H             ;ZP       
L_05:      LDA #000H            ;         
           STA 003H             ;ZP       
           STA 00DH             ;ZP       
           STA 00CH             ;ZP       
           STA 00BH             ;ZP       
           STA 012H             ;ZP       
           STA 013H             ;ZP       
           STA 014H             ;ZP       
           STA 015H             ;ZP       
           STA 016H             ;ZP       
           STA 00EH             ;ZP       
           STA 00FH             ;ZP       
           LDA #001H            ;         
           STA 004H             ;ZP       
           STA 005H             ;ZP       
           LDA #07FH            ;         
           STA VIA_IER          ;         
           LDA #040H            ;         
           STA VIA_ACR          ;         
           LDA #0E8H            ;         
           STA VIA_T1_CL        ;         
           LDA #003H            ;         
           STA VIA_T1_CH        ;         
           LDA UART_cntrl       ;         
           AND #00FH            ;         
           ASLA                 ;         
           TAX                  ;         
           LDA 0FC2DH,X         ;         
           STA 010H             ;ZP       
           INX                  ;         
           LDA 0FC2DH,X         ;         
           STA 011H             ;ZP       
           LDA 006H             ;ZP       
           CMP #07AH            ;         
           BNE L_06             ;         
           LDA #0FFH            ;         
           STA 010H             ;ZP       
L_06:      LDA 006H             ;ZP       
           LDX #07AH            ;         
           CMP #07AH            ;         
           BEQ L_07             ;         
           TAX                  ;         
L_07:      LDA #02DH            ;         
           STA 00300H           ;         
           LDA #021H            ;         
           LDY #001H            ;         
           INX                  ;         
           INX                  ;         
           INX                  ;         
           INX                  ;         
L_09:      STA 00300H,Y         ;         
           INY                  ;         
           DEX                  ;         
           BEQ L_08             ;         
           JMP L_09             ;JUMP     
L_08:      LDA #02AH            ;         
           STA 00300H,Y         ;         
L_34:      LDA #02AH            ;         
           STA 0037FH           ;         
           LDA 006H             ;ZP       
           CMP #07AH            ;         
           BNE L_10             ;         
           LDA #000H            ;         
           STA 00FH             ;ZP       
           STA 00EH             ;ZP       
           STA 00DH             ;ZP       
L_10:      LDA VIA_IFR          ;         
           STA VIA_IFR          ;         
           AND #040H            ;         
           BEQ L_11             ;         
           LDA 00FH             ;ZP       
           CLC                  ;         
           ADC #001H            ;         
           STA 00FH             ;ZP       
           LDA 00EH             ;ZP       
           ADC #000H            ;         
           STA 00EH             ;ZP       
           INC 014H             ;ZP       
           CMP 010H             ;ZP       
           BNE L_11             ;         
           LDA 00FH             ;ZP       
           CMP 011H             ;ZP       
           BNE L_11             ;         
           LDA #001H            ;         
           STA 005H             ;ZP       
           LDA #000H            ;         
           STA 00FH             ;ZP       
           STA 00EH             ;ZP       
L_11:      LDA 014H             ;ZP       
           CMP #00AH            ;         
           BCC L_12             ;         
           SBC #00AH            ;         
           STA 014H             ;ZP       
           LDA 00CH             ;ZP       
           SED                  ;         
           CLC                  ;         
           ADC #001H            ;         
           STA 00CH             ;ZP       
           LDA 00BH             ;ZP       
           ADC #000H            ;         
           STA 00BH             ;ZP       
           LDA 012H             ;ZP       
           CLC                  ;         
           ADC #001H            ;         
           STA 012H             ;ZP       
           LDA 013H             ;ZP       
           ADC #000H            ;         
           STA 013H             ;ZP       
           CLD                  ;         
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
L_15:      TAY                  ;         
           AND #0F0H            ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           ORA #030H            ;         
           STA 00300H,X         ;         
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           INX                  ;         
           TYA                  ;         
           AND #00FH            ;         
           ORA #030H            ;         
           STA 00300H,X         ;         
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           JMP L_17             ;JUMP     
L_17:      INX                  ;         
           LDA 012H             ;ZP       
           TAY                  ;         
           AND #0F0H            ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           ORA #030H            ;         
           STA 00300H,X         ;         
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           INX                  ;         
           TYA                  ;         
           AND #00FH            ;         
           ORA #030H            ;         
           STA 00300H,X         ;         
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           INX                  ;         
           LDA #02AH            ;         
           STA 00300H,X         ;         
           JMP L_16             ;JUMP     
L_14:      LDA #021H            ;         
           STA 015H             ;ZP       
           LDY #000H            ;         
           LDX 016H             ;ZP       
L_19:      STA 00300H,X         ;         
           INX                  ;         
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           JSR sub1             ;JUMP     
           NOP                  ;         
           NOP                  ;         
           JMP L_18             ;JUMP     
L_18:      INY                  ;         
           CPY #004H            ;         
           BNE L_19             ;         
L_16:      LDA 003H             ;ZP       
           BNE L_20             ;         
           JMP L_21             ;JUMP     
L_20:      LDA 004H             ;ZP       
           TAX                  ;         
           TAY                  ;         
           INY                  ;         
           LDA 00280H,X         ;         
           CMP #02AH            ;         
           BNE L_22             ;         
           JMP L_23             ;JUMP     
L_22:      LDA UART_status      ;         
           AND #010H            ;         
           BNE L_24             ;         
           JMP L_21             ;JUMP     
L_24:      LDA 00280H,X         ;         
           CMP #03CH            ;         
           BNE L_25             ;         
           LDA 00280H,Y         ;         
           CMP #05EH            ;         
           BNE L_25             ;         
           LDA #00DH            ;         
           STA 00280H,X         ;         
           LDA #00AH            ;         
           STA 00280H,Y         ;         
L_25:      CPX #001H            ;         
           BNE L_26             ;         
           CMP #05EH            ;         
           BNE L_26             ;         
           LDA 00280H,Y         ;         
           CMP #05EH            ;         
           BNE L_26             ;         
           INY                  ;         
           LDA 00280H,Y         ;         
           ASLA                 ;         
           ASLA                 ;         
           ASLA                 ;         
           ASLA                 ;         
           ASLA                 ;         
           ASLA                 ;         
           STA 000H             ;ZP       
           CLD                  ;         
           INY                  ;         
           LDA 00280H,Y         ;         
           SEC                  ;         
           SBC #030H            ;         
           TAX                  ;         
           LDA 0FC64H,X         ;         
           STA 017H             ;ZP       
           INY                  ;         
           LDA 00280H,Y         ;         
           SEC                  ;         
           SBC #030H            ;         
           TAX                  ;         
           LDA 0FC4DH,X         ;         
           ORA 017H             ;ZP       
           STA 001H             ;ZP       
           INY                  ;         
           LDA 00280H,Y         ;         
           SEC                  ;         
           SBC #030H            ;         
           TAX                  ;         
           LDA 0FC64H,X         ;         
           STA 017H             ;ZP       
           INY                  ;         
           LDA 00280H,Y         ;         
           SEC                  ;         
           SBC #030H            ;         
           TAX                  ;         
           LDA 0FC4DH,X         ;         
           ORA 017H             ;ZP       
           STA 002H             ;ZP       
           JMP L_27             ;JUMP     
L_26:      LDA 00280H,X         ;         
           STA UART_data        ;         
           INC 004H             ;ZP       
           JMP L_21             ;JUMP     
L_23:      LDA #000H            ;         
           STA 003H             ;ZP       
           LDA #001H            ;         
           STA 004H             ;ZP       
L_21:      LDA UART_status      ;         
           AND #008H            ;         
           BNE L_28             ;         
           JMP L_29             ;JUMP     
L_28:      JMP testchar1        ;JUMP     
L_56:      NOP                  ;         
           CMP #00DH            ;         
           BEQ L_30             ;         
           CMP #00AH            ;         
           BNE L_31             ;         
L_30:      LDA #027H            ;         
L_31:      TAX                  ;         
           LDA #000H            ;         
           STA 00EH             ;ZP       
           STA 00FH             ;ZP       
           STA 015H             ;ZP       
           LDA 005H             ;ZP       
           CMP #001H            ;         
           BNE L_32             ;         
           LDA #000H            ;         
           STA 00CH             ;ZP       
           STA 00BH             ;ZP       
           STA 014H             ;ZP       
L_32:      TXA                  ;         
           LDX 005H             ;ZP       
           STA 00200H,X         ;         
           INX                  ;         
           STX 005H             ;ZP       
           LDA #02AH            ;         
           STA 00200H,X         ;         
           DEX                  ;         
           CPX 006H             ;ZP       
           BEQ L_33             ;         
           CPY 007H             ;ZP       
           BEQ L_33             ;         
           JMP L_34             ;JUMP     
L_33:      LDA 00CH             ;ZP       
           STA 012H             ;ZP       
           LDA 00BH             ;ZP       
           STA 013H             ;ZP       
           LDX 005H             ;ZP       
           STX 016H             ;ZP       
L_49:      LDX 016H             ;ZP       
           LDA 013H             ;ZP       
           TAY                  ;         
           AND #0F0H            ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           ORA #030H            ;         
           STA 00200H,X         ;         
           INX                  ;         
           TYA                  ;         
           AND #00FH            ;         
           ORA #030H            ;         
           STA 00200H,X         ;         
           INX                  ;         
           LDA 012H             ;ZP       
           TAY                  ;         
           AND #0F0H            ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           LSR A                ;         
           ORA #030H            ;         
           STA 00200H,X         ;         
           INX                  ;         
           TYA                  ;         
           AND #00FH            ;         
           ORA #030H            ;         
           STA 00200H,X         ;         
           INX                  ;         
           LDA #02AH            ;         
           STA 00200H,X         ;         
           LDA #001H            ;         
           STA 005H             ;ZP       
           LDA #02BH            ;         
           STA 00200H           ;         
           LDX #000H            ;         
L_39:      LDA 00200H,X         ;         
           TAY                  ;         
           STA 00300H,X         ;         
           LDA VIA_IFR          ;         
           STA VIA_IFR          ;         
           AND #040H            ;         
           BEQ L_35             ;         
           LDA 00FH             ;ZP       
           CLC                  ;         
           ADC #001H            ;         
           STA 00FH             ;ZP       
           LDA 00EH             ;ZP       
           ADC #000H            ;         
           STA 00EH             ;ZP       
           INC 014H             ;ZP       
           JMP L_36             ;JUMP     
L_35:      JSR sub1             ;JUMP     
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           JMP L_36             ;JUMP     
L_36:      JMP L_37             ;JUMP     
L_37:      NOP                  ;         
           NOP                  ;         
           NOP                  ;         
           INX                  ;         
           CPX #07FH            ;         
           BEQ L_38             ;         
           CPY #02AH            ;         
           BNE L_39             ;         
L_38:      LDY 00DH             ;ZP       
           BEQ L_40             ;         
           LDA #000H            ;         
           STA 00DH             ;ZP       
           LDA 00380H           ;         
           CMP #02DH            ;         
           BNE L_40             ;         
           JMP L_41             ;JUMP     
L_40:      JMP L_34             ;JUMP     
L_29:      LDA 00380H           ;         
           CMP #02BH            ;         
           BEQ L_42             ;         
           JMP L_34             ;JUMP     
L_42:      LDA #02DH            ;         
           STA 00380H           ;         
           LDY #000H            ;         
L_51:      INY                  ;         
           LDA VIA_IFR          ;         
           STA VIA_IFR          ;         
           AND #040H            ;         
           BEQ L_43             ;         
           LDA 00FH             ;ZP       
           CLC                  ;         
           ADC #001H            ;         
           STA 00FH             ;ZP       
           LDA 00EH             ;ZP       
           ADC #000H            ;         
           STA 00EH             ;ZP       
           INC 014H             ;ZP       
           CMP 010H             ;ZP       
           BNE L_43             ;         
           LDA 00FH             ;ZP       
           CMP 011H             ;ZP       
           BNE L_43             ;         
           LDA #001H            ;         
           STA 005H             ;ZP       
           LDA #000H            ;         
           STA 00FH             ;ZP       
           STA 00EH             ;ZP       
L_43:      LDA UART_status      ;         
           AND #008H            ;         
           BEQ L_44             ;         
           JMP testchar2        ;JUMP     
L_61:      NOP                  ;         
           CMP #00DH            ;         
           BEQ L_45             ;         
           CMP #00AH            ;         
           BNE L_46             ;         
L_45:      LDA #027H            ;         
L_46:      STA 017H             ;ZP       
           LDA #000H            ;         
           STA 00EH             ;ZP       
           STA 00FH             ;ZP       
           STA 015H             ;ZP       
           LDX 005H             ;ZP       
           CPX #001H            ;         
           BNE L_47             ;         
           LDX #000H            ;         
           STX 00CH             ;ZP       
           STX 00BH             ;ZP       
L_47:      LDX 005H             ;ZP       
           LDA 017H             ;ZP       
           STA 00200H,X         ;         
           INC 005H             ;ZP       
           CPX 006H             ;ZP       
           BEQ L_48             ;         
           CPY 007H             ;ZP       
           BEQ L_48             ;         
           JMP L_44             ;JUMP     
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
L_44:      JSR sub1             ;JUMP     
L_41:      LDA 00380H,Y         ;         
           STA 00280H,Y         ;         
           CMP #02AH            ;         
           BEQ L_50             ;         
           JMP L_51             ;JUMP     
L_50:      LDA #001H            ;         
           STA 003H             ;ZP       
           JMP L_34             ;JUMP     
sub1:      RTS                  ;Return SUB 
data1:     DFB 000H,000H,003H,0E8H,002H,09BH,001H,0C7H ;         
           DFB 001H,074H,001H,04DH,000H,0A7H,000H,053H ;         
           DFB 000H,02AH,000H,01CH,000H,015H,000H,00EH ;         
           DFB 000H,00AH,000H,007H,000H,005H,000H,003H ;         
table:     DFB 000H,001H,002H,003H,004H,005H,006H,007H ;         
           DFB 008H,009H,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;         
           DFB 0FFH,00AH,00BH,00CH,00DH,00EH,00FH,000H ;         
           DFB 010H,020H,030H,040H,050H,060H,070H,080H ;         
           DFB 090H,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;         
           DFB 0A0H,0B0H,0C0H,0D0H,0E0H,0F0H,0FFH,0FFH ;         
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;         
           DFB 0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH,0FFH ;         
           DFB 0FFH,0FFH,0FFH   ;         
testchar1: LDA UART_data        ;         
           TAY                  ;         
           INC 020H             ;ZP       
           LDX 020H             ;ZP       
           CPX #007H            ;         
           BCS L_52             ;         
           CMP 0FE00H,X         ;         
           BEQ L_53             ;         
           LDX #000H            ;         
           STX 021H             ;ZP       
L_53:      CMP #00AH            ;         
           BNE L_54             ;         
           LDX #000H            ;         
           STX 020H             ;ZP       
           INX                  ;         
           STX 021H             ;ZP       
L_54:      JMP L_29             ;JUMP     
           NOP                  ;         
L_52:      LDX 021H             ;ZP       
           CPX #000H            ;         
           BEQ L_53             ;         
           CMP #00AH            ;         
           BNE L_55             ;         
           LDX #000H            ;         
           STX 020H             ;ZP       
           INX                  ;         
           STX 021H             ;ZP       
L_55:      NOP                  ;         
           NOP                  ;         
           STA UART_data        ;         
           JMP L_56             ;JUMP     
data3:     DFB 0FFH,0FFH,0FFH   ;         
testchar2: LDA UART_data        ;         
           TAY                  ;         
           INC 020H             ;ZP       
           LDX 020H             ;ZP       
           CPX #007H            ;         
           BCS L_57             ;         
           CMP 0FE00H,X         ;         
           BEQ L_58             ;         
           LDX #000H            ;         
           STX 021H             ;ZP       
L_58:      CMP #00AH            ;         
           BNE L_59             ;         
           LDX #000H            ;         
           STX 020H             ;ZP       
           INX                  ;         
           STX 021H             ;ZP       
L_59:      JMP L_44             ;JUMP     
           NOP                  ;         
L_57:      LDX 021H             ;ZP       
           CPX #000H            ;         
           BEQ L_58             ;         
           CMP #00AH            ;         
           BNE L_60             ;         
           LDX #000H            ;         
           STX 020H             ;ZP       
           INX                  ;         
           STX 021H             ;ZP       
L_60:      NOP                  ;         
           NOP                  ;         
           STA UART_data        ;         
           JMP L_61             ;JUMP     
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
string:    DFB 000H,024H,049H,049H,047H,047H,04CH,000H ;         
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
NMI_addr:  DFB 0FFH,0FFH        ;         
RES_addr:  DFB 000H,0F8H        ;         
IRQ_addr:  DFB 0FFH,0FFH        ;         
