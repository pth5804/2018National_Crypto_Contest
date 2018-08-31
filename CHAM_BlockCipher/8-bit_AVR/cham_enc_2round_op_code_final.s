	.global CHAM_EncryptBlk
	.type CHAM_EncryptBlk, @function
  
#define ZERO R2 //R2

#define X0 R4 //R4 --> no. 1
#define X1 R5 //R5 --> no. 0
#define X2 R6 //R6 --> no. 3
#define X3 R7 //R7 --> no. 2
#define X4 R8 //R8 --> no. 5  
#define X5 R9 //R9 --> no. 4  
#define X6 R10 //R10 --> no. 7 
#define X7 R11 //R11 --> no. 6 
#define X8 R26 
#define X9 R27 
#define C0 R24 
#define C1 R25 



	CHAM_EncryptBlk:

	MOVW R26, R24	
	LD X0, X+ 		// R20 <- X+1
	LD X1, X+ 		// R21 <- X+1
	LD X2, X+ 		// R22 <- X+1
	LD X3, X+ 		// R23 <- X+1
	LD X4, X+ 		// R0 <- X+1
	LD X5, X+ 		// R1 <- X+1
	LD X6, X+ 		// R18 <- X+1
	LD X7, X+	 	// R19 <- X+1
					// It means to load the PlainText from memory
	
	CLR C0			// clear register (R24)
	CLR ZERO		// clear register (R2)
	CLR R30			// clear register (R30)

	STEP1:			// rotation by offset
	//First Round
	MOVW X8, X2		// Copy register word X8 (R26) <- X2 (R22)

	LSL X2			// Logical Shift Left
	ROL X3			// Rotate Left Through Carry
	ADC X2, ZERO	// Add with Carry two Registers : X2 <- X2 + ZERO + C (Carry)

	EOR X0, C0	 	// Exclusive OR Registers : X0 <- X0 ^ C0
	ANDI R30, 31	// Logical AND Register and Constant : R30 <- R30 & 0x1F

	LPM C1, Z+		// Load Program Memory and Post-Inc : C1 <- Z+1
	EOR X2, C1	 	// Exclusive OR Registers : X2 <- X2 ^ C1

	LPM C1, Z+		// Load Program Memory and Post-Inc : C1 <- Z+1
	EOR X3, C1	 	// Exclusive OR Registers : X3 <- X3 ^ C1

	ADD X0, X2		// X0 <- X0 + X2
	ADC X1, X3		// Add with Carry two Registers : X1 <- X1 + X3 + C (Carry)

	INC C0			// C0++
	
	//Second Round
	MOVW X2, X4		// Copy register word X2 (R22) <- X4 (R0)
	EOR X8, C0		// Exclusive OR Registers : X8 <- X8 ^ C0

	LPM C1, Z+		// Load Program Memory and Post-Inc : C1 <- Z+1
	EOR X5, C1		// REVERSE : X5 <- X5 ^ C1

	LPM C1, Z+		// Load Program Memory and Post-Inc : C1 <- Z+1
	EOR X4, C1		// REVERSE : X4 <- X4 ^ C1

	ADD X8, X5		// REVERSE : X8 <- X8 + X5
	ADC X9, X4		// Add with Carry two Registers : X9 <- X9 + X4 + C (Carry)

	LSL X8			// Logical Shift Left
	ROL X9			// Rotate Left Through Carry
	ADC X8, ZERO	// Add with Carry two Registers : X8 <- X8 + ZERO + C (Carry)

	//register alignment
	MOV X4, X1		// Move Between Registers : X4 <- X1
	MOV X5, X0		// Move Between Registers : X5 <- X0

	MOVW X0, X2		// Copy register word X0 (R20) <- X2 (R22)
	MOVW X2, X6		// Copy register word X2 (R22) <- X6 (R18)
	MOVW X6, X8		// Copy register word X6 (R18) <- X8 (R26)

	INC C0			// C0++

	CPI C0, 80		// Compare Register with C0 to 80
	BRLT STEP1		// if C0 less than 80, then go to STEP1:
		
	ST -X, X7		// Store Indirect and Pre-Dec
	ST -X, X6
	ST -X, X5
	ST -X, X4
	ST -X, X3
	ST -X, X2
	ST -X, X1
	ST -X, X0
	
	RET