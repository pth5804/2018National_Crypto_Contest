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

#define X8 R26 //R26
#define X9 R27 //R27
#define X10 R12 // new
#define X11 R13 // new
#define X12 R14 // new
#define X13 R15 // new
#define X14 R20 // new
#define X15 R21 // new

#define X18 R18
#define X19 R19

#define C0 R24 //R24
#define C1 R25 //R25

	CHAM_EncryptBlk:

	//First Round
	MOVW R26, R24	
	LD X0, X+ 		
	LD X1, X+ 		
	LD X2, X+ 		
	LD X3, X+ 		
	LD X4, X+ 		
	LD X5, X+ 		
	LD X6, X+ 		
	LD X7, X+	 	
	
	CLR C0			// clear register (R24)
	CLR ZERO		// clear register (R2)
	CLR R30			// clear register (R30)

	STEP1:
	MOVW X8, X0  // X[0]
	MOVW X10, X2 // X[1]
	MOVW X12, X4 // X[2] 
	
	MOVW X14, X6 // X[3]
	MOVW X18, X6 // X[3]

	//FIRST ROUND
	LSL X2
	ROL X3
	ADC X2, ZERO // ROTL16(PT[1], 1)

	EOR X8, C0 // PT[0] = PT[0] ^ I
	ANDI R30, 31  // SETTING R30 TO INPUT RK

	LPM C1, Z+ 
	EOR X2, C1	// X[1] = ROTL16(PT[1], 1) ^ RK

	LPM C1, Z+
	EOR X3, C1	// X[1] = ROTL16(PT[1], 1) ^ RK

	ADD X8, X2	// 
	ADC X9, X3

	INC C0
	MOV X1, X8 // 1ROUND no err
	MOV X0, X9

	//SECOND ROUND
	EOR X10, C0 // X[1] = X[1] ^ I

	LPM C1, Z+
	EOR X5, C1 // X[2] = ROTL16(PT[2], 8) ^ RK

	LPM C1, Z+
	EOR X4, C1 // X[2] = ROTL16(PT[2], 8) ^ RK

	ADD X10, X5
	ADC X11, X4

	INC C0

	LSL X10
	ROL X11
	ADC X10, ZERO
	
	MOVW X2, X10  // 2ROUND no err

	//THIRD ROUND
	LSL X14
	ROL X15
	ADC X14, ZERO // ROTL16(PT[3], 1)

	EOR X12, C0 // X[2] = X[2] ^ I

	LPM C1, Z+ 	
	EOR X14, C1	 // X[3] = ROTL16(PT[3], 1) ^ RK

	LPM C1, Z+
	EOR X15, C1	 // X[3] = ROTL16(PT[3], 1) ^ RK

	ADD X12, X14
	ADC X13, X15

	MOV X5, X12
	MOV X4, X13 // 3ROUND no err

	INC C0

	//FOURTH ROUND 
	EOR X18, C0 // X[3] = X[3] ^ I

	LPM C1, Z+
	EOR X8, C1  // X[0]

	LPM C1, Z+
	EOR X9, C1  // X[0]

	ADD X18, X8 // X[3] = X[3] + X[0]
	ADC X19, X9 // X[3] = X[3] + X[0]

	LSL X18 
	ROL X19
	ADC X18, ZERO // ROTL16(X[3], 1)

	MOVW X6, X18  // 4ROUND no err

	INC C0

	CPI C0, 80
	BRLT STEP1

	ST -X, X7		// Store Indirect and Pre-Dec
	ST -X, X6
	ST -X, X5
	ST -X, X4
	ST -X, X3
	ST -X, X2
	ST -X, X1
	ST -X, X0

	RET