#ifndef CHAM_H
#define CHAM_H

#include <stdio.h>
#include <stdint.h>
#include <immintrin.h> // AVX2 SIMD




//AVX-2 SIMD
typedef __m256i	REGISTER;
#define LOAD(x)			_mm256_loadu_si256((REGISTER*)x)
#define STORE(x,y)		_mm256_storeu_si256((REGISTER*)x,y)
#define SET16(a)		_mm256_set1_epi16(a)
#define SET32(a)		_mm256_set1_epi32(a)
#define XOR(x,y)		_mm256_xor_si256(x,y)
#define OR(x,y)			_mm256_or_si256(x,y)
#define AND(x,y)		_mm256_and_si256(x,y)
#define SHIFT16_L(x,r)		_mm256_slli_epi16(x,r)
#define SHIFT16_R(x,r)		_mm256_srli_epi16(x,r)

#define ROT16_L(x,r)		OR(SHIFT16_L(x,r),SHIFT16_R(x,16-r))
#define ROT16_L8(x)		OR(SHIFT16_L(x,8),SHIFT16_R(x,8))
#define ROT16_L5(x)		OR(SHIFT16_L(x,5),SHIFT16_R(x,11))
#define ROT16_L1(x)		OR(SHIFT16_L(x,1),SHIFT16_R(x,15))
#define ROT16_L2(x)		OR(SHIFT16_L(x,2),SHIFT16_R(x,14))
#define ROT16_R(x,r)		OR(SHIFT16_R(x,r),SHIFT16_L(x,16-r))

#define ADD16(x,y)		_mm256_add_epi16(x,y)

#define SHIFT32_L(x,r)	_mm256_slli_epi32(x,r)
#define SHIFT32_R(x,r)	_mm256_srli_epi32(x,r)
#define ROT32_L(x,r)	OR(SHIFT32_L(x,r),SHIFT32_R(x,32-r))
#define ROT32_L8(x)	OR(SHIFT32_L(x,8),SHIFT32_R(x,24))
#define ROT32_L5(x)	OR(SHIFT32_L(x,5),SHIFT32_R(x,27))
#define ROT32_L2(x)	OR(SHIFT32_L(x,2),SHIFT32_R(x,30))
#define ROT32_L1(x)	OR(SHIFT32_L(x,1),SHIFT32_R(x,31))

#define ADD32(x,y)		_mm256_add_epi32(x,y)








/*============================== CHAM64/128 AVX2 version =========================================*/
/*============================== CHAM64/128 AVX2 version(Ref)=====================================*/
// CHAM 64/128 AVX2 ref version
void cham64_128_Enc_SIMD_16blocks(uint16_t key[], uint16_t plaintext[], uint16_t ciphertext[]){
	int i = 0;
	// AVX2 SIMD
	// AVX2 registers : 16 256-bit registers(YMM0-YMM15), 32 128-bit registers(XMM0-XMM31)
    	__m256i data1, data2, data3, data4;
	__m256i data5, data6, data7;
	
	data1 = LOAD(&plaintext[0]); // pt[0]
	data2 = LOAD(&plaintext[16]); // pt[1]
	data3 = LOAD(&plaintext[32]); // pt[2]
	data4 = LOAD(&plaintext[48]); // pt[3]

	for(i=0; i<80; i+=2){ //ROL1, ROL8, XOR, ADD(modular)
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT16_L1(data2);
		// Set roundkey[i%16]
		data6 = SET16(key[i%16]);
		// Set i as AVX2 register
		data7 = SET16((uint16_t)i);
		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ i
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD16(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;
		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT16_L8(data5);

		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT16_L8(data2);
		// Set roundkey[(i+1)%16]
		data6 = SET16(key[(i+1)%16]);
		// Set (i+1) as AVX2 register
		data7 = SET16((uint16_t)(i+1));
		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (i+1)
		data7 = XOR(data7, data1);
		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD16(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT16_L1(data5);
	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[16], data2);//256-bit
	STORE(&ciphertext[32], data3);//256-bit
	STORE(&ciphertext[48], data4);//256-bit
}


// CHAM 64/128 AVX2 ref version
void cham64_128_Enc_SIMD_32blocks(uint16_t key[], uint16_t plaintext[], uint16_t ciphertext[]){
	int i = 0;
	// AVX2 SIMD
	// AVX2 registers : 16 256-bit registers(YMM0-YMM15), 32 128-bit registers(XMM0-XMM31)
    	__m256i data1, data2, data3, data4;
	__m256i data5, data6, data7, data8;
	__m256i data9, data10, data11, data12;
	__m256i data13, data14;
	
	data1 = LOAD(&plaintext[0]); // pt[0]
	data2 = LOAD(&plaintext[16]); // pt[1]
	data3 = LOAD(&plaintext[32]); // pt[2]
	data4 = LOAD(&plaintext[48]); // pt[3]

	data8 = LOAD(&plaintext[64]); // pt[0]
	data9 = LOAD(&plaintext[80]); // pt[1]
	data10 = LOAD(&plaintext[96]); // pt[2]
	data11 = LOAD(&plaintext[112]); // pt[3]

	for(i=0; i<80; i+=2){ //ROL1, ROL8, XOR, ADD(modular)
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT16_L1(data2);
		data12 = ROT16_L1(data9);

		// Set roundkey[i%16]
		data6 = SET16(key[i%16]);


		// Set i as AVX2 register
		data7 = SET16((uint16_t)i);


		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ i
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD16(data5, data14);
		data12 = ADD16(data12, data13);


		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;

		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT16_L8(data5);
		data11 = ROT16_L8(data12);

		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT16_L8(data2);
		data12 = ROT16_L8(data9);

		// Set roundkey[(i+1)%16]
		data6 = SET16(key[(i+1)%16]);


		// Set (i+1) as AVX2 register
		data7 = SET16((uint16_t)(i+1));


		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);


		// pt[0] ^ (i+1)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD16(data5, data14);
		data12 = ADD16(data12, data13);



		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;


		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT16_L1(data5);
		data11 = ROT16_L1(data12);


	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[16], data2);//256-bit
	STORE(&ciphertext[32], data3);//256-bit
	STORE(&ciphertext[48], data4);//256-bit

	STORE(&ciphertext[64], data8);//256-bit
	STORE(&ciphertext[80], data9);//256-bit
	STORE(&ciphertext[96], data10);//256-bit
	STORE(&ciphertext[112], data11);//256-bit
}


/*============================== CHAM64/128 AVX2 version(Fast)====================================*/
// CHAM 64/128 AVX2 fast 16 blocks version
void cham64_128_Enc_SIMD_16blocks_Fast(uint16_t key[], uint16_t plaintext[], uint16_t ciphertext[]){
	int i = 0;
	// AVX2 SIMD
	// AVX2 registers : 16 256-bit registers(YMM0-YMM15), 32 128-bit registers(XMM0-XMM31)
    	__m256i data1, data2, data3, data4;
	__m256i data5, data6, data7, data8;
	
	data1 = LOAD(&plaintext[0]); // pt[0]
	data2 = LOAD(&plaintext[16]); // pt[1]
	data3 = LOAD(&plaintext[32]); // pt[2]
	data4 = LOAD(&plaintext[48]); // pt[3]

	for(i=0; i<20; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT16_L1(data2);
		// Set roundkey[4*i%16]
		data6 = SET16(key[(4*i)%16]);
		// Set 4*i as AVX2 register
		data7 = SET16((uint16_t)(4*i));
		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (4*i)
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD16(data5, data7);
		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT16_L8(data5);


		//ct[1]
		// ROL8(pt[2])
		data5 = ROT16_L8(data3);
		// Set roundkey[4*i+1%16]
		data6 = SET16(key[(4*i+1)%16]);
		// Set 4*i+1 as AVX2 register
		data7 = SET16((uint16_t)(4*i+1));
		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		// pt[1] ^ (4*i+1)
		data7 = XOR(data7, data2);
		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD16(data5, data7);
		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT16_L1(data5);


		// ct[2]
		// ROL1(pt[3])
		data5 = ROT16_L1(data4);
		// Set roundkey[4*i+2%16]
		data6 = SET16(key[(4*i+2)%16]);
		// Set 4*i+2 as AVX2 register
		data7 = SET16((uint16_t)(4*i+2));
		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		// pt[2] ^ (4*i+2)
		data7 = XOR(data7, data3);
		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD16(data5, data7);
		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT16_L8(data5);


		//ct[3]
		// ROL8(ct[0])
		data5 = ROT16_L8(data1);
		// Set roundkey[4*i+3%16]
		data6 = SET16(key[(4*i+3)%16]);
		// Set 4*i+3 as AVX2 register
		data7 = SET16((uint16_t)(4*i+3));
		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		// pt[3] ^ (4*i+3)
		data7 = XOR(data7, data4);
		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD16(data5, data7);
		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT16_L1(data5);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[16], data2);//256-bit
	STORE(&ciphertext[32], data3);//256-bit
	STORE(&ciphertext[48], data4);//256-bit
}


// CHAM 64/128 AVX2 Fast 32 blocks version
void cham64_128_Enc_SIMD_32blocks_Fast(uint16_t key[], uint16_t plaintext[], uint16_t ciphertext[]){
	int i = 0;
	// AVX2 SIMD
	// AVX2 registers : 16 256-bit registers(YMM0-YMM15), 32 128-bit registers(XMM0-XMM31)
    	__m256i data1, data2, data3, data4;
	__m256i data5, data6, data7, data8;
	__m256i data9, data10, data11, data12;
	__m256i data13, data14;
	
	data1 = LOAD(&plaintext[0]); // pt[0]
	data2 = LOAD(&plaintext[16]); // pt[1]
	data3 = LOAD(&plaintext[32]); // pt[2]
	data4 = LOAD(&plaintext[48]); // pt[3]

	data8 = LOAD(&plaintext[64]); // pt[0]
	data9 = LOAD(&plaintext[80]); // pt[1]
	data10 = LOAD(&plaintext[96]); // pt[2]
	data11 = LOAD(&plaintext[112]); // pt[3]

	for(i=0; i<20; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT16_L1(data2);
		data12 = ROT16_L1(data9);

		// Set roundkey[4*i%16]
		data6 = SET16(key[(4*i)%16]);

		// Set 4*i as AVX2 register
		data7 = SET16((uint16_t)(4*i));

		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ (4*i)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD16(data5, data14);
		data12 = ADD16(data12, data13);

		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT16_L8(data5);
		data8 = ROT16_L8(data12);




		//ct[1]
		// ROL8(pt[2])
		data5 = ROT16_L8(data3);
		data12 = ROT16_L8(data10);

		// Set roundkey[4*i+1%16]
		data6 = SET16(key[(4*i+1)%16]);

		// Set 4*i+1 as AVX2 register
		data7 = SET16((uint16_t)(4*i+1));

		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[1] ^ (4*i+1)
		data13 = XOR(data7, data2);
		data14 = XOR(data7, data9);

		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD16(data5, data13);
		data12 = ADD16(data12, data14);

		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT16_L1(data5);
		data9 = ROT16_L1(data12);





		// ct[2]
		// ROL1(pt[3])
		data5 = ROT16_L1(data4);
		data12 = ROT16_L1(data11);

		// Set roundkey[4*i+2%16]
		data6 = SET16(key[(4*i+2)%16]);

		// Set 4*i+2 as AVX2 register
		data7 = SET16((uint16_t)(4*i+2));

		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[2] ^ (4*i+2)
		data13 = XOR(data7, data3);
		data14 = XOR(data7, data10);

		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD16(data5, data13);
		data12 = ADD16(data12, data14);

		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT16_L8(data5);
		data10 = ROT16_L8(data12);



		//ct[3]
		// ROL8(ct[0])
		data5 = ROT16_L8(data1);
		data12 = ROT16_L8(data8);

		// Set roundkey[4*i+3%16]
		data6 = SET16(key[(4*i+3)%16]);

		// Set 4*i+3 as AVX2 register
		data7 = SET16((uint16_t)(4*i+3));

		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[3] ^ (4*i+3)
		data13 = XOR(data7, data4);
		data14 = XOR(data7, data11);

		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD16(data5, data13);
		data12 = ADD16(data12, data14);

		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT16_L1(data5);
		data11 = ROT16_L1(data12);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[16], data2);//256-bit
	STORE(&ciphertext[32], data3);//256-bit
	STORE(&ciphertext[48], data4);//256-bit

	STORE(&ciphertext[64], data8);//256-bit
	STORE(&ciphertext[80], data9);//256-bit
	STORE(&ciphertext[96], data10);//256-bit
	STORE(&ciphertext[112], data11);//256-bit
}











/*============================== CHAM128/128 AVX2 version =======================================*/
/*============================== CHAM128/128 AVX2 version(Ref)===================================*/
// CHAM 128/128 AVX2 ref with 8 blocks
void cham128_128_Enc_SIMD_8blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	for(i=0; i<80; i+=2){
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		// Set roundkey[i%16]
		data6 = SET32((uint32_t)key[i%8]);
		// Set i as AVX2 register
		data7 = SET32((uint32_t)i);
		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ i
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;
		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT32_L8(data5);

		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT32_L8(data2);
		// Set roundkey[(i+1)%16]
		data6 = SET32((uint32_t)key[(i+1)%8]);
		// Set (i+1) as AVX2 register
		data7 = SET32((uint32_t)(i+1));
		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (i+1)
		data7 = XOR(data7, data1);
		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD32(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT32_L1(data5);
	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

}



// CHAM 128/128 AVX2 ref with 16 blocks
void cham128_128_Enc_SIMD_16blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7, data8;
    	__m256i data9, data10, data11, data12;
    	__m256i data13, data14, data15, data16;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	data8 = LOAD(&plaintext[32]); 	// pt[0]
	data9 = LOAD(&plaintext[40]); 	// pt[1]
	data10 = LOAD(&plaintext[48]); 	// pt[2]
	data11 = LOAD(&plaintext[56]); 	// pt[3]

	for(i=0; i<80; i+=2){
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		data12 = ROT32_L1(data9);


		// Set roundkey[i%16]
		data6 = SET32((uint32_t)key[i%8]);


		// Set i as AVX2 register
		data7 = SET32((uint32_t)i);


		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);


		// pt[0] ^ i
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data1);


		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);



		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;

		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT32_L8(data5);
		data11 = ROT32_L8(data12);



		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT32_L8(data2);
		data12 = ROT32_L8(data9);

		// Set roundkey[(i+1)%16]
		data6 = SET32((uint32_t)key[(i+1)%8]);


		// Set (i+1) as AVX2 register
		data7 = SET32((uint32_t)(i+1));


		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ (i+1)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);



		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;


		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT32_L1(data5);
		data11 = ROT32_L1(data12);


	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

	STORE(&ciphertext[32], data8);//256-bit
	STORE(&ciphertext[40], data9);//256-bit
	STORE(&ciphertext[48], data10);//256-bit
	STORE(&ciphertext[56], data11);//256-bit

}



/*============================== CHAM128/128 AVX2 version(Fast)==================================*/
// CHAM 128/128 AVX2 Fast with 8 blocks
void cham128_128_Enc_SIMD_8blocks_Fast(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	for(i=0; i<20; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		// Set roundkey[4*i%16]
		data6 = SET32(key[(4*i)%8]);
		// Set 4*i as AVX2 register
		data7 = SET32((uint32_t)(4*i));
		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (4*i)
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data7);
		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT32_L8(data5);


		//ct[1]
		// ROL8(pt[2])
		data5 = ROT32_L8(data3);
		// Set roundkey[4*i+1%16]
		data6 = SET32(key[(4*i+1)%8]);
		// Set 4*i+1 as AVX2 register
		data7 = SET32((uint32_t)(4*i+1));
		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		// pt[1] ^ (4*i+1)
		data7 = XOR(data7, data2);
		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD32(data5, data7);
		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT32_L1(data5);


		// ct[2]
		// ROL1(pt[3])
		data5 = ROT32_L1(data4);
		// Set roundkey[4*i+2%16]
		data6 = SET32(key[(4*i+2)%8]);
		// Set 4*i+2 as AVX2 register
		data7 = SET32((uint32_t)(4*i+2));
		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		// pt[2] ^ (4*i+2)
		data7 = XOR(data7, data3);
		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD32(data5, data7);
		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT32_L8(data5);


		//ct[3]
		// ROL8(ct[0])
		data5 = ROT32_L8(data1);
		// Set roundkey[4*i+3%16]
		data6 = SET32(key[(4*i+3)%8]);
		// Set 4*i+3 as AVX2 register
		data7 = SET32((uint32_t)(4*i+3));
		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		// pt[3] ^ (4*i+3)
		data7 = XOR(data7, data4);
		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD32(data5, data7);
		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT32_L1(data5);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

}



// CHAM 128/128 AVX2 fast with 16 blocks
void cham128_128_Enc_SIMD_16blocks_Fast(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7, data8;
    	__m256i data9, data10, data11, data12;
    	__m256i data13, data14, data15, data16;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	data8 = LOAD(&plaintext[32]); 	// pt[0]
	data9 = LOAD(&plaintext[40]); 	// pt[1]
	data10 = LOAD(&plaintext[48]); 	// pt[2]
	data11 = LOAD(&plaintext[56]); 	// pt[3]

	for(i=0; i<20; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		data12 = ROT32_L1(data9);

		// Set roundkey[4*i%16]
		data6 = SET32(key[(4*i)%8]);

		// Set 4*i as AVX2 register
		data7 = SET32((uint32_t)(4*i));

		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ (4*i)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);

		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT32_L8(data5);
		data8 = ROT32_L8(data12);

		//ct[1]
		// ROL8(pt[2])
		data5 = ROT32_L8(data3);
		data12 = ROT32_L8(data10);

		// Set roundkey[4*i+1%16]
		data6 = SET32(key[(4*i+1)%8]);

		// Set 4*i+1 as AVX2 register
		data7 = SET32((uint32_t)(4*i+1));

		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[1] ^ (4*i+1)
		data13 = XOR(data7, data2);
		data14 = XOR(data7, data9);

		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT32_L1(data5);
		data9 = ROT32_L1(data12);

		// ct[2]
		// ROL1(pt[3])
		data5 = ROT32_L1(data4);
		data12 = ROT32_L1(data11);

		// Set roundkey[4*i+2%16]
		data6 = SET32(key[(4*i+2)%8]);

		// Set 4*i+2 as AVX2 register
		data7 = SET32((uint32_t)(4*i+2));

		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[2] ^ (4*i+2)
		data13 = XOR(data7, data3);
		data14 = XOR(data7, data10);

		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT32_L8(data5);
		data10 = ROT32_L8(data12);


		//ct[3]
		// ROL8(ct[0])
		data5 = ROT32_L8(data1);
		data12 = ROT32_L8(data8);

		// Set roundkey[4*i+3%16]
		data6 = SET32(key[(4*i+3)%8]);

		// Set 4*i+3 as AVX2 register
		data7 = SET32((uint32_t)(4*i+3));

		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[3] ^ (4*i+3)
		data13 = XOR(data7, data4);
		data14 = XOR(data7, data11);

		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT32_L1(data5);
		data11 = ROT32_L1(data12);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

	STORE(&ciphertext[32], data8);//256-bit
	STORE(&ciphertext[40], data9);//256-bit
	STORE(&ciphertext[48], data10);//256-bit
	STORE(&ciphertext[56], data11);//256-bit

}









/*============================== CHAM128/256 AVX2 version ===================================*/
/*============================== CHAM128/256 AVX2 version(Ref) ==============================*/
// CHAM 128/256 AVX2 ref with 8 blocks
void cham128_256_Enc_SIMD_8blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	for(i=0; i<96; i+=2){
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		// Set roundkey[i%16]
		data6 = SET32((uint32_t)key[i%16]);
		// Set i as AVX2 register
		data7 = SET32((uint32_t)i);
		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ i
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;
		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT32_L8(data5);

		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT32_L8(data2);
		// Set roundkey[(i+1)%16]
		data6 = SET32((uint32_t)key[(i+1)%16]);
		// Set (i+1) as AVX2 register
		data7 = SET32((uint32_t)(i+1));
		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (i+1)
		data7 = XOR(data7, data1);
		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD32(data5, data7);

		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT32_L1(data5);
	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

}


// CHAM 128/256 AVX2 ref with 16 blocks
void cham128_256_Enc_SIMD_16blocks(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

    	__m256i data8, data9, data10, data11;
    	__m256i data12, data13, data14, data15;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	data8 = LOAD(&plaintext[32]); 	// pt[0]
	data9 = LOAD(&plaintext[40]); 	// pt[1]
	data10 = LOAD(&plaintext[48]); 	// pt[2]
	data11 = LOAD(&plaintext[56]); 	// pt[3]


	for(i=0; i<96; i+=2){
		// [ODD round]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		data12 = ROT32_L1(data9);

		// Set roundkey[i%16]
		data6 = SET32((uint32_t)key[i%16]);


		// Set i as AVX2 register
		data7 = SET32((uint32_t)i);


		// ROL1(x[1]) ^ RK[i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);


		// pt[0] ^ i
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);


		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);


		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;

		
		//ct[3] = ROL8 ( (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i) )
		data4 = ROT32_L8(data5);
		data11 = ROT32_L8(data12);


		// [EVEN round]
		// ROL8(pt[1])
		data5 = ROT32_L8(data2);
		data12 = ROT32_L8(data9);


		// Set roundkey[(i+1)%16]
		data6 = SET32((uint32_t)key[(i+1)%16]);


		// Set (i+1) as AVX2 register
		data7 = SET32((uint32_t)(i+1));


		// ROL8(pt[1]) ^ RK[(i+1)%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ (i+1)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);


		// (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1))
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);



		// pt[0] <- pt[1], pt[1] <- pt[2], pt[2] <- pt[3]
		data1 = data2;
		data2 = data3;
		data3 = data4;

		data8 = data9;
		data9 = data10;
		data10 = data11;


		// ct[3] = ROL1( (ROL8(pt[1]) ^ RK[(i+1)%16]) + (pt[0] ^ (i+1)) )
		data4 = ROT32_L1(data5);
		data11 = ROT32_L1(data12);


	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit


	STORE(&ciphertext[32], data8);//256-bit
	STORE(&ciphertext[40], data9);//256-bit
	STORE(&ciphertext[48], data10);//256-bit
	STORE(&ciphertext[56], data11);//256-bit

}


/*============================== CHAM128/256 AVX2 version(Fast) ================================*/
// CHAM 128/256 AVX2 Fast with 8 blocks
void cham128_256_Enc_SIMD_8blocks_Fast(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	for(i=0; i<24; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		// Set roundkey[4*i%16]
		data6 = SET32(key[(4*i)%16]);
		// Set 4*i as AVX2 register
		data7 = SET32((uint32_t)(4*i));
		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		// pt[0] ^ (4*i)
		data7 = XOR(data7, data1);
		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data7);
		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT32_L8(data5);


		//ct[1]
		// ROL8(pt[2])
		data5 = ROT32_L8(data3);
		// Set roundkey[4*i+1%16]
		data6 = SET32(key[(4*i+1)%16]);
		// Set 4*i+1 as AVX2 register
		data7 = SET32((uint32_t)(4*i+1));
		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		// pt[1] ^ (4*i+1)
		data7 = XOR(data7, data2);
		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD32(data5, data7);
		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT32_L1(data5);


		// ct[2]
		// ROL1(pt[3])
		data5 = ROT32_L1(data4);
		// Set roundkey[4*i+2%16]
		data6 = SET32(key[(4*i+2)%16]);
		// Set 4*i+2 as AVX2 register
		data7 = SET32((uint32_t)(4*i+2));
		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		// pt[2] ^ (4*i+2)
		data7 = XOR(data7, data3);
		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD32(data5, data7);
		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT32_L8(data5);


		//ct[3]
		// ROL8(ct[0])
		data5 = ROT32_L8(data1);
		// Set roundkey[4*i+3%16]
		data6 = SET32(key[(4*i+3)%16]);
		// Set 4*i+3 as AVX2 register
		data7 = SET32((uint32_t)(4*i+3));
		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		// pt[3] ^ (4*i+3)
		data7 = XOR(data7, data4);
		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD32(data5, data7);
		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT32_L1(data5);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit

}


// CHAM 128/256 AVX2 Fast with 16 blocks
void cham128_256_Enc_SIMD_16blocks_Fast(uint32_t key[], uint32_t plaintext[], uint32_t ciphertext[]){
	int i = 0;
	//AVX2 SIMD 256-bit = 32-bit * 8
    	__m256i data1, data2, data3, data4;
    	__m256i data5, data6, data7;

    	__m256i data8, data9, data10, data11;
    	__m256i data12, data13, data14, data15;

	data1 = LOAD(&plaintext[0]); 	// pt[0]
	data2 = LOAD(&plaintext[8]); 	// pt[1]
	data3 = LOAD(&plaintext[16]); 	// pt[2]
	data4 = LOAD(&plaintext[24]); 	// pt[3]

	data8 = LOAD(&plaintext[32]); 	// pt[0]
	data9 = LOAD(&plaintext[40]); 	// pt[1]
	data10 = LOAD(&plaintext[48]); 	// pt[2]
	data11 = LOAD(&plaintext[56]); 	// pt[3]


	for(i=0; i<24; i++){ //ROL1, ROL8, XOR, ADD(modular)
		// ct[0]
		// ROL1(pt[1])
		data5 = ROT32_L1(data2);
		data12 = ROT32_L1(data9);

		// Set roundkey[4*i%16]
		data6 = SET32(key[(4*i)%16]);

		// Set 4*i as AVX2 register
		data7 = SET32((uint32_t)(4*i));

		// ROL1(x[1]) ^ RK[4*i%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[0] ^ (4*i)
		data14 = XOR(data7, data1);
		data13 = XOR(data7, data8);

		// (ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i)
		data5 = ADD32(data5, data14);
		data12 = ADD32(data12, data13);

		// ct[0] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data1 = ROT32_L8(data5);
		data8 = ROT32_L8(data12);

		//ct[1]
		// ROL8(pt[2])
		data5 = ROT32_L8(data3);
		data12 = ROT32_L8(data10);

		// Set roundkey[4*i+1%16]
		data6 = SET32(key[(4*i+1)%16]);

		// Set 4*i+1 as AVX2 register
		data7 = SET32((uint32_t)(4*i+1));

		// ROL8(pt[2]) ^ RK[4*i+1%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[1] ^ (4*i+1)
		data13 = XOR(data7, data2);
		data14 = XOR(data7, data9);

		// (ROL8(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1))
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[1] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data2 = ROT32_L1(data5);
		data9 = ROT32_L1(data12);

		// ct[2]
		// ROL1(pt[3])
		data5 = ROT32_L1(data4);
		data12 = ROT32_L1(data11);

		// Set roundkey[4*i+2%16]
		data6 = SET32(key[(4*i+2)%16]);

		// Set 4*i+2 as AVX2 register
		data7 = SET32((uint32_t)(4*i+2));

		// ROL1(pt[3]) ^ RK[4*i+2%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[2] ^ (4*i+2)
		data13 = XOR(data7, data3);
		data14 = XOR(data7, data10);

		// (ROL1(pt[3]) ^ RK[4*i+2%16]) + (pt[2] ^ 4*i+2)
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[2] = ROL8((ROL1(x[1]) ^ RK[i%16]) + (pt[0] ^ i))
		data3 = ROT32_L8(data5);
		data10 = ROT32_L8(data12);


		//ct[3]
		// ROL8(ct[0])
		data5 = ROT32_L8(data1);
		data12 = ROT32_L8(data8);

		// Set roundkey[4*i+3%16]
		data6 = SET32(key[(4*i+3)%16]);

		// Set 4*i+3 as AVX2 register
		data7 = SET32((uint32_t)(4*i+3));

		// ROL8(ct[0]) ^ RK[4*i+3%16]
		data5 = XOR(data5, data6);
		data12 = XOR(data12, data6);

		// pt[3] ^ (4*i+3)
		data13 = XOR(data7, data4);
		data14 = XOR(data7, data11);

		// (ROL8(ct[0]) ^ RK[4*i+3%16]) + (pt[3] ^ (4*i+3))
		data5 = ADD32(data5, data13);
		data12 = ADD32(data12, data14);

		// ct[3] = ROL1((ROL1(pt[2]) ^ RK[4*i+1%16]) + (pt[1] ^ (4*i+1)))
		data4 = ROT32_L1(data5);
		data11 = ROT32_L1(data12);
		

	}

	STORE(&ciphertext[0], data1);//256-bit
	STORE(&ciphertext[8], data2);//256-bit
	STORE(&ciphertext[16], data3);//256-bit
	STORE(&ciphertext[24], data4);//256-bit


	STORE(&ciphertext[32], data8);//256-bit
	STORE(&ciphertext[40], data9);//256-bit
	STORE(&ciphertext[48], data10);//256-bit
	STORE(&ciphertext[56], data11);//256-bit

}




#endif
