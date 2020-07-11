#include "prf.h"
#include <stdio.h>



uint8_t x[32] = {107, 132, 35, 183, 57, 54, 149, 226, 177, 25, 211, 12 ,83, 124, 74, 129, 
		210, 103, 103, 10, 57, 79, 188, 47, 136, 9, 43, 212, 157, 127, 83, 211};

int is_okay(uint8_t tmp_r[32], const uint8_t privateKey[32])
{
	int index;
	int byte_location, bit_location;
	int mask = 1;
	int byte_value, bit_value;
	int result;
	int first_bit_in_r1;
	int r1_xor_x;
	

	index = tmp_r[0];
	//printf("is_okay, index value in hex: %x.\n", index);

	byte_location = index/8;
	bit_location = index%8;

	//printf("Byte location is: %d, and bit location is: %d.\n", byte_location, bit_location);

	mask = mask << bit_location;
	//printf("Mask is: %d.\n", mask);

	byte_value = privateKey[byte_location];
	//printf("Corresponding byte in pkey in hex: %x, and decimal: %d.\n", byte_value, byte_value);

	bit_value = byte_value & mask;
	//printf("Corresponding bit in pkey in decimal (before shift): %d.\n", bit_value);

	bit_value = bit_value >> bit_location;
	//printf("Corresponding bit in pkey in decimal (after shift): %d.\n", bit_value);

	first_bit_in_r1 = tmp_r[1] & 1; 
	//printf("first_bit_in_r1: %d.\n", first_bit_in_r1);

	r1_xor_x = first_bit_in_r1 ^ (x[1] & 1); 
	//printf("r1_xor_x: %d.\n", r1_xor_x);
	
	if(r1_xor_x == bit_value)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
