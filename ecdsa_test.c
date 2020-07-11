#include <stdio.h>
#include <time.h> 
#include <math.h>
#include "ecc.h"
//#include "tt.h"


/* These variables will hold overall values for all rejection-sampling experiments*/
#define num_of_experiments  4
float overall_total_trials[num_of_experiments];
float overall_average_trials[num_of_experiments];
int overall_leaked_bits[num_of_experiments];
int overall_signs_for_32[num_of_experiments]; //12.5%
int overall_signs_for_64[num_of_experiments]; //25%
int overall_signs_for_96[num_of_experiments]; //37.5%
int overall_signs_for_128[num_of_experiments]; //50%
int overall_signs_for_160[num_of_experiments]; //62.5%
int overall_signs_for_192[num_of_experiments]; //75%
int overall_signs_for_224[num_of_experiments]; //224%
int overall_signs_for_256[num_of_experiments]; //256
/***************************************************************/

#define key_length 32

/*These variables are used for synthetic randomness test*/
uint8_t public_v[key_length+1]; 
uint8_t private_v[key_length];
uint8_t signature1[64],signature2[64];
uint8_t computed_key[32];
/******************************************************************************/



uint8_t publicKey[key_length+1]; 
uint8_t privateKey[key_length];

uint8_t m[32];
uint8_t signature[64];

static uint8_t x[32] = {107, 132, 35, 183, 57, 54, 149, 226, 177, 25, 211, 12 ,83, 124, 74, 129, 
		210, 103, 103, 10, 57, 79, 188, 47, 136, 9, 43, 212, 157, 127, 83, 211};

uint8_t leaked_key[32];


  
void delay(int number_of_seconds) 
{ 
    // Converting time into milli_seconds 
    int milli_seconds = 1000 * number_of_seconds; 
  
    // Storing start time 
    clock_t start_time = clock(); 
  
    // looping till required time is not achieved 
    while (clock() < start_time + milli_seconds) 
        ; 
} 


/*
This function generates a pair of keys for the attacker.
The public key is given to the (subverted) signer, so that it can be used to generate the synthetic randomness.
The private key is key (secretly) and used later to retrieve the signer's secret key.
*/
void generate_attacker_key()
{

	//printf("This is generate_attacker_key() \n");

	//generate a pair of keys for the attacker
	ecc_make_key(public_v,private_v);

	//pass it to the signer.
	set_public_v(public_v);

	/*
	printf("Private v: (");
	for(int i=0; i<32; i++) printf("%d ", private_v[i]);
	printf(").\n");
	printf("Public v: (");
	for(int i=0; i<33; i++) printf("%d ", public_v[i]);
	printf(").\n");
	*/
}



static void extract_bit(uint8_t sign[64])
{

	int index, byte_location, bit_location;
	int first_bit_in_r1, r1_xor_x, bit;

	index = sign[0];
	byte_location = index/8;
	bit_location = index%8;

	first_bit_in_r1 = sign[1] & 1; 

	r1_xor_x = first_bit_in_r1 ^ (x[1] & 1); 

	bit = r1_xor_x;
	//printf("leaked bit: %d.\n", bit);

	bit = bit<<bit_location;
	//printf("leaked bit (after shifting): %d.\n", bit);

	leaked_key[byte_location] = leaked_key[byte_location] | (bit & 0xff);

	/*printf("---------------------------------------------\n");
	printf("After this bit, leaked key is: (");
	for(int i=0; i<32; i++) printf("%x ", leaked_key[i]);
	printf(") \n");
	printf("---------------------------------------------\n");
	*/
	return;
}



static void sign_and_test(int experiment)
{
	int max_rounds = 3000;	
	int num_of_trials;
	float average_trials;

	int indices[256];
	int num_of_leaked_bits = 0;
	int leaked_index;
	int already_exist = 0;

	int number_of_sigs_for_128 = 0;
	int number_of_sigs_for_256 = 0;

	for(int i=0; i<256; i++) indices[i] = 0;
	for(int i=0; i<32; i++) leaked_key[i] = 0;

	printf("hello - this is ecdsa_test \n");
	
	if(ecc_make_key(publicKey,privateKey))
	{
		printf("ecc_make_key is successful - print private and public keys:\n");
		printf("private: ");
		for(int i=0; i<32; i++) printf("%d ", privateKey[i]);
		printf("\n");
		printf("public: ");
		for(int i=0; i<33; i++) printf("%d ", publicKey[i]);
		printf("\n");
	}
	else
	{
		printf("ecc_make_key is NOT successful.. \n");

		return;
	}


	printf("------------------------------------------------------------------------- \n");
	printf("------------------------------------------------------------------------- \n");



	/* ecdsa_sign() function.
	Generate an ECDSA signature for a given hash value.

	Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
	this function along with your private key.

	Inputs:
	    privateKey - Your private key.
	    m          - The message hash to sign.

	Outputs:
	    signature  - Will be filled in with the signature value.

	Returns 1 if the signature generated successfully, 0 if an error occurred.
	*/

	//initialize m
	for(int i=0; i<32; i++) m[i] = i;
	
	average_trials = 0;
	for(int i=0; i<max_rounds; i++)
	{
		//printf(".");

		num_of_trials = ecdsa_sign(privateKey, m, signature);
	
		//printf("Number of trials for (%d) was (%d) \n",i, num_of_trials);
		//printf("Produced signature: (");
		//for(int i=0; i<64; i++) printf("%x ", signature[i]);
		//printf(") \n");
		average_trials += num_of_trials;


		//check if this leaked bit already exists
		//signature[0] = r[0] = leaked index
		leaked_index = signature[0];
		//printf("Leaked index value in hex: %x.\n", leaked_index);
		already_exist = 0;
		for(int m=0; m<num_of_leaked_bits; m++)
		{
			if(indices[m] == leaked_index)
			{
				already_exist = 1;
				//printf("Leaked bit in round (%d) already exists. \n",i);
			}
		}
		if(!already_exist)
		{
			extract_bit(signature);

			indices[num_of_leaked_bits] = leaked_index;
			num_of_leaked_bits++;


			if(num_of_leaked_bits == 32)
			{
				overall_signs_for_32[experiment] = i;
			}
			else if(num_of_leaked_bits == 64)
			{
				overall_signs_for_64[experiment] = i;
			}
			else if(num_of_leaked_bits == 96)
			{
				overall_signs_for_96[experiment] = i;
			}
			else if(num_of_leaked_bits == 128)
			{
				overall_signs_for_128[experiment] = i;
			}
			else if(num_of_leaked_bits == 160)
			{
				overall_signs_for_160[experiment] = i;
			}
			else if(num_of_leaked_bits == 192)
			{
				overall_signs_for_192[experiment] = i;
			}
			else if(num_of_leaked_bits == 224)
			{
				overall_signs_for_224[experiment] = i;
			}
			else if(num_of_leaked_bits == 256)
		        {
				overall_signs_for_256[experiment] = i;
				break;
			}
		}
	}
	//printf(". \n");
	/*
	printf("Trials for all rounds (%f) and average trials per signature/round (%f) \n",average_trials, average_trials/max_rounds);
	printf("Number of leaked key bits: (%d) \n", num_of_leaked_bits);
	if(num_of_leaked_bits == 256) printf("Number of signs for full key: (%d). \n", number_of_sigs_for_256);

	if(num_of_leaked_bits >= 128) printf("Number of signs for 50 percent of key: (%d). \n", number_of_sigs_for_128);
	*/
	
	overall_total_trials[experiment] = average_trials;
	if(num_of_leaked_bits == 256)
	{
		overall_average_trials[experiment] = average_trials/overall_signs_for_256[experiment];
	}
	else
	{
		overall_average_trials[experiment] = average_trials/max_rounds;
	}
	
	overall_leaked_bits[experiment] = num_of_leaked_bits;
	//overall_signs_for_128[experiment] = number_of_sigs_for_128;
	//overall_signs_for_256[experiment] = number_of_sigs_for_256;
	/*
	printf("---------------------------------------------------------------------------------------------\n");
	printf("After this bit, leaked key is: (");
	for(int i=0; i<32; i++) printf("%x ", leaked_key[i]);
	printf(") \n");
	printf("---------------------------------------------------------------------------------------------\n");

	printf("---------------------------------------------------------------------------------------------\n");
	printf("private key: (");
	for(int i=0; i<32; i++) printf("%x ", privateKey[i]);
	printf(") \n");
	printf("---------------------------------------------------------------------------------------------\n");
	*/
	return;
}


void synthetic_randomness()
{
	printf("\nThis is synthetic_randomness_ecdsa \n");

	generate_attacker_key();


	//generate keys for signning.
	ecc_make_key(publicKey,privateKey);
	
	printf("Signer's private key: (");
	for(int i=0; i<32; i++) printf("%d ", privateKey[i]);
	printf(").\n");
	printf("Signer's public Key: (");
	for(int i=0; i<33; i++) printf("%d ", publicKey[i]);
	printf(").\n");
	

	//m: the message (m = H(message) to be specific).
	for(int i=0; i<32; i++) m[i] = i;

	/*first signature - ephemeral key should be stored. counter = 0*/
	ecdsa_sign_synthetic_randomness(0, privateKey, m, signature1);
	printf("Produced signature1: (");
	for(int i=0; i<64; i++) printf("%x ", signature1[i]);
	printf(") \n");

	
	
	/*second signature - ephemeral key is generated using previous ephemeral key and attacker's public key. counter = 1 */
	ecdsa_sign_synthetic_randomness(1, privateKey, m, signature2);
	printf("Produced signature2: (");
	for(int i=0; i<64; i++) printf("%x ", signature2[i]);
	printf(") \n");

	printf("\n^_^\n");
	printf("^_^\n\n");
	
	//test_retrieve_k(signature, m);
	//compute_z_with_public(computed_key);
	//compute_z_with_private(signature1, signature2, private_v);
	printf("After generating the two consecutive signatures, try to retrieve the signer's secret signing key with public information and the attacker's private key.\n");
	retrieve_private_key(signature1, signature2, m, private_v);

}



void rejection_sampling()
{
	


	for(int i=0; i<num_of_experiments; i++) sign_and_test(i);

	printf("\n");
	printf("\n");
	printf("**********************************************************************\n");
	for(int i=0; i<num_of_experiments; i++)
	{
		printf("These are the results for experiment (%d):\n", i);
		printf("The total number of trials/signature: %f. \n", overall_total_trials[i]); 
		printf("The average number of trials/signature: %f. \n", overall_average_trials[i]); 
		printf("The number of leaked bits: %d. \n", overall_leaked_bits[i]);
		printf("The number of signatures needed to leak 32 bits: %d. \n",overall_signs_for_32[i]);
		printf("The number of signatures needed to leak 64 bits: %d. \n",overall_signs_for_64[i]);
		printf("The number of signatures needed to leak 96 bits: %d. \n",overall_signs_for_96[i]);
		printf("The number of signatures needed to leak 128 bits: %d. \n",overall_signs_for_128[i]);
		printf("The number of signatures needed to leak 160 bits: %d. \n",overall_signs_for_160[i]);
		printf("The number of signatures needed to leak 192 bits: %d. \n",overall_signs_for_192[i]);
		printf("The number of signatures needed to leak 224 bits: %d. \n",overall_signs_for_224[i]);
		printf("The number of signatures needed to leak 256 bits: %d. \n",overall_signs_for_256[i]);
		printf("\n");
	}
	printf("**********************************************************************\n");


	//compute averages and display as table row
	float averages[8];
	for(int i=0; i<8; i++) averages[i] = 0;
	for(int i=0; i<num_of_experiments; i++)
	{
		averages[0] += overall_signs_for_32[i];
		averages[1] += overall_signs_for_64[i];
		averages[2] += overall_signs_for_96[i];
		averages[3] += overall_signs_for_128[i];
		averages[4] += overall_signs_for_160[i];
		averages[5] += overall_signs_for_192[i];
		averages[6] += overall_signs_for_224[i];
		averages[7] += overall_signs_for_256[i];
	}
	for(int i=0; i<8; i++) averages[i] = averages[i]/num_of_experiments;


	printf("**********************************************************************\n");
	printf("The average number of signatures needed to leak 32 bits: %f. \n",averages[0]);
	printf("The average number of signatures needed to leak 64 bits: %f. \n",averages[1]);
	printf("The average number of signatures needed to leak 96 bits: %f. \n",averages[2]);
	printf("The average number of signatures needed to leak 128 bits: %f. \n",averages[3]);
	printf("The average number of signatures needed to leak 160 bits: %f. \n",averages[4]);
	printf("The average number of signatures needed to leak 192 bits: %f. \n",averages[5]);
	printf("The average number of signatures needed to leak 224 bits: %f. \n",averages[6]);
	printf("The average number of signatures needed to leak 256 bits: %f. \n",averages[7]);
	printf("\n");
	printf("**********************************************************************\n");

	//compute standard deviations
	//sandard deviation = square_root((sum_1_to_N((element_i - average)^2))/N)
	float std_deviations[8];
	for(int i=0; i<8; i++) std_deviations[i] = 0;

	for(int i=0; i<num_of_experiments; i++)
	{
		std_deviations[0] += ((overall_signs_for_32[i] - averages[0])*(overall_signs_for_32[i] - averages[0]))/num_of_experiments;
		std_deviations[1] += ((overall_signs_for_64[i] - averages[1])*(overall_signs_for_64[i] - averages[1]))/num_of_experiments;
		std_deviations[2] += ((overall_signs_for_96[i] - averages[2])*(overall_signs_for_96[i] - averages[2]))/num_of_experiments;	
		std_deviations[3] += ((overall_signs_for_128[i] - averages[3])*(overall_signs_for_128[i] - averages[3]))/num_of_experiments;	
		std_deviations[4] += ((overall_signs_for_160[i] - averages[4])*(overall_signs_for_160[i] - averages[4]))/num_of_experiments;	
		std_deviations[5] += ((overall_signs_for_192[i] - averages[5])*(overall_signs_for_192[i] - averages[5]))/num_of_experiments;	
		std_deviations[6] += ((overall_signs_for_224[i] - averages[6])*(overall_signs_for_224[i] - averages[6]))/num_of_experiments;	
		std_deviations[7] += ((overall_signs_for_256[i] - averages[7])*(overall_signs_for_256[i] - averages[7]))/num_of_experiments;		
	}

	std_deviations[0] = sqrtf(std_deviations[0]);
	std_deviations[1] = sqrtf(std_deviations[1]);
	std_deviations[2] = sqrtf(std_deviations[2]);	
	std_deviations[3] = sqrtf(std_deviations[3]);	
	std_deviations[4] = sqrtf(std_deviations[4]);	
	std_deviations[5] = sqrtf(std_deviations[5]);	
	std_deviations[6] = sqrtf(std_deviations[6]);	
	std_deviations[7] = sqrtf(std_deviations[7]);


	printf("**********************************************************************\n");
	printf("Standard deviations from averages: \n");
	printf("For 32 bits: %f. \n",std_deviations[0]);
	printf("For 64 bits: %f. \n",std_deviations[1]);
	printf("For 96 bits: %f. \n",std_deviations[2]);
	printf("For 128 bits: %f. \n",std_deviations[3]);
	printf("For 160 bits: %f. \n",std_deviations[4]);
	printf("For 192 bits: %f. \n",std_deviations[5]);
	printf("For 224 bits: %f. \n",std_deviations[6]);
	printf("For 256 bits: %f. \n",std_deviations[7]);
	printf("\n");
	printf("**********************************************************************\n");
	
#if 0
	printf("\n\nSummarizing all results in latex table.\n");
	

	printf("**********************************************************************\n");
	for(int i=0; i<num_of_experiments; i++)
	{
		printf("%d & ", i+1);
		printf("%d & ",overall_signs_for_32[i]);
		printf("%d & ",overall_signs_for_64[i]);
		printf("%d & ",overall_signs_for_96[i]);
		printf("%d & ",overall_signs_for_128[i]);
		printf("%d & ",overall_signs_for_160[i]);
		printf("%d & ",overall_signs_for_192[i]);
		printf("%d & ",overall_signs_for_224[i]);
		printf("%d ",overall_signs_for_256[i]);		
		printf("%c%c \n", (char)0x5c, (char)0x5c);
		printf("%chline \n", (char)0x5c);
	}

	

	printf("%ctextbf{Average} ", (char)0x5c);
	for(int i=0; i<8; i++) printf("& %f ", averages[i]); 
	printf("%c%c \n", (char)0x5c, (char)0x5c);
	printf("%chline \n", (char)0x5c);
		
	

	printf("%ctextbf{SD} ", (char)0x5c);
	for(int i=0; i<8; i++) printf("& %f ", std_deviations[i]); 
	printf("%c%c \n", (char)0x5c, (char)0x5c);
	printf("%chline \n", (char)0x5c);

	printf("**********************************************************************\n");
#endif
	
}

int main(){


	int c;

	do
	{
		printf( "\nFor synthetic randomness test, enter: 1 \n");
		printf( "For rejection sampling test, enter: 2 \n");
		printf( "T exist, enter: 0 \n");
		
		do
		{
			c=getchar();
			
		}while(c == '\n');		
		
		//printf( "\nYou entered: %c \n", c);

		printf("\n");

		if(c == '1')
		{
			printf("You have chosen to run ECDSA with synthetic randomness \n");
			//printf("This may take few seconds - wait until (DONE). \n");
			synthetic_randomness();
			printf("\n\n\n(DONE) \n\n");
		}
		else if(c == '2')
		{
			printf("You have chosen to run ECDSA with rejection sampling. \n");
			printf("The num_of_experiments: %d. You can change this hard-coded value. \n", num_of_experiments);
			printf("This may take few seconds - wait until (DONE). \n");
			rejection_sampling();

			printf("\n\n\n(DONE) \n\n");
		}
		else if(c == '0')
		{
			printf("You have chosen to reminate this program. Bye! \n");
		}
		else
		{
			printf("You have entered an invalid choice. \n");
			
		}
	}while(c != '0');

	
	
	

	
#if 0
	/* ecdsa_verify() function.
	Verify an ECDSA signature.

	Usage: Compute the hash of the signed data using the same hash as the signer and
	pass it to this function along with the signer's public key and the signature values (r and s).

	Inputs:
	    publicKey - The signer's public key
	    m         - The hash of the signed data.
	    signature - The signature value.

	Returns 1 if the signature is valid, 0 if it is invalid.
	*/
	if(ecdsa_verify(publicKey, m, signature))
	{
		printf("ecdsa_verify is successful \n");
	}
	else
	{
		printf("ecdsa_verify is NOT successful \n");
		//return 0;
	}

	printf("---------------------------------------------\n");
	printf("Change one byte in (m) and try again \n");
	m[0] = 122;

	if(ecdsa_verify(publicKey, m, signature))
	{
		printf("ecdsa_verify is successful \n");
	}
	else
	{
		printf("ecdsa_verify is NOT successful \n");
		//return 0;
	}

	printf("---------------------------------------------\n");
	printf("Change back (m), and try again \n");
	m[0] = 0;

	if(ecdsa_verify(publicKey, m, signature))
	{
		printf("ecdsa_verify is successful \n");
	}
	else
	{
		printf("ecdsa_verify is NOT successful \n");
		//return 0;
	}
	
	printf("---------------------------------------------\n");
	printf("Change one byte in publicKey \n");

	publicKey[1] = publicKey[1] ^ 1;
	
	if(ecdsa_verify(publicKey, m, signature))
	{
		printf("ecdsa_verify is successful \n");
	}
	else
	{
		printf("ecdsa_verify is NOT successful \n");
		//return 0;
	}

	printf("---------------------------------------------\n");

	printf("Change back publicKey \n");

	publicKey[1] = publicKey[1] ^ 1;
	
	if(ecdsa_verify(publicKey, m, signature))
	{
		printf("ecdsa_verify is successful \n");
	}
	else
	{
		printf("ecdsa_verify is NOT successful \n");
		//return 0;
	}
	
#endif
	
	return 0;
}
