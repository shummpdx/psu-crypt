#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint8_t shiftKey(int index, uint8_t * key, uint8_t highBit);
void generateSubkeys(uint8_t key[], uint8_t subkeys[][12]);
void printSubkeys(uint8_t subkeys[][12]);
bool plainToWords(char plaintext[], uint16_t words[4]);
void getR(uint16_t r[4], uint16_t words[4], uint8_t key[]);
uint8_t highBits(uint16_t r);
void fFunction(uint16_t r0, uint16_t r1, int round, uint8_t subkey[][12], uint16_t f0f1[2], bool set);
uint16_t g(uint16_t r, int round, uint8_t subkey[][12], int i, bool set);
uint16_t fTable(uint8_t value);
void encryption(uint16_t words[4], uint8_t key[10], uint8_t subkeys[][12], FILE *output, bool set);
void reverseSubkeys(uint8_t subkeys[][12], uint8_t reversedSubkeys[][12]);
void importKey(uint8_t finalKey[]);
void importCipher(char line[], uint16_t finalHex[], ssize_t nread);

uint8_t ascii_to_hex(char c);
//Previous function taken from: https://stackoverflow.com/questions/18693841/read-contents-of-a-file-as-hex-in-c

int main(int argc, char *argv[]){

    FILE *input = fopen("plaintext.txt", "rb");
    FILE *output = fopen("ciphertext.txt", "w");
    

    char plaintext[8];
    uint8_t subkeys[20][12];
    uint8_t reversedSubkeys[20][12];
    
    uint8_t key[10];
    
    size_t amount = 0;
    uint16_t finalHex[4];
    uint16_t words[4];
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    char response;

    do{

        printf("1. Encrypt\n");
        printf("2. Decrypt\n");
        printf("3. Exit\n");

        while((response = getchar()) == '\n');

        if(response == '1'){
            importKey(key);
            generateSubkeys(key, subkeys); 

            while((amount = fread(plaintext, 1, sizeof(plaintext), input)) == 8){
                plainToWords(plaintext, words);
                encryption(words, key, subkeys, output, false);
            }

            if(amount < 8 && amount > 0 && plaintext[0] != '\n'){
                for(int i = amount-1; i < 8; i++){
                    plaintext[i] = 0;
                }
                plainToWords(plaintext, words);
                encryption(words, key, subkeys, output, false);
            }

            fclose(output);
            fclose(input);
        }

        else if(response == '2'){
            FILE *file = fopen("ciphertext.txt", "rb");

            reverseSubkeys(subkeys, reversedSubkeys);

            while((nread = getline(&line, &len, file)) != -1){
                importCipher(line, finalHex, nread);
                encryption(finalHex, key, reversedSubkeys, output, true);
            }
        }

    }while(response != '3');

    return(0);
}

void importCipher(char line[], uint16_t finalHex[], ssize_t nread){
    
    
    uint8_t temp[8][2];
    uint8_t intercipher[8];

    int i = 0;
    int j = 0;

    for(int k = 0; k < nread-1; k++){ 
        temp[i][j] = ascii_to_hex(line[k]);
        j++;
        if(j == 2){
            i++;
            j = 0;
        }
    }

    for(int k = 0; k < 8; k++){
        intercipher[k] = ((uint16_t)temp[k][0] << 4 | temp[k][1]);
    }

    int m = 0;

    for(int k = 0; k < 8; k = k+2){
        finalHex[m] = ((uint16_t)intercipher[k] << 8 | intercipher[k+1]);
        m++;
    }

    printf("finalcipher = ");

    for(i = 0; i < 4; i++){
        printf("%x", finalHex[i]);
    }

    printf("\n");
}

void importKey(uint8_t finalKey[]){

    uint8_t key[10][2];
    char c; 
    int i = 0;
    int j = 0;
    FILE *fr = fopen ("key.txt", "r");

    c = fgetc(fr);
    c = fgetc(fr);

    while((c = fgetc(fr)) != EOF){
        key[i][j] = ascii_to_hex(c);
        j++;
        if(j == 2){
            i++;
            j = 0;
        }
    }

    for(int m = 0; m<10; m++){
        finalKey[m] = ((uint8_t)key[m][0] << 4 | key[m][1]);
    }
}

void reverseSubkeys(uint8_t subkeys[][12], uint8_t reversedSubkeys[][12]){
    int ii = 0;
    int jj = 0;

    for(int i = 19; i > -1; i--){
        for(int j = 0; j < 12; j++){
            reversedSubkeys[ii][jj] = subkeys[i][j];
            jj++;
        }
        ii++;
        jj = 0;
    }
}

void encryption(uint16_t words[], uint8_t key[10], uint8_t subkeys[][12], FILE *output, bool set){
    
    uint16_t r[4];
    uint16_t f0f1[2], r0, r1, r2, r3, temp, y0, y1, y2, y3;
    uint16_t keyvalue;
    uint8_t temp_characters[8];
    

    getR(r, words, key);

    r0 = r[0];
    r1 = r[1];
    r2 = r[2];
    r3 = r[3];

    for(int round = 0; round < 20; round++){
        
        fFunction(r0, r1, round, subkeys, f0f1, set);

        r2 ^= f0f1[0];
        r3 ^= f0f1[1];

        temp = r3;
        r3 = r1;
        r1 = temp;

        temp = r2;
        r2 = r0;
        r0 = temp;

        //printf("block = 0x%x%x%x%x\n", r0,r1,r2,r3);

        y0 = r2;
        y1 = r3;
        y2 = r0;
        y3 = r1;
       
        keyvalue = ((uint16_t)key[0] << 8 | key[1]);
        y0 ^= keyvalue;
        keyvalue = ((uint16_t)key[2] << 8 | key[3]);
        y1 ^= keyvalue;
        keyvalue = ((uint16_t)key[4] << 8 | key[5]);
        y2 ^= keyvalue;
        keyvalue = ((uint16_t)key[6] << 8 | key[7]);
        y3 ^= keyvalue;
    } 

    printf("ciphertext = %x %x %x %x\n", y0, y1, y2, y3);
    fprintf(output, "%x%x%x%x\n", y0, y1, y2, y3);

    if(set == true){
        temp_characters[0] = y0 >> 8;
        printf("%c", temp_characters[0]);
        temp_characters[1] = y0;
        printf("%c", temp_characters[1]);
        temp_characters[2] = y1 >> 8;
        printf("%c", temp_characters[2]);
        temp_characters[3] = y1;
        printf("%c", temp_characters[3]);
        temp_characters[4] = y2 >> 8;
        printf("%c", temp_characters[4]);
        temp_characters[5] = y2;
        printf("%c",temp_characters[5]);
        temp_characters[6] = y3 >> 8;
        printf("%c", temp_characters[6]);
        temp_characters[7] = y3;
        printf("%c\n", temp_characters[7]);
    }
}

void fFunction(uint16_t r0, uint16_t r1, int round, uint8_t subkey[][12], uint16_t f0f1[2], bool set){
    uint16_t t0, t1, fConcat, f0, f1;
    int power = pow(2,16);

    t0 = g(r0, round, subkey, 0, set);
    t1 = g(r1, round, subkey, 4, set);

    fConcat = (((uint16_t)subkey[round][8] << 8) | subkey[round][9]);
    f0 = (t0+(t1*2)+fConcat)%power;

    fConcat = (((uint16_t)subkey[round][10] << 8) | subkey[round][11]);
    f1 = ((2*t0)+(t1)+fConcat)%power;
    
    f0f1[0] = f0;
    f0f1[1] = f1;
}

uint8_t highBits(uint16_t r){
    uint16_t temp;
    temp = r << 8;
    return temp >>= 8;
}

uint16_t g(uint16_t r, int round, uint8_t subkey[][12], int i, bool set){
    uint8_t g1,g2,g3,g4,g5,g6;
    uint16_t g5g6;
    uint8_t r0, r1;

    r0 = r >> 8;
    r1 = highBits(r);
    
    g1 = r0; 
    g2 = r1;
    if(set){
        g3 = fTable(g2^subkey[round][i])^g1;
        g4 = fTable(g3^subkey[round][i+1])^g2;
        g5 = fTable(g4^subkey[round][i+2])^g3;
        g6 = fTable(g5^subkey[round][i+3])^g4;
    //printf("g's = %x %x %x %x %x %x\n", g1, g2, g3, g4, g5, g6);
        g5g6 = ((uint16_t)g5 << 8) | g6;
    }
    else{
        g3 = fTable(g2^subkey[round][i])^g1;
        g4 = fTable(g3^subkey[round][i+1])^g2;
        g5 = fTable(g4^subkey[round][i+2])^g3;
        g6 = fTable(g5^subkey[round][i+3])^g4;
    //printf("g's = %x %x %x %x %x %x\n", g1, g2, g3, g4, g5, g6);
        g5g6 = ((uint16_t)g5 << 8) | g6;
    }
    return g5g6;
}

uint16_t fTable(uint8_t value){
    uint8_t col, row;

    uint8_t fTable[16][16] = {
        {0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9},
        {0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28},
        {0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53},
        {0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2},
        {0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8},
        {0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90},
        {0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76},
        {0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d},
        {0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18},
        {0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4},
        {0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40},
        {0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5},
        {0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2},
        {0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8},
        {0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac},
        {0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46}
    };

    row = value >> 4;
    col = value << 4;
    col = col >> 4;
    
    return fTable[row][col];
}

void getR(uint16_t r[4], uint16_t words[4], uint8_t key[]){

    int k = 0;
    uint16_t keyConcat;
    for(int i = 0; i < 4; i++){
            keyConcat = ((uint16_t) key[k] << 8 | key[k+1]);
            //printf("keyConcat = %x\n", keyConcat);
            r[i] = words[i]^keyConcat;
            k+=2;
    }
}

bool plainToWords(char plaintext[], uint16_t words[4]){

    int k = 0;
    for(int i = 0; i < 4; i++){
        words[i] = ((uint16_t)plaintext[k] << 8 | plaintext[k+1]);
        k+=2;
    }

    return true;
}

void printSubkeys(uint8_t subkeys[][12]){

    for(int ii = 0; ii < 20; ii++){
        for(int i = 0; i < 12; i++){
            printf(" %x ", subkeys[ii][i]);
        }
        printf("\n");
    }
}

void generateSubkeys(uint8_t key[], uint8_t subkeys[][12]){

    uint8_t highBit;

    for(int i = 0; i < 20; i++){
        for(int ii = 0; ii < 12; ii++){
            highBit = key[0] >> 7;
            subkeys[i][ii] = shiftKey((4*i)+(ii%4), key, highBit);
        }
    }
}

uint8_t shiftKey(int index, uint8_t * key, uint8_t highBit){

    uint8_t pushedBit;
    uint8_t newKey[10];

    for(int i = 9, j = 0; i >= 0; i--, j++){
        pushedBit = key[i] >> 7;
        newKey[j] = key[i] <<= 1;
        newKey[j] = key[i] ^= highBit;
        highBit = pushedBit;
    }

    index = index % 10;

    return newKey[index];
}

//From: https://stackoverflow.com/questions/18693841/read-contents-of-a-file-as-hex-in-c
uint8_t ascii_to_hex(char c){
        uint8_t num = (uint8_t) c;

        if(num < 58 && num > 47)
        {
                return num - 48; 
        }
        if(num < 103 && num > 96)
        {
                return num - 87;
        }

        return num;

}
