#define _CRT_SECURE_NO_WARNINGS
#include <iostream> //standard library for i/o
#include <string>  //strings
#include <stdlib.h>
#include <vector> //for vectors
#include <cmath>//power
#include <bitset>//decimal to binary
#include "BigInt.hpp"
#include <algorithm>
using namespace std;
string MillerRabin (BigInt p, int t, int &s, BigInt &r); //primality test
string MillerRabin2 (BigInt p, int t, int &s2, BigInt &r2); //primality test
void primeFact (BigInt p,int &s, BigInt &r); //to get the values for miller rabin
void primeFact2 (BigInt p,int &s2, BigInt &r2);
BigInt modExp (BigInt base, BigInt exp, BigInt modulus); //modular exponention mod p
BigInt modExp2 (BigInt base, BigInt exp, BigInt modulus);
BigInt modExpRSA (BigInt base, BigInt exp, BigInt modulus);
BigInt RSAe (BigInt n, BigInt e, BigInt Ksym);
BigInt RSAd (BigInt Kmaster, BigInt n, BigInt d);
vector<BigInt> eea(BigInt e,BigInt phi);
string decToBin (BigInt &a); //decimal to binary conversion for modular exponentiation
string decToBin2(BigInt Ksym);
string decToBinR2 (BigInt &r2);
string decToBinfree (BigInt Ksym);
//---Symmetric---
void keySchedule(string masterKey);
void reverseKeySchedule(string masterKey);
string des(string message);
string desReceiver(string message);
//global arrays for keys
string keys[16];
string reversekeys[16];
//helpers
string circle1 (string s);
string circle2(string s);
string desDecToBin(int dec);
int desBinToDec(string bin);
string XOR(string a, string b);


// n = pq
// phi = (p-1)(q-1)
// 1<e<phi gcd(e,phi)=1
// 1<d<phi e*d=1(mod phi)
// (n,e) are public, d is private
int main ()
{
        string isPrime = "";
        BigInt p;
        BigInt q;
        BigInt n;
        BigInt phi=2;
        BigInt d=2;//multiplicaitve inverse of emod(phi)
        BigInt e=4;
        int t = 100; //security parameter miller rabin
        int s;
        int s2;
        string str;//to find digits in phi
        BigInt r;
        BigInt r2;
        BigInt res;
    while((d*e)%phi != 1)
    {
        //generate large p and q
        while(isPrime != "prime")
        {
            p = big_random(20);
            if(p%2 == 0)
            {
                p+=1;
            }
            isPrime = MillerRabin(p,t,s,r);
        }
        isPrime ="";
        while(isPrime != "prime")
        {
            q = big_random(20);
            if(q%2 == 0)
            {
                q+=1;
            }
            isPrime = MillerRabin2(q,t,s2,r2);
        }
        cout<<p;
        n = p*q;
        phi = (p-1)*(q-1);
        //number of digits in phi
        str = phi.to_string();
        int numdigits = int(str.length());
        //generate random number "e" coprime to phi
        while(res !=1)
        {
            e = big_random(numdigits);
            while(e >= phi || e <= 1)
            {
                e = big_random(numdigits);
            }
            res = gcd(e,phi);
        }
        cout<<endl<<e<<endl;
        cout<<endl<<phi<<endl;
        //find "d" multiplicative inverse of e
        vector<BigInt> v = eea(phi, e); //d will be Kpriv
        cout<<"s"<<v[0]<<endl;
        cout<<"t"<<v[1]<<endl;
        for(int i = 0; i < 2; i++)
        {
            if(v[i] < 0)
                v[i]*=(-1);
        }
        for(int i = 0; i < 2; i++)
        {
            if((v[i]*e)%phi == 1)
                d = v[i];
        }
    }
    //(n,e) is public
    cout<<"public key: ("<<n<<", "<<e<<")"<<"\n";
    cout<<"private key: "<<d<<"\n";
    //generate random symmetric key
    BigInt Ksym;
    Ksym = "12336079032971605074";//this will be a symmetric key used by sender
    BigInt Kmaster = RSAe(n, e, Ksym); //(n,e) used by sender to encrypt Ksym
    BigInt KsymReceiver = RSAd(Kmaster, n, d); //d used by reciever to decrypt Kmaster and get back Ksym
    cout<<endl<<"\nsecret sym key: "<<Ksym<<endl;
    cout<<endl<<"\ncipher secret key, to be sent to receiver: "<<Kmaster<<endl;
    cout<<endl<<"\nreceiver decrypts cipher to get this secret key: "<<KsymReceiver<<endl;
    //now, for future messages, the Ksym can be used to encrypt messages to be sent to reciever
    string masterKey = decToBinfree(Ksym);
    cout<<masterKey<<endl;
    //---Symmetric------
    keySchedule(masterKey); //key generation
    string message = "1010101100110010100011101000010101101001011010101011010001010010";
    cout<<"\nthis is the message sender wants to send:\n"<<message<<endl;
    
    string ct = des(message);
    cout<<"\nthis ciphertext is sent to receiver:\n"<<ct<<endl;
    //here the receiver uses their secret key to generate reverse order of key schedule
    //reverseKeySchedule(masterKey);
    int startIndex = 15;
    int revIndex = 0;
    string temp="";
    while(startIndex > revIndex)
    {
        temp = keys[startIndex];
        keys[startIndex] = keys[revIndex];
        keys[revIndex] = temp;
        startIndex--;
        revIndex++;
    }
    string pt = des(ct);
    cout<<"\nreceiver now decrypts using des and has the message:\n"<<pt<<"\n\n"<<endl;
    
    
    
}
//extended euclidian---------
vector<BigInt> eea(BigInt a, BigInt b)
{
    vector<BigInt>st;
    BigInt s = 0;
    BigInt old_s = 1;
    BigInt t = 1;
    BigInt old_t = 0;
    BigInt r = b;
    BigInt old_r = a;
    BigInt temp1 = 0;
    BigInt temp2 = 0;
    BigInt temp3 = 0;
    while(r!=0)
    {
        BigInt q = old_r/r ;
        temp1 = old_r;
        old_r = r;
        //r = old_r - q * r ;
        r = (temp1 - q * r);
        temp2 = old_s;
        old_s = s;
        //s = old_s - q * s;
        s = temp2 - q * s;
        temp3 = old_t;
        old_t = t;
        //t = old_t - q * t;
        t = temp3 - q * t;
    }
    //old_r is gcd
    //old_t is multiplicative inverse
    st.push_back(old_t);
    st.push_back(old_s);
    return st;
}
//rsa for encryption---------------------------
BigInt RSAe (BigInt n, BigInt e, BigInt Ksym)
{
    BigInt Kmaster;
    Kmaster = modExpRSA(Ksym, e, n);
    return Kmaster;
}
//rsa for decryption---------------------
BigInt RSAd (BigInt Kmaster, BigInt n, BigInt d)
{
    BigInt Ksym;
    Ksym = modExpRSA(Kmaster, d, n);
    return Ksym;
}
//primality checker-----------------------------------
string MillerRabin (BigInt p, int t, int &s, BigInt &r)
{
    string prime = "prime";
    string composite = "composite";
    //get s and r using prime factorization
    primeFact(p,s,r);
    for(int i = 0; i < t; i++)
    {
        //Generate a random a in the range 2 <= a <= p-2
        srand((unsigned)time(0));
        BigInt a = (rand() % (p-1)-2+1)+2;
        //modular exponentiation
        BigInt y = modExp(a,r,p); //y = a^r(mod p)
        if((y != 1) && (y != (p-1)))
        {
            int j = 1;
            while((j <= (s-1)) && (y != (p-1)))
            {
                y = pow(y,2);
                y = y%p;
                if(y == 1)
                {
                    return composite;
                }
                j++;
            }
            if(y != (p-1))
            {
                return composite;
            }
        }
    }
    return prime;
}
string MillerRabin2 (BigInt p, int t, int &s2, BigInt &r2)
{
    string prime = "prime";
    string composite = "composite";
    //get s and r using prime factorization
    primeFact2(p,s2,r2);
    for(int i = 0; i < t; i++)
    {
        //Generate a random a in the range 2 <= a <= p-2
        srand((unsigned)time(0));
        BigInt a = (rand() % (p-1)-2+1)+2;
        //modular exponentiation
        BigInt y = modExp2(a,r2,p); //y = a^r(mod p)
        if((y != 1) && (y != (p-1)))
        {
            int j = 1;
            while((j <= (s2-1)) && (y != (p-1)))
            {
                y = pow(y,2);
                y = y%p;
                if(y == 1)
                {
                    return composite;
                }
                j++;
            }
            if(y != (p-1))
            {
                return composite;
            }
        }
    }
    return prime;
}
//prime fact------------------------------
void primeFact (BigInt p,int &s, BigInt &r)
{
    BigInt temp;
    s = 0;
    r=0;
    temp = p - 1;
    while(temp % 2 == 0)
    {
        s = s+1;
        temp = temp/2;
    }
    r = temp;
}
void primeFact2 (BigInt p,int &s2, BigInt &r2)
{
    BigInt temp;
    s2 = 0;
    r2=0;
    temp = p - 1;
    while(temp % 2 == 0)
    {
        s2 = s2+1;
        temp = temp/2;
    }
    r2 = temp;
}
//modular exponentiation--------------------------
BigInt modExp (BigInt base, BigInt exp, BigInt modulus)
{
    string K = decToBin(exp);
    BigInt b = 1;
    if(K == "0")
    {
        return b;
    }
    BigInt A = base;
    if(K[0] == '1')
    {
        b = base;
    }
    for(int i = 1; i < K.length(); i++)
    {
        A = pow(A,2);
        A = A%modulus;
        if(K[i] == '1')
        {
            b = (A * b)%modulus;
        }
    }
    return b;
}
//modular exponentiation--------------------------
BigInt modExp2 (BigInt base, BigInt exp, BigInt modulus)
{
    string K = decToBinR2(exp);
    BigInt b = 1;
    if(K == "0")
    {
        return b;
    }
    BigInt A = base;
    if(K[0] == '1')
    {
        b = base;
    }
    for(int i = 1; i < K.length(); i++)
    {
        A = pow(A,2);
        A = A%modulus;
        if(K[i] == '1')
        {
            b = (A * b)%modulus;
        }
    }
    return b;
}
BigInt modExpRSA (BigInt base, BigInt exp, BigInt modulus)
{
    string K = decToBin2(exp);
    BigInt b = 1;
    if(K == "0")
    {
        return b;
    }
    BigInt A = base;
    if(K[0] == '1')
    {
        b = base;
    }
    for(int i = 1; i < K.length(); i++)
    {
        A = pow(A,2);
        A = A%modulus;
        if(K[i] == '1')
        {
            b = (A * b)%modulus;
        }
    }
    return b;
}
//decimal to binary conversion-
string decToBin (BigInt &r)
{
    string res = "";
    while(r != 0)
    {
        if(r%2 == 0)
        {
            res = res + "0";
        }
        else
        {
            res = res +"1";
        }
        r = r/2;
    }
    return res;
}
string decToBinR2 (BigInt &r2)
{
    string res = "";
    while(r2 != 0)
    {
        if(r2%2 == 0)
        {
            res = res + "0";
        }
        else
        {
            res = res +"1";
        }
        r2 = r2/2;
    }
    return res;
}
//decimal to binary conversion-
string decToBin2 (BigInt Ksym)
{
    string res = "";
    while(Ksym != 0)
    {
        if(Ksym%2 == 0)
        {
            res = res + "0";
        }
        else
        {
            res = res +"1";
        }
        Ksym = Ksym/2;
    }
    return res;
}
string decToBinfree (BigInt Ksym)
{
    string res = "";
    while(Ksym != 0)
    {
        if(Ksym%2 == 0)
        {
            res = res + "0";
        }
        else
        {
            res = res +"1";
        }
        Ksym = Ksym/2;
    }
    return res;
}

void keySchedule(string masterKey)
{
    int pc1[56] =
    {
        57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29, 21,13,5,28,20,12,4
    };
    int pc2[48] =
    {
        14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
    };
    string inPerm ="";
    string left="";
    string right="";
    //turn into 56 bits
    for(int i = 0; i < 56; i++)
    {
        inPerm = inPerm + masterKey[pc1[i]-1];
    }
    //left 28 bits, right 28 bits
    left= inPerm.substr(0, 28);
    right= inPerm.substr(28, 28);
    //16 subkeys
    for(int i=0; i<16; i++)
    {
        string tempKey = "";
        string leftPlusRight ="";

        if(i == 0 || i == 1 || i==8 || i==15 ) //circular left shift by 1
        {
            left=circle1(left);
            right=circle1(right);
        }
        else //circular left shift by 2
        {
            left = circle2(left);
            right = circle2(right);
        }
        leftPlusRight = left + right;
        for(int i = 0; i < 48; i++)
        {
            tempKey = tempKey + leftPlusRight[pc2[i]-1];
        }
        //add to array
        keys[i] = tempKey;
        //cout<<"Key "<<i+1<<": "<<round_keys[i]<<endl;
    }
}
void reverseKeySchedule(string masterKey)
{
    int pc1[56] =
    {
        57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29, 21,13,5,28,20,12,4
    };
    int pc2[48] =
    {
        14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
    };
    string inPerm ="";
    string left="";
    string right="";
    //turn into 56 bits
    for(int i = 0; i < 56; i++)
    {
        inPerm = inPerm + masterKey[pc1[i]-1];
    }
    //left 28 bits, right 28 bits
    left= inPerm.substr(0, 28);
    right= inPerm.substr(28, 28);
    for(int i=0; i<16; i++)
    {
        string tempKey = "";
        string leftPlusRight ="";

        if(i == 0 || i == 1 || i==8 || i==15 ) //circular RIGHT shift by 1
        {
            rotate(left.begin(),left.begin()+left.size()-1,left.end());
            rotate(right.begin(),right.begin()+right.size()-1,right.end());
        }
        else //circular RIGHT shift by 2
        {
            rotate(left.begin(),left.begin()+left.size()-2,left.end());
            rotate(right.begin(),right.begin()+right.size()-2,right.end());
        }
        leftPlusRight = left + right;
        for(int i = 0; i < 48; i++)
        {
            tempKey = tempKey + leftPlusRight[pc2[i]-1];
        }
        //add to array
        reversekeys[i] = tempKey;
        //cout<<"Key "<<i+1<<": "<<round_keys[i]<<endl;
    }
    
}
string circle1 (string s)
{
    rotate(s.begin(),s.begin()+1,s.end());
    return s;
}
string circle2 (string s)
{
    rotate(s.begin(),s.begin()+2,s.end());
    return s;
}
string des(string message)
{
    int initialPerm[64] =
    {
        58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
    };
    int expansion[48] =
    {
        32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
    };
    int sbox[8][4][16]=
    {{
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }};
    int permutation[32] =
    {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
    };
    int inversePerm[64]=
    {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
    };
    string intPerm = "";
    string leftPlusRight="";
    string ct="";
    string left ="";
    string right ="";
    for(int i = 0; i < 64; i++)
    {
        intPerm += message[initialPerm[i]-1];
    }
    left = intPerm.substr(0, 32);
    right = intPerm.substr(32, 32);
    for(int i=0; i<16; i++)
    {
        string right_expanded = "";
        string XORed="";
        string sboxString = "";
        string secondPerm ="";
        for(int i = 0; i < 48; i++)
        {
              right_expanded += right[expansion[i]-1];
        }
        XORed = XOR(keys[i], right_expanded);
        //divide this result into 8 sections (6-bit each)
        for(int i=0;i<8; i++)
        {
            string rowbin ="";
            string colbin ="";
            int row = 0;
            int column = 0;
            rowbin= XORed.substr(i*6,1) + XORed.substr(i*6 + 5,1);
            row = desBinToDec(rowbin);
            colbin = XORed.substr(i*6 + 1,1) + XORed.substr(i*6 + 2,1) + XORed.substr(i*6 + 3,1) + XORed.substr(i*6 + 4,1);
            column = desBinToDec(colbin);
            //get the corresponding decimal number from the current sbox using rowdec and coldec, which are also current
            int decimalNum = sbox[i][row][column];
            //turn this decimal back into a binary put it in ciphertext, now as a string of size 4, 4 x 8 = 32
            sboxString += desDecToBin(decimalNum);
        }
        for(int i = 0; i < 32; i++)
        {
            secondPerm += sboxString[permutation[i]-1];
        }
        //XOR the rightside with the leftside to get the new leftside
        XORed = XOR(secondPerm, left);
        left = XORed;
        if(i < 15)
        {
            //left and right switch
            string temp = right;
            right = XORed;
            left = temp;
        }
    }
    //concatination of left and right
    leftPlusRight = left + right;
    // The inverse of the initial permuttaion is applied
    for(int i = 0; i < 64; i++)
    {
        ct+= leftPlusRight[inversePerm[i]-1];
    }
    return ct;
}
string desReceiver(string message)
{
    int initialPerm[64] =
    {
        58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
    };
    int expansion[48] =
    {
        32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
    };
    int sbox[8][4][16]=
    {{
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }};
    int permutation[32] =
    {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
    };
    int inversePerm[64]=
    {
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
    };
    string intPerm = "";
    string leftPlusRight="";
    string ct="";
    string left ="";
    string right ="";
    for(int i = 0; i < 64; i++)
    {
        intPerm += message[initialPerm[i]-1];
    }
    left = intPerm.substr(0, 32);
    right = intPerm.substr(32, 32);
    for(int i=0; i<16; i++)
    {
        string right_expanded = "";
        string XORed="";
        string sboxString = "";
        string secondPerm ="";
        for(int i = 0; i < 48; i++)
        {
              right_expanded += right[expansion[i]-1];
        }
        XORed = XOR(reversekeys[i], right_expanded);
        //divide this result into 8 sections (6-bit each)
        for(int i=0;i<8; i++)
        {
            string rowbin ="";
            string colbin ="";
            int row = 0;
            int column = 0;
            rowbin= XORed.substr(i*6,1) + XORed.substr(i*6 + 5,1);
            row = desBinToDec(rowbin);
            colbin = XORed.substr(i*6 + 1,1) + XORed.substr(i*6 + 2,1) + XORed.substr(i*6 + 3,1) + XORed.substr(i*6 + 4,1);
            column = desBinToDec(colbin);
            //get the corresponding decimal number from the current sbox using rowdec and coldec, which are also current
            int decimalNum = sbox[i][row][column];
            //turn this decimal back into a binary put it in ciphertext, now as a string of size 4, 4 x 8 = 32
            sboxString += desDecToBin(decimalNum);
        }
        for(int i = 0; i < 32; i++)
        {
            secondPerm += sboxString[permutation[i]-1];
        }
        //XOR the rightside with the leftside to get the new leftside
        XORed = XOR(secondPerm, left);
        left = XORed;
        if(i < 15)
        {
            //left and right switch
            string temp = right;
            right = XORed;
            left = temp;
        }
    }
    //concatination of left and right
    leftPlusRight = left + right;
    // The inverse of the initial permuttaion is applied
    for(int i = 0; i < 64; i++)
    {
        ct+= leftPlusRight[inversePerm[i]-1];
    }
    return ct;
}
string desDecToBin(int dec)
{
    string binary = bitset<4>(dec).to_string();
    return binary;
}
int desBinToDec(string bin)
{
    int res = 0;
    int exp = 0;
    for(int i = int(bin.length())-1; i >= 0; i--)
    {
        if(bin[i] == '1')
        {
            res += pow(2, exp);
        }
        exp++;
    }
    return res;
}
string XOR(string x, string y)
{
    string res = "";
    for(int i = 0; i < int(y.length()); i++)
    {
        if(x[i] == y[i])
        {
            res += "0";
        }
        else
        {
            res += "1";
        }
    }
    return res;
}
