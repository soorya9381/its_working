// sha1.c

#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>


#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

#define SHA1HashSize 20

unsigned char Digest[SHA1HashSize];
unsigned char Device_Key[SHA1HashSize+1];
unsigned char Challenge_Token[SHA1HashSize+1];
unsigned char Response_Token[SHA1HashSize+1];
unsigned char Device_Id[9];
unsigned char Buffer[SHA1HashSize+2];
//int Random[20];

struct node
{
    unsigned char ID[9];
    unsigned char DeviceKey[SHA1HashSize+1];
    struct node *next;
}*Current, *Head, *Move;

typedef struct node item;




typedef struct SHA1Context
{
    unsigned int Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */

    unsigned int Length_Low;            /* Message length in bits      */
    unsigned int Length_High;           /* Message length in bits      */

    /* Index into message block array   */
    short Message_Block_Index;
    unsigned char Message_Block[64];          /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;



void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);
int SHA1Reset(SHA1Context *);
int SHA1Result(SHA1Context *, unsigned char[] );
int SHA1Input(SHA1Context *,const unsigned char *,unsigned int length);
void Random_generator( int, SHA1Context *);
void Registration_Challenge(int );
void Add_Device_Details();
void Update_Buffer();
void Response_Generation();



enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};


/*
 * Random Generator
 * 
 *  Description:
 *      This function is used to generate a required length
 *      of pseudo random numbers.
 *
 *  Parameters:
 *      Size :
 The required number of pseudo random numbers.
 *
 *  Returns:
 *      Nothing
 *      
 */

void Random_Generator(int length, SHA1Context * Con)
{
    int i;
    srand (time(NULL)); // Initialize Random Seed
    for(i=0;i<length;i++)
    {
        Con->Message_Block[i]= rand() % 255;

    }


}

void Update_Buffer()
{
    int i;
    srand(time(NULL));
    strcpy(Buffer,Device_Id);
    for(i=8;i<SHA1HashSize;i++)
    {
        Buffer[i]=rand();
    }


}

/*
 * Registration
 * 
 *  Description:
 *      This function is used to generate a 160 bit key for the 
 *      device as part of the initial registrtion phase.
 *      The Device Id and a time based random string is used for
 *      this purpose.
 *
 *  Parameters:
 *      None:550

 *
 *  Returns:
 *      Nothing
 *      
 */ 

void Registration_Challenge(module_id) 
{
    int i;

    SHA1Context con;
    Random_Generator(20, &con);
    Update_Buffer();
    if (SHA1Reset(&con)!=0)
    {
        printf ("\n Error..");
        return;
    }
    if (SHA1Input (&con,Buffer, 22) !=0)
    {
        printf ("\n Error...");
        return;
    }
    switch(module_id)
   {
        case 1:
            if (SHA1Result (&con,Device_Key)!=0)
            {
               printf("\n Error..");
               return;
            }

             printf("\n Device Key : \n");
             for(i=0;i<20;i++)
             printf (" %x", Device_Key[i]);
             printf ("\n");
        break;
   
        case 2:
             if (SHA1Result(&con,Challenge_Token)!=0)
             {
                printf("\n Error..");
                return;
             }
             printf("\n Challenge Token : \n");
             for(i=0;i<20;i++)
                 printf("%x", Challenge_Token[i]);
             printf("\n");
        break;

        default:
              printf("\n Invalid Argument to the Function");
        
    
    }

}

void Response_Generation()
{

    int i;

    SHA1Context con;

    if (SHA1Reset(&con)!=0)
    {
        printf ("\n Error..");
        return;
    }
    strcpy(Buffer,Challenge_Token);
    if (SHA1Input (&con,Buffer, 22) !=0)
    {
        printf ("\n Error...");
        return;
    }


    if (SHA1Result (&con,Response_Token)!=0)
    {
        printf("\n Error..");
        return;
    }

    printf("\n Response Token : \n");
    for(i=0;i<20;i++)
        printf ("%x", Response_Token[i]);
    printf ("\n");
    return;
}




/*
 * Add_Device_Details
 * 
 *  Description:
 *      This function adds the Device Id and the corresponding generated
 *      key in a linked list data structure.
 *      
 *
 *  Parameters:
 *      None
 *
 *  Returns:
 *      Nothing
 *      
 */

void Add_Device_Details()
{

    Current=(item *) malloc(sizeof(item));
    strcpy(Current->ID, Device_Id);
    strcpy(Current->DeviceKey, Device_Key);
    Current->next=Head;
    Head=Current;


}



/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Reset(SHA1Context *context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;

    return shaSuccess;
}


/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Input(    SHA1Context    *context,
        const unsigned char  *message_array,
        unsigned   int    length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;

        return shaStateError;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
            (*message_array & 0xFF);

        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Result( SHA1Context *context,
        unsigned char Message_Digest[SHA1HashSize])
{
    int i;


    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;

    }

    for(i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
            >> 8 * ( 3 - ( i & 0x03 ) );
    }

    return shaSuccess;
}


/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *

 *
 *
 */
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned int K[] =    {       /* Constants defined in SHA-1   */
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int           t;                 /* Loop counter                */
    unsigned int      temp;              /* Temporary word value        */
    unsigned int  W[80];             /* Word sequence               */
    unsigned int      A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
            ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}


/*
 *  SHA1PadMessage
 *
 4,0x5F,0x08,0xC8,0x89,0xB9,0x7F,0x59,0x80,0x03,0x8B,00
 x83,0x59};

 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 *
 */

void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {

            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}


int main() {
    int i, choice, ch,flag;
    Head =  NULL;
    SHA1Context con;
    // printf("\n Required Module ");
    // printf("\n Registration/Key generation : 1 \t Challenge Response : 2");
    // printf("\n Enter the Module ID :");
    // scanf("%d",&choice);

    // switch (choice){
    //   case 1:

    printf ("Registration phase");
    do{
        printf ("\n Enter Device ID (<=8 alphanumeric characters  ) :");
        scanf ("%s",Device_Id);
        Registration_Challenge(1);
        Add_Device_Details();
        printf("\n More device (y=1/n=0) : ");
        scanf("%d",&ch);


    } while (ch!=0);
    Current=Head;
    while(Current)
    {
        printf ("\n Device ID :  %s ", Current->ID);
        printf("\t\t Device Key : ");
        for(i=0; i<20;i++)
        {
            printf("%x", Current->DeviceKey[i]);
        }
        printf("\n");

        Current=Current->next;
    }
    

  printf ("\n\n\n Challenge and Response Generation");
    printf("\n Enter Device ID :");
    scanf("%s",  Device_Id) ;
    Current=Head;
    flag=0;
   while(Current)
    {
        if(!(strcmp(Current->ID, Device_Id)))
        {
            flag=1;
            strcpy(con.Message_Block,Current->DeviceKey);

        }
        if(flag==1) break;
        Current=Current->next;
    }
    if(flag==0)
        printf("\n Device ID not found");
    else 
    {

        Registration_Challenge(2);
        Response_Generation();
    }

    printf("\n");
}


