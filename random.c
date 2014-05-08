#include<stdio.h>
#include<stdlib.h>
#include<time.h>

void add(int num);

int main ()
{
    int i, input;
    
    srand ( time(NULL) );
    /* initialize random seed: */
    for(i=0;i<10;i++){

    /* Generate a random number: */
    int number = rand() % 255 ;
    printf("\n %d \n", number);
    }

    return 0;
}
