#include <stdio.h>

void askInput(FILE * temp);


int main(){

      FILE *myfile = (FILE *) fopen("results.csv", "w");

      fputs("name,age\n", myfile);

      for (int i = 0; i < 3; i++){
      askInput(myfile);
      }  

      fclose(myfile);
}

void askInput(FILE * temp){

      char name[99];
      int age;

      printf("Please provide name: ");
      scanf("%s", name);

      printf("Enter age: ");
      scanf("%d", &age);

      fprintf(temp, "%s,%d\n", name, age);


      

}