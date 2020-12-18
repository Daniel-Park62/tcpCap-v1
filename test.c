#include <stdlib.h>
#include <stdio.h>

int main() {
  char temp[20] = "0123456789";

  printf("siz=(%d)(%5s)(%5.6s)(%.5s)\n", sizeof(temp),temp,temp+2,temp);

}
