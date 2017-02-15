#include "corsaro.h"

#include "ksort.h" 

#define simple_compare2(a,b) ((a) < (b))
KSORT_INIT(seen_dest2, uint32_t, simple_compare2);

float p_from_birthday_spacing (uint32_t * array, int size)
{
  int m=1024;
  int s=50;
  int i,j;
  int r;
  uint32_t sample [m];
  bool selected [size];
  int duplicated = 0;
  uint32_t duplicated_spacings [11];

  if (size < m*s)
    return -1;

  for(j=0; j < size; j++)
    {
      selected[j]=0;
    }

  for(j=0; j < 11; j++)
    {
      duplicated_spacings[j]=0;
    }

  for (i=0; i < s ; i++)
    {
      j=0;
      while (j < m)
	{
	  r=rand()%size;
	  if (!selected[r])
	    {
	      sample[j]=array[r];
	      j+=1;
	    }
	}
      ks_combsort(seen_dest2, m, sample);
      duplicated=0;
      for (j=1; j<m ; j++)
	{
	  if (sample[j] == sample[j-1])
	    {
	      duplicated+=1;
	    }
	}
      if (duplicated >=10){
	duplicated_spacings[10]+=1;
      } else {
	duplicated_spacings[duplicated]+=1;
      }
    }
  fprintf(stderr, "%d %d %d %d %d %d %d %d %d %d %d\n", duplicated_spacings[0], duplicated_spacings[1], duplicated_spacings[2], duplicated_spacings[3], duplicated_spacings[4], duplicated_spacings[5], duplicated_spacings[6], duplicated_spacings[7], duplicated_spacings[8], duplicated_spacings[9], duplicated_spacings[10]);
  return 0;
}


