inline unsigned long long int rdtsc_32bits()
{
        unsigned long long int x;
        asm   volatile ("rdtsc" : "=A" (x));
        return x;
}

inline unsigned long long int rdtsc()
{
   unsigned long long int x;
   unsigned a, d;

   __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

