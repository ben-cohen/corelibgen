/****************************************************************
 * frametest: example program
 *
 * Compile using:
 *     gcc -ggdb -o frametest frametest.c library.so
 */
void library_function(int x, char y);

int f2(int x, char y)
{
   library_function(x + 1, y + 1);
}

int f1(int x, char y)
{
   f2(x + 1, y + 1);
}

int main()
{
   f1(1, 'a');
}

