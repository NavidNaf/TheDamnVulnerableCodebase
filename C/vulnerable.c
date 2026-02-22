// I will be using the following Blog: https://www.code-intelligence.com/blog/most-dangerous-vulnerabilities-cwes-in-c-2025
// This C Program demonstrates different Vulnerabilities in C. The vulnerabilities that I am covering in this program are:
// 1. Out-of-Bounds Write (CWE-787)
// 2. Out-of-Bounds Read (CWE-125)
// 3. Use After Free (CWE-416)
// 4. Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119)
// 5. NULL Pointer Dereference (CWE-476)
// 6. Integer Overflow or Wraparound (CWE-190)


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Out-of-Bounds Write (CWE-787)
void outOfBoundsWrite() {
    char buffer[10];
    for (int i = 0; i <= 10; i++) { // This loop writes beyond the buffer size
        buffer[i] = 'A'; // Buffer overflow vulnerability
    }
    printf("Buffer after out-of-bounds write: %s\n", buffer);
}

// 2. Out-of-Bounds Read (CWE-125)
void outOfBoundsRead() {
    char buffer[10] = "Hello";
    for (int i = 0; i <= 10; i++) { // This loop reads beyond the buffer size
        printf("%c ", buffer[i]); // Buffer overflow vulnerability
    }
    printf("\n");
}

// 3. Use After Free (CWE-416)
void useAfterFree() {
    char *ptr = (char *)malloc(10 * sizeof(char));
    strcpy(ptr, "Hello");
    free(ptr); // Memory is freed
    printf("Use after free: %s\n", ptr); // Accessing freed memory
}

// 4. Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-119)
void improperRestriction() {
    char buffer[10];
    int index = 15; // Index is out of bounds
    buffer[index] = 'A'; // Buffer overflow vulnerability
    printf("Buffer after improper restriction: %s\n", buffer);
}

// 5. NULL Pointer Dereference (CWE-476)
void nullPointerDereference() {
    char *ptr = NULL;
    printf("Dereferencing NULL pointer: %s\n", ptr); // NULL pointer dereference
}   

// 6. Integer Overflow or Wraparound (CWE-190)
void integerOverflow() {
    int a = 2147483647; // Maximum value for a 32-bit signed integer
    int b = 1;
    int result = a + b; // Integer overflow vulnerability
    printf("Integer overflow result: %d\n", result);
}  

int main() {
    // It will not work directly.
    // Comment out the function calls one by one to see the output of each vulnerability demonstration.

    printf("Demonstrating Out-of-Bounds Write:\n");
    outOfBoundsWrite();
    
    printf("\nDemonstrating Out-of-Bounds Read:\n");
    outOfBoundsRead();
    
    printf("\nDemonstrating Use After Free:\n");
    useAfterFree();
    
    printf("\nDemonstrating Improper Restriction of Operations within the Bounds of a Memory Buffer:\n");
    improperRestriction();
    
    printf("\nDemonstrating NULL Pointer Dereference:\n");
    nullPointerDereference();
    
    printf("\nDemonstrating Integer Overflow or Wraparound:\n");
    integerOverflow();
    
    return 0;
}
