#include <stdio.h>
#include <string.h>

int main(int ac, char **argc)
{
    char *user_input;

    printf("Please enter key:\n");
    scanf("%s", user_input);
    if (strcmp(user_input, "__stack_check") == 0)
        printf("Good Job.\n");
    else
        printf("Nope.\n");
    return 0;
}