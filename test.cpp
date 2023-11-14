#include <stdio.h>
#include <stdlib.h>

#define test(d) test##d

void test1() {
	printf("11\n");
}
void test2() {
	printf("22\n");
}

int main2() {
	char d[10] = { 0 };
	printf(" ‰»Î1/2: ");
	scanf_s("%[^\n]%*c", d, 10);
	int a = atoi(d);

	// test(a)();
	while (1) {
		test(2)();
#pragma warning(disable: 4996)
		_sleep(3000);
	}
	return 0;
}