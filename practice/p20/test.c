struct ch8_struct
{				   // Size Minimum offset Default offset
	int field1;	   // 4 0 0
	short field2;  // 2 4 4
	char field3;   // 1 6 6
	int field4;	   // 4 7 8
	double field5; // 8 11 16
};				   // Minimum total size: 19 Default size: 24

void print(struct ch8_struct* ch8) {

}

int main()
{
	struct ch8_struct ch8_struct;
	ch8_struct.field1 = 10;
	ch8_struct.field2 = 20;
	ch8_struct.field3 = 30;
	ch8_struct.field4 = 40;
	ch8_struct.field5 = 50.0;

	print(&ch8_struct);

	return 0;
}

// gcc test.c -o test.o