#include <stdio.h>
#include <unistd.h>

int main()
{
	pid_t pid;
	int data;
	printf("index1\n");
	pid=fork();
	printf("index2\n");
	data=1;
	if(pid == -1){
		printf("failed to fork, error\n");
		return -1;
	}
	if(pid == 0){
		data = 2;
	}else{
		data = 3;
	}
	printf("data=%d\n",data);
	return 0;
}
