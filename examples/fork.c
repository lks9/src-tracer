#include <stdio.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(){
    int id ;
    id = fork();
    printf("id value : %d\n",id);

    if ( id == 0 )
    {
        sleep(8);
        printf ( "Child : Hello I am the child process\n");
        printf ( "Child : Child’s PID: %d\n", getpid());
        printf ( "Child : Parent’s PID: %d\n", getppid());
    }
    else
    {
        //sleep(8);
        printf ( "Parent : Hello I am the parent process\n" ) ;
        printf ( "Parent : Parent’s PID: %d\n", getpid());
        printf ( "Parent : Child’s PID: %d\n", id);
    } 

}
