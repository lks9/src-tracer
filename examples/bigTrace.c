const int maxCall = 340000 * 1024;

int numGb = 10;

void foo () {
    
}

int main () {
    for (int i = 0; i < 1;i++){
        for (int j = 0; j < maxCall;j++){
            foo();
        }
    }
}
