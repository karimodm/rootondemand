int main() {
__asm__(
        "movl $1,%eax\n"
        "movl $-1,%ebx\n"
        "int $0x80"
);
}
