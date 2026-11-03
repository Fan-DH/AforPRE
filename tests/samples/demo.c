#include <stdio.h>

/* 第一版 demo 样本：flag 以静态字符串常量形式存放在 .rodata 中。 */
static const char g_flag[] = "flag{demo_static_string_2026}";

static void reveal_flag(void) {
    puts(g_flag);
}

int main(void) {
    reveal_flag();
    return 0;
}