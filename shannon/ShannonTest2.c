#include "Shannon.h"
#include "stdio.h"
#include "string.h"
#include "ShannonFast.c" // Gives us shn_diffuse

void dump_ctx(const char *msg, shn_ctx *ctx)
{
  const unsigned char *ptr = (unsigned char *)ctx;
  printf("%s ctx=", msg);
  for (int i = 0; i < sizeof(shn_ctx); i++)
  {
    printf("%02x", ptr[i]);
  }
  printf("\n");
  fflush(stdout);
}

void dump_hex(const char *msg, uint8_t *ptr, int size)
{
  printf("%s ", msg);
  for (int i = 0; i < size; i++)
  {
    printf("%02x", ptr[i]);
  }
  printf("\n");
}

int main(int argc, char *argv[])
{
  shn_ctx ctx;
  memset(&ctx, 0x0, sizeof(ctx));
  const uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
  const uint8_t nonce[] = {0x00, 0x00, 0x00, 0x00};
  shn_key(&ctx, key, sizeof(key));
  uint8_t buff[] = {0x01, 0x02, 0x03, 0x04};

  dump_hex("buffer", buff, sizeof(buff));
  dump_ctx("before encrypt", &ctx);
  printf("shn_encrypt\n");
  shn_encrypt(&ctx, buff, sizeof(buff));
  dump_hex("buffer", buff, sizeof(buff));
  dump_ctx("after encrypt", &ctx);

  dump_hex("buffer", buff, sizeof(buff));
  dump_ctx("before decrypt", &ctx);
  printf("shn_decrypt\n");
  shn_decrypt(&ctx, buff, sizeof(buff));
  dump_hex("buffer", buff, sizeof(buff));
  dump_ctx("after decrypt", &ctx);

  printf("shn_diffuse=%p\n", &shn_diffuse);
  shn_diffuse(&ctx);
}
