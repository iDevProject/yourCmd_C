#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
inline int endian_flip(unsigned int x)
{
return (x>>24) | ((x<<8) & 0x00FF0000) | ((x>>8) & 0x0000FF00) | (x<<24);
}
char* findptr(void* ptr, const char* cmd, int size){
char* step=0;
while(size--){
if(memcmp(ptr, cmd, strlen(cmd))==0){
return step;
}
step++;
ptr++;
}
return 0;
}
void ycmd(const char* path, int handlee){
if(access(path, R_OK)!=0){
printf("[-] Could not access %s\n", path);
exit(1);
}
FILE* fp=fopen(path, "r");
fseek(fp, 0L, SEEK_END);
int sz = ftell(fp);
fseek(fp, 0L, SEEK_SET);
fp=fopen(path, "r");
char* ibss=malloc(sz+1);
if(fread(ibss, sz, 1, fp)==-1){
free(ibss);
printf("[-] Error reading %s\n", path);
perror("read");
exit(3);
}
unsigned char* patched=malloc(sz);
memcpy(patched, ibss, sz);
unsigned int* irq=(unsigned int*)(((char*)ibss)+0x38);
unsigned char* hax=(unsigned char*)irq;
printf("IRQ Handler: 0x%X\n", (unsigned int)*irq);
*hax++=0;
*hax++=0;
*hax++=0;
printf("Base: 0x%X\n", *irq);
const char* ptr=findptr(ibss, "reset", sz);
if(ptr==0){
puts("[-] Could not find a pointer to a cmd");
exit(5);
}
printf("Pointer to cmd: 0x%X\n", (unsigned int)ptr);
int ptrtomem=(int)(*irq+ptr);
printf("Pointer to memorymapped cmd: 0x%X\n", ptrtomem);
int ptr_cr=memmem(ibss, sz, &ptrtomem, sizeof(int));
int ptr_c=ptr_cr-(int)ibss;
printf("Pointer to cmdstruct (relative to file): %x\n\n", ptr_c);
printf("Patching..\n");
unsigned char* cmd_s=ptr_c+patched;
unsigned int* handler=(int*)(cmd_s+4);
*handler=handlee;
unsigned char* cmname=((int)ptr)+patched;
printf("PtrInMem: [ptr:%X] [base:%X]\n", (unsigned int)cmname, (unsigned int)patched);
strcpy(cmname, "load");
printf("Done! Writing to file.. \n\n");
char* pathz=malloc(strlen(path)+15);
strcpy(pathz, path);
strcat(pathz, ".loader.dec");
FILE* patch=fopen(pathz, "w");
fwrite(patched, 1, sz, patch);
printf("[+] Done."); 
free(ibss);
free(pathz);
free(patched);
fclose(patch);
fclose(fp);
}
int main (int argc, char** argv, char** envp){
puts("yourCmd - iBSS Loader Patch Generator\n\n");
if(!argv[1]){
printf("[-] Usage: %s <path_to_ibss_decrypted> [handler]\nhandler defaults to 0x41000000 (loadaddr for A4 devices)\n", argv[0]);
exit(-1);
}
unsigned int handler=0x41000000;
if(argv[2]){
handler=strtol(argv[2], NULL, 16);
}
ycmd(argv[1], handler);
}
