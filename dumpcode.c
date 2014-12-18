#include <linux/kernel.h>

int isprintable(unsigned char c)
{
  if(0x20 <= c && 0x7E >=c)
    return 1;
  return 0;
}

void printchar(unsigned char c)
{
  
		if(isprintable(c))
		printk("%c",c);
		
		else
			printk(".");
 
}

void dumpcode(unsigned char *buff, int len)
{
	int i;
		printk("----------BEGIN DUMP----------\n");
   
		for(i=0;i<len;i++)
		{
		if(i%16==0)
			printk("0x%08x  ",(int)&buff[i]);
            printk("%02x ",buff[i]);
		if(i%16-15==0)
		{
			int j;
			printk("  ");
			for(j=i-15;j<=i;j++)
			printchar(buff[j]);
			printk("\n");
		}
}
			if(i%16!=0)
			{
			int j;
			int spaces=(len-i+16-i%16)*3+2;
			for(j=0;j<spaces;j++)
			printk(" ");
			for(j=i-i%16;j<len;j++)
			printchar(buff[j]);
			}
			printk("\n");
		printk("---------END DUMP----------\n");
 } 
