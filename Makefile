KERNELSRC=/usr/src/linux 
obj-m=rootondemand.o

rootondemand.o:rootondemand.c
	make -C ${KERNELSRC} M=${shell pwd} modules
clean:
	rm -rf *.o .*.o.d *.ko .*.cmd *.mod.c .tmp_versions Modules.symvers
	